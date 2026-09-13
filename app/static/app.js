/*
  Apex Terminal — panes, splits, broadcast.

  Three ideas hold this together.

  A pane is a *view* of a session, not the session itself. The session lives in
  the backend and survives this page: close the tab, lose wifi, suspend the
  laptop, and the command keeps running. Reattaching replays the scrollback and
  carries on. That is the property people actually want from tmux, and it is
  why panes are cheap and sessions are not.

  The layout is a binary tree, the way tmux's is. A split replaces a leaf with
  a node holding two leaves, so "split the pane I am in" is a local edit and
  closing a pane collapses its parent back into its sibling. Rendering walks
  the tree into nested flexboxes; there is no grid to keep in step.

  Broadcast is one flag read at the keystroke. Every pane's xterm hands its
  input to one function, and that function decides whether it goes to one
  session or all of them. Nothing else in the file knows about the mode.
*/

"use strict";

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k === "style" && typeof v === "object") Object.assign(node.style, v);
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, v);
  }
  append(node, ...children);
  return node;
}

/* Node.append() stringifies null into the literal text "null". */
function append(parent, ...children) {
  for (const child of children.flat(4)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

/* ------------------------------------------------------------------ toasts */

const TOAST_LIFE = { info: 4000, ok: 3200, warning: 8000, error: 12000 };

function toast(title, { body = "", severity = "info" } = {}) {
  const stack = $("#toastStack");
  while (stack.children.length >= 4) stack.firstElementChild.remove();
  const node = el("div", { class: `toast sev-${severity}` },
    el("span", { class: "toast-sev", text: severity }),
    el("h4", { text: title }),
    body ? el("p", { text: body }) : null);
  stack.append(node);
  setTimeout(() => {
    node.classList.add("out");
    node.addEventListener("animationend", () => node.remove(), { once: true });
    setTimeout(() => node.remove(), 400);
  }, TOAST_LIFE[severity] ?? 4000);
}

/* ---------------------------------------------------------------- the model */

const state = {
  tree: null,              // {type:'leaf', pane} | {type:'split', dir, a, b, ratio}
  panes: new Map(),        // paneId -> Pane
  focus: null,             // paneId
  sync: false,             // broadcast typing
  antiidle: 0,
  nextId: 1,
  drawerTab: "saved",
};

const XTERM_THEME = {
  background: "#05070e", foreground: "#d8e3f5", cursor: "#00f0ff",
  cursorAccent: "#05070e", selectionBackground: "rgba(0,240,255,.28)",
  black: "#0a0e1b", red: "#ff3860", green: "#39ff88", yellow: "#ffb020",
  blue: "#3b82f6", magenta: "#ff2ed1", cyan: "#00f0ff", white: "#d8e3f5",
  brightBlack: "#5a6785", brightRed: "#ff6d88", brightGreen: "#7dffb4",
  brightYellow: "#ffc95c", brightBlue: "#7aa9ff", brightMagenta: "#ff77e0",
  brightCyan: "#7df6ff", brightWhite: "#ffffff",
};

async function api(path, options = {}) {
  const res = await fetch(path, Object.assign({
    headers: options.body ? { "Content-Type": "application/json" } : {},
  }, options));
  const data = await res.json().catch(() => ({}));
  if (!res.ok && !data.error) throw new Error("HTTP " + res.status);
  if (data.ok === false) throw new Error(data.error || "request failed");
  return data;
}

const post = (path, body) =>
  api(path, { method: "POST", body: JSON.stringify(body || {}) });

/* -------------------------------------------------------------------- Pane */

class Pane {
  constructor(session) {
    this.id = "p" + state.nextId++;
    this.session = session;
    this.ws = null;
    this.dead = false;
    this.retry = 0;
    this.retryTimer = null;

    this.term = new Terminal({
      theme: XTERM_THEME,
      fontFamily: getComputedStyle(document.body).getPropertyValue("--mono").trim(),
      fontSize: 12.5,
      lineHeight: 1.15,
      cursorBlink: true,
      scrollback: 8000,
      allowProposedApi: true,
      // The backend is the source of truth for what was typed; letting xterm
      // echo as well would double every character on a line-buffered shell.
      convertEol: false,
    });
    this.fit = new FitAddon.FitAddon();
    this.term.loadAddon(this.fit);

    this.el = this.build();
    this.term.onData((data) => sendInput(this, data));
    this.term.onResize(({ cols, rows }) => this.send({ t: "resize", cols, rows }));
    this.connect();
  }

  build() {
    this.titleEl = el("span", { class: "pane-title", text: this.session.label });
    this.tagEl = el("span", { class: "pane-tag idle", hidden: true, text: "anti-idle" });
    this.dotEl = el("span", { class: "pane-dot" });
    this.bodyEl = el("div", { class: "pane-body" });

    const node = el("div", {
      class: "pane",
      dataset: { pane: this.id },
      onMousedown: () => focusPane(this.id),
    },
      el("div", { class: "pane-head" },
        this.dotEl,
        this.titleEl,
        this.tagEl,
        el("button", { class: "icon-btn", title: "Split vertical",
                       onClick: (e) => { e.stopPropagation(); splitPane(this.id, "v"); } }, "⬒"),
        el("button", { class: "icon-btn", title: "Close pane",
                       onClick: (e) => { e.stopPropagation(); closePane(this.id); } }, "×")),
      this.bodyEl);
    return node;
  }

  mounted() {
    if (this.term.element) { this.refit(); return; }
    this.term.open(this.bodyEl);
    this.refit();
  }

  refit() {
    // fit() throws if the element is not laid out yet (zero height during a
    // re-render); a pane that cannot be measured simply keeps its old size.
    try { this.fit.fit(); } catch (_) { /* not visible yet */ }
  }

  connect() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/ws?session=${encodeURIComponent(this.session.id)}`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      this.onGone("cannot open a socket: " + e.message);
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.retry = 0;
      setConn(true);
      this.send({ t: "resize", cols: this.term.cols, rows: this.term.rows });
      if (state.antiidle) this.send({ t: "antiidle", interval: state.antiidle });
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (_) { this.term.write(ev.data); return; }
      if (msg.t === "out") this.term.write(msg.d);
      else if (msg.t === "info") this.applyInfo(msg.session);
      else if (msg.t === "exit") this.onExit(msg.code);
    };
    ws.onerror = () => setConn(false);
    ws.onclose = () => {
      this.ws = null;
      if (this.dead || this.closing) return;
      // The session is still alive on the backend; this socket is not. Getting
      // back to it is the whole reason sessions outlive sockets, so retry --
      // backing off, because a server that is down stays down for a while.
      setConn(false);
      this.retry = Math.min(this.retry + 1, 6);
      const wait = Math.min(500 * 2 ** (this.retry - 1), 15000);
      this.retryTimer = setTimeout(() => this.connect(), wait);
      this.term.write(`\r\n\x1b[2m— link lost; reattaching in ${Math.round(wait / 1000)}s —\x1b[0m\r\n`);
    };
  }

  applyInfo(info) {
    if (!info) return;
    this.session = Object.assign({}, this.session, info);
    this.tagEl.hidden = !info.antiidle;
    this.titleEl.textContent = info.label || info.command;
  }

  onExit(code) {
    this.dead = true;
    this.el.classList.add("dead");
    this.tagEl.hidden = false;
    this.tagEl.className = "pane-tag exit";
    this.tagEl.textContent = code === 0 || code === null ? "exited" : `exit ${code}`;
    this.term.write(`\r\n\x1b[2m— session ended${code !== null ? " (" + code + ")" : ""} —\x1b[0m\r\n`);
    refreshDrawer();
  }

  onGone(reason) {
    this.dead = true;
    this.el.classList.add("dead");
    this.term.write(`\r\n\x1b[31m${reason}\x1b[0m\r\n`);
  }

  send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }

  dispose() {
    this.closing = true;
    clearTimeout(this.retryTimer);
    if (this.ws) { try { this.ws.close(); } catch (_) { /* already gone */ } }
    try { this.term.dispose(); } catch (_) { /* already disposed */ }
  }
}

/* ------------------------------------------------------------------- input */

function sendInput(pane, data) {
  // The one place broadcast exists. Every pane's keystrokes arrive here and
  // this decides how many sessions hear them.
  if (!state.sync) { pane.send({ t: "in", d: data }); return; }
  for (const p of state.panes.values()) {
    if (!p.dead) p.send({ t: "in", d: data });
  }
}

function sendToAll(line) {
  const text = line.endsWith("\n") ? line : line + "\r";
  let n = 0;
  for (const p of state.panes.values()) {
    if (!p.dead && p.send({ t: "in", d: text })) n++;
  }
  return n;
}

/* -------------------------------------------------------------- layout tree */

const leaf = (paneId) => ({ type: "leaf", pane: paneId });

function findParent(node, paneId, parent = null) {
  if (!node) return null;
  if (node.type === "leaf") return node.pane === paneId ? parent : null;
  return findParent(node.a, paneId, node) || findParent(node.b, paneId, node);
}

function findLeaf(node, paneId) {
  if (!node) return null;
  if (node.type === "leaf") return node.pane === paneId ? node : null;
  return findLeaf(node.a, paneId) || findLeaf(node.b, paneId);
}

function firstLeaf(node) {
  if (!node) return null;
  return node.type === "leaf" ? node : (firstLeaf(node.a) || firstLeaf(node.b));
}

function replaceLeaf(node, paneId, replacement) {
  if (!node) return node;
  if (node.type === "leaf") return node.pane === paneId ? replacement : node;
  node.a = replaceLeaf(node.a, paneId, replacement);
  node.b = replaceLeaf(node.b, paneId, replacement);
  return node;
}

function removeLeaf(node, paneId) {
  // Returns the tree with that leaf gone; a split with one child left collapses
  // into that child, which is what makes closing panes feel like tmux.
  if (!node) return null;
  if (node.type === "leaf") return node.pane === paneId ? null : node;
  const a = removeLeaf(node.a, paneId);
  const b = removeLeaf(node.b, paneId);
  if (!a) return b;
  if (!b) return a;
  node.a = a; node.b = b;
  return node;
}

/* ------------------------------------------------------------------ render */

function render() {
  const host = $("#layout");
  // Detach every pane element before rebuilding so the xterm instances -- and
  // their scrollback -- survive the re-layout. Re-creating them would clear
  // every terminal on every split.
  for (const pane of state.panes.values()) {
    if (pane.el.parentNode) pane.el.parentNode.removeChild(pane.el);
  }
  clear(host);

  if (state.tree) host.append(build(state.tree));
  $("#emptyState").hidden = !!state.tree;

  for (const pane of state.panes.values()) {
    pane.el.classList.toggle("focus", pane.id === state.focus);
    if (pane.el.isConnected) pane.mounted();
  }
  document.body.classList.toggle("syncing", state.sync);

  const live = [...state.panes.values()].filter((p) => !p.dead).length;
  $("#paneCount").textContent = state.panes.size
    ? `${state.panes.size} pane${state.panes.size === 1 ? "" : "s"} · ${live} live`
    : "no panes";
  requestAnimationFrame(() => {
    for (const pane of state.panes.values()) pane.refit();
  });
}

function build(node) {
  if (node.type === "leaf") {
    const pane = state.panes.get(node.pane);
    return pane ? pane.el : el("div", { class: "pane" });
  }
  const wrap = el("div", { class: `split ${node.dir}` });
  const a = build(node.a);
  const b = build(node.b);
  const ratio = node.ratio ?? 0.5;
  a.style.flex = `${ratio} 1 0`;
  b.style.flex = `${1 - ratio} 1 0`;
  const divider = el("div", { class: "divider" });
  wireDivider(divider, wrap, node, a, b);
  append(wrap, a, divider, b);
  return wrap;
}

function wireDivider(divider, wrap, node, a, b) {
  divider.addEventListener("mousedown", (down) => {
    down.preventDefault();
    divider.classList.add("dragging");
    const horizontal = node.dir === "v";   // 'v' splits lay panes left/right
    const rect = wrap.getBoundingClientRect();
    const total = horizontal ? rect.width : rect.height;

    const move = (e) => {
      const offset = horizontal ? e.clientX - rect.left : e.clientY - rect.top;
      // Clamp so a pane can never be dragged to nothing and become unreachable.
      const ratio = Math.min(0.88, Math.max(0.12, offset / total));
      node.ratio = ratio;
      a.style.flex = `${ratio} 1 0`;
      b.style.flex = `${1 - ratio} 1 0`;
    };
    const up = () => {
      divider.classList.remove("dragging");
      removeEventListener("mousemove", move);
      removeEventListener("mouseup", up);
      for (const pane of state.panes.values()) pane.refit();
    };
    addEventListener("mousemove", move);
    addEventListener("mouseup", up);
  });
}

/* ----------------------------------------------------------------- actions */

async function openPane({ command = "", cwd = "", label = "", split = null } = {}) {
  const cols = 80, rows = 24;
  let data;
  try {
    data = await post("/api/sessions", { command, cwd, label, cols, rows });
  } catch (e) {
    toast("Could not open a terminal", { body: e.message, severity: "error" });
    return null;
  }
  const pane = new Pane(data.session);
  state.panes.set(pane.id, pane);

  if (!state.tree) {
    state.tree = leaf(pane.id);
  } else if (split && state.focus && findLeaf(state.tree, state.focus)) {
    state.tree = replaceLeaf(state.tree, state.focus, {
      type: "split", dir: split, ratio: 0.5,
      a: leaf(state.focus), b: leaf(pane.id),
    });
  } else {
    // No split asked for: sit beside the current layout rather than replacing
    // it, so "+ Pane" never loses a terminal.
    state.tree = { type: "split", dir: "v", ratio: 0.5, a: state.tree, b: leaf(pane.id) };
  }
  state.focus = pane.id;
  render();
  pane.term.focus();
  refreshDrawer();
  return pane;
}

function splitPane(paneId, dir) {
  if (!state.panes.size) return openPane({ split: dir });
  state.focus = paneId || state.focus;
  return openPane({ split: dir });
}

function closePane(paneId) {
  const pane = state.panes.get(paneId);
  if (!pane) return;
  // The pane goes; the session only goes if it is still running, because a
  // finished one is exactly what somebody comes back to read.
  if (!pane.dead) post(`/api/sessions/${encodeURIComponent(pane.session.id)}/kill`).catch(() => {});
  pane.dispose();
  state.panes.delete(paneId);
  state.tree = removeLeaf(state.tree, paneId);
  if (state.focus === paneId) {
    const next = firstLeaf(state.tree);
    state.focus = next ? next.pane : null;
  }
  render();
  if (state.focus) state.panes.get(state.focus)?.term.focus();
  refreshDrawer();
}

function focusPane(paneId) {
  if (state.focus === paneId) return;
  state.focus = paneId;
  for (const pane of state.panes.values()) {
    pane.el.classList.toggle("focus", pane.id === paneId);
  }
}

function setSync(on) {
  state.sync = !!on;
  $("#btnSync").setAttribute("aria-pressed", String(state.sync));
  $("#sendBar").hidden = !state.sync;
  document.body.classList.toggle("syncing", state.sync);
  if (state.sync) {
    toast("Broadcast on", {
      body: `Every keystroke now goes to all ${state.panes.size} pane(s).`,
      severity: "warning",
    });
    $("#sendAll").focus();
  }
  for (const pane of state.panes.values()) pane.refit();
}

function setAntiIdle(seconds) {
  state.antiidle = Number(seconds) || 0;
  for (const pane of state.panes.values()) {
    pane.send({ t: "antiidle", interval: state.antiidle });
  }
  toast(state.antiidle ? `Anti-idle every ${state.antiidle}s` : "Anti-idle off", {
    body: state.antiidle
      ? "A NUL byte goes to any session that has been quiet that long. Shells discard it; the far end sees traffic."
      : "",
    severity: state.antiidle ? "info" : "ok",
  });
}

function setConn(up) {
  const dot = $("#connDot");
  dot.classList.toggle("on", up);
  dot.classList.toggle("off", !up);
  $("#connText").textContent = up ? "live" : "reattaching";
}

/* ------------------------------------------------------ the colour legend */

/* The 16 ANSI slots, from the same theme the terminals are built with, so a
   swatch here is the colour a pane actually paints. */
const ANSI = [
  XTERM_THEME.black, XTERM_THEME.red, XTERM_THEME.green, XTERM_THEME.yellow,
  XTERM_THEME.blue, XTERM_THEME.magenta, XTERM_THEME.cyan, XTERM_THEME.white,
  XTERM_THEME.brightBlack, XTERM_THEME.brightRed, XTERM_THEME.brightGreen,
  XTERM_THEME.brightYellow, XTERM_THEME.brightBlue, XTERM_THEME.brightMagenta,
  XTERM_THEME.brightCyan, XTERM_THEME.brightWhite,
];

/* Turn an SGR sequence such as "01;34;46" into inline style. Only the subset a
   file-colour scheme uses: bold, underline, the 8 foreground and 8 background
   colours, and their bright forms. Anything else is ignored rather than
   guessed at. */
function sgrToStyle(sgr) {
  const style = {};
  let bold = false;
  for (const part of String(sgr).split(";")) {
    const n = parseInt(part, 10);
    if (Number.isNaN(n)) continue;
    if (n === 0) { style.color = XTERM_THEME.foreground; }
    else if (n === 1) { bold = true; style.fontWeight = "700"; }
    else if (n === 4) style.textDecoration = "underline";
    else if (n >= 30 && n <= 37) style.color = ANSI[n - 30];
    else if (n >= 90 && n <= 97) style.color = ANSI[n - 90 + 8];
    else if (n >= 40 && n <= 47) style.background = ANSI[n - 40];
    else if (n >= 100 && n <= 107) style.background = ANSI[n - 100 + 8];
  }
  // Bold picks the bright variant, which is what a terminal does and what
  // makes "01;36" read as the cyan a directory is actually drawn in.
  if (bold && style.color) {
    const i = ANSI.indexOf(style.color);
    if (i >= 0 && i < 8) style.color = ANSI[i + 8];
  }
  return style;
}

const SAMPLE = {
  "Directory": "src/", "Symlink": "current -> v2", "Broken symlink": "gone -> ?",
  "Executable": "deploy.sh", "Regular file": "notes", "Hidden (ll / la)": ".bashrc",
  "Archive": "backup.tar.gz", "Image": "diagram.png", "Audio / video": "clip.mp4",
  "Document": "README.md", "Source code": "server.py", "Config / data": "config.yaml",
  "Logs, backups, swap": "debug.log", "Device / socket / fifo": "docker.sock",
  "setuid / setgid": "passwd", "World-writable dir": "tmp/",
};

async function renderColors(host) {
  let data;
  try {
    data = await api("/api/colors");
  } catch (e) {
    host.append(el("p", { class: "hint", text: "Could not load: " + e.message }));
    return;
  }
  const grid = el("div", { class: "legend" });
  for (const { label, sgr } of data.legend || []) {
    grid.append(el("div", { class: "legend-row" },
      el("span", { class: "legend-sample", style: sgrToStyle(sgr),
                   text: SAMPLE[label] || label }),
      el("span", { class: "legend-sgr", text: label })));
  }
  host.append(grid);

  const shims = Object.entries(data.shims || {});
  host.append(el("p", { class: "hint" },
    "Colour needs two things, and a plain shell has neither: a scheme in ",
    el("kbd", {}, "LS_COLORS"), ", and an ", el("kbd", {}, "ls"),
    " that has been asked to use it. Both are set up for every pane — no alias, ",
    "no change to your shell config. Your own alias still wins."));
  if (shims.length) {
    host.append(el("p", { class: "hint" },
      "Wrappers on PATH in this pane:",
      el("br"),
      ...shims.map(([name, what]) => el("span", {},
        el("kbd", {}, name), " → " + what, el("br")))));
  }
  host.append(el("p", { class: "hint" },
    el("b", {}, "About hidden files: "),
    "GNU ls cannot colour them. Its scheme takes two-letter type codes and ",
    el("kbd", {}, "*suffix"),
    " patterns only — a leading-dot glob is rejected outright. ",
    shims.some(([n]) => n === "la")
      ? "eza does accept one, so ll and la dim them; plain ls cannot."
      : "Install eza and ll/la will dim them; plain ls cannot."));
}

/* ------------------------------------------------------------------ drawer */

/* ------------------------------------------------------------- help & about */

async function openHelp() {
  $("#helpWrap").hidden = false;
  $("#btnHelpClose").focus();
  const box = $("#helpAbout");
  box.textContent = "Reading…";
  let health;
  try {
    health = await api("/api/health");
  } catch (err) {
    box.textContent = `Could not reach the backend — ${err.message}`;
    return;
  }
  const rows = [
    ["version", health.version || "—"],
    ["terminals", health.supported ? "supported on this machine"
                                   : (health.reason || "not available here")],
    ["live sessions", String(health.sessions ?? 0)],
    ["running", health.embedded ? "inside ApexBuild" : "on its own"],
    ["signed in as", health.user || "nobody — no ApexBuild sign-on"],
    ["author", "Alfredo Nacino"],
  ];
  box.textContent = "";
  for (const [key, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value;
    box.append(dt, dd);
  }
}

function closeHelp() {
  $("#helpWrap").hidden = true;
}

function openDrawer(tab) {
  if (tab) state.drawerTab = tab;
  $("#drawer").hidden = false;
  $("#drawerScrim").hidden = false;
  $(".launcher").hidden = state.drawerTab === "colors";
  for (const b of document.querySelectorAll(".drawer-tabs button")) {
    b.classList.toggle("on", b.dataset.tab === state.drawerTab);
  }
  refreshDrawer();
  if (state.drawerTab !== "colors") $("#newCommand").focus();
}

function closeDrawer() {
  $("#drawer").hidden = true;
  $("#drawerScrim").hidden = true;
}

const ago = (ts) => {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
};

async function refreshDrawer() {
  if ($("#drawer").hidden) return;
  // The legend never changes; redrawing it on the poll would fight the reader.
  if (state.drawerTab === "colors" && $("#drawerList").querySelector(".legend")) return;
  const host = clear($("#drawerList"));
  if (state.drawerTab === "colors") return renderColors(host);
  let data;
  try {
    data = state.drawerTab === "live"
      ? await api("/api/sessions")
      : await api("/api/history");
  } catch (e) {
    host.append(el("p", { class: "hint", text: "Could not load: " + e.message }));
    return;
  }

  if (state.drawerTab === "live") {
    const rows = data.sessions || [];
    if (!rows.length) host.append(el("p", { class: "hint", text: "Nothing running." }));
    for (const s of rows) host.append(liveRow(s));
    return;
  }

  const rows = state.drawerTab === "saved" ? (data.saved || []) : (data.history || []);
  if (!rows.length) {
    host.append(el("p", { class: "hint" },
      state.drawerTab === "saved"
        ? "Nothing saved yet. Type a command above and press Save to keep it here."
        : "No history yet."));
  }
  for (const row of rows) {
    host.append(state.drawerTab === "saved" ? savedRow(row) : historyRow(row));
  }
  host.append(el("p", { class: "hint" },
    "Passwords are blanked before anything is written to disk — ",
    el("kbd", {}, "--password"), ", ", el("kbd", {}, "sshpass -p"),
    " and credentials in URLs. Ports such as ", el("kbd", {}, "ssh -p 2222"),
    " are left alone."));
}

function savedRow(entry) {
  return el("div", { class: "row" },
    el("div", { class: "row-main" },
      el("div", { class: "row-cmd", text: entry.name }),
      el("div", { class: "row-meta", text: entry.command })),
    el("div", { class: "row-actions" },
      el("button", { class: "btn sm primary",
                     onClick: () => { openPane({ command: entry.command, cwd: entry.cwd, label: entry.name }); closeDrawer(); } },
        "Open"),
      el("button", { class: "btn sm danger", title: "Forget",
                     onClick: async () => { await post("/api/history/forget", { name: entry.name }); refreshDrawer(); } },
        "×")));
}

function historyRow(entry) {
  const status = entry.ended === null
    ? el("span", { class: "pill live", text: "running" })
    : el("span", { class: entry.exit_code ? "pill bad" : "pill ok",
                   text: entry.exit_code ? "exit " + entry.exit_code : "done" });
  return el("div", { class: "row" },
    el("div", { class: "row-main" },
      el("div", { class: "row-cmd", text: entry.command }),
      el("div", { class: "row-meta" }, ago(entry.started), " · ", entry.cwd || "~")),
    status,
    el("div", { class: "row-actions" },
      el("button", { class: "btn sm",
                     onClick: () => { openPane({ command: entry.command, cwd: entry.cwd }); closeDrawer(); } },
        "Again")));
}

function liveRow(s) {
  return el("div", { class: "row" },
    el("div", { class: "row-main" },
      el("div", { class: "row-cmd", text: s.label || s.command }),
      el("div", { class: "row-meta" },
        `pid ${s.pid} · ${s.cols}×${s.rows} · idle ${s.idle_for}s`,
        s.viewers ? ` · ${s.viewers} viewer(s)` : " · detached")),
    el("span", { class: s.alive ? "pill live" : "pill bad", text: s.alive ? "alive" : "ended" }),
    el("div", { class: "row-actions" },
      s.alive && ![...state.panes.values()].some((p) => p.session.id === s.id)
        ? el("button", {
            class: "btn sm primary", title: "Attach this session to a new pane",
            onClick: () => { attachExisting(s); closeDrawer(); },
          }, "Attach")
        : null,
      el("button", { class: "btn sm danger",
                     onClick: async () => { await post(`/api/sessions/${encodeURIComponent(s.id)}/kill`); refreshDrawer(); } },
        "Kill")));
}

function attachExisting(info) {
  // The session already exists; this only builds a view onto it. Everything it
  // printed while nobody was watching is replayed by the backend on attach.
  const pane = new Pane(info);
  state.panes.set(pane.id, pane);
  state.tree = state.tree
    ? { type: "split", dir: "v", ratio: 0.5, a: state.tree, b: leaf(pane.id) }
    : leaf(pane.id);
  state.focus = pane.id;
  render();
  pane.term.focus();
}

/* -------------------------------------------------------------------- wire */


/* ----------------------------------------------------------------- the ask bar

   A question box under the panes, backed by the Claude Agent SDK (app/agent.py).
   It answers with commands and never runs one: `insert` writes the text into
   the focused pane *without* a newline, so the operator reads it, edits it if
   they want to, and presses Enter themselves.

   Broadcast is deliberately bypassed on insert. Putting a command into every
   pane at once because a toggle happens to be on is not something anybody
   would mean by clicking one suggestion.
*/

const ask = { open: false, busy: false, ready: null };

function setAskOpen(open) {
  ask.open = open;
  $("#askBar").hidden = !open;
  $("#btnAskBar").setAttribute("aria-pressed", open ? "true" : "false");
  // The bar takes height from the stage, so every pane has to be told its new
  // size or xterm keeps drawing at the old one and the bottom rows are lost.
  for (const pane of state.panes.values()) pane.refit();
  if (open) $("#askInput").focus();
}

async function loadAskState() {
  try {
    ask.ready = await api("/api/agent/state");
  } catch (_) {
    ask.ready = { available: false, detail: "The backend did not answer." };
  }
  const bad = $("#askUnavailable");
  const usable = !!(ask.ready && ask.ready.available);
  bad.hidden = usable;
  bad.textContent = usable ? "" : (ask.ready.detail || "The assistant is unavailable.");
  $("#askInput").disabled = !usable;
  $("#btnAsk").disabled = !usable;
}

async function doAsk() {
  if (ask.busy) return;
  const question = $("#askInput").value.trim();
  if (!question) return;

  ask.busy = true;
  $("#btnAsk").disabled = true;
  $("#askInput").disabled = true;
  $("#askAnswer").hidden = false;
  $("#askText").textContent = "Thinking…";
  $("#askCmds").textContent = "";
  $("#askMeta").textContent = "";

  try {
    const pane = state.focus ? state.panes.get(state.focus) : null;
    const data = await post("/api/agent/ask", {
      prompt: question,
      // The focused pane's directory, so "what is in this folder" means the
      // folder the operator is actually looking at.
      cwd: (pane && pane.session && pane.session.cwd) || "",
    });
    renderAnswer(data);
  } catch (e) {
    $("#askText").textContent = e.message;
    $("#askCmds").textContent = "";
    $("#askMeta").textContent = "";
  } finally {
    ask.busy = false;
    $("#btnAsk").disabled = false;
    $("#askInput").disabled = false;
    $("#askInput").focus();
  }
}

function renderAnswer(data) {
  // The prose, with the fenced blocks stripped out: they are rendered below as
  // buttons, and leaving them in the text too would say everything twice.
  const prose = (data.text || "")
    .replace(/```(?:[\w.+-]*)\n[\s\S]*?```/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  $("#askText").textContent = prose || "(no explanation given)";

  const host = $("#askCmds");
  host.textContent = "";
  for (const command of data.commands || []) {
    const row = document.createElement("button");
    row.className = "ask-cmd";
    row.type = "button";
    row.title = "Put this in the focused pane (it is not run)";
    const code = document.createElement("code");
    code.textContent = command;
    const tag = document.createElement("span");
    tag.className = "insert";
    tag.textContent = "insert";
    row.append(code, tag);
    row.onclick = () => insertCommand(command);
    host.append(row);
  }

  const u = data.usage || {};
  const bits = [];
  if (u.cost != null) {
    bits.push(`<b>$${u.cost.toFixed(4)}</b>${u.estimated ? " (estimated)" : ""}`);
  }
  if (u.input != null) bits.push(`${u.input.toLocaleString()} in / ${(u.output || 0).toLocaleString()} out`);
  if (u.duration_ms != null) bits.push(`${(u.duration_ms / 1000).toFixed(1)}s`);
  const models = (u.models || []).map((m) => m.model).filter(Boolean);
  if (models.length) bits.push(models.join(", "));
  $("#askMeta").innerHTML = bits.join(" &nbsp;·&nbsp; ");
}

function insertCommand(command) {
  const pane = state.focus ? state.panes.get(state.focus) : null;
  if (!pane || pane.dead) {
    toast("No pane to insert into", { body: "Open a terminal first.",
                                      severity: "warning" });
    return;
  }
  // No trailing newline, and pane.send rather than sendInput: this puts the
  // command on the prompt for a human to run, in one pane, deliberately.
  pane.send({ t: "in", d: command });
  pane.term.focus();
  toast("Inserted", { body: "Press Enter to run it.", severity: "ok" });
}

/* ------------------------------------------------------------- cost analysis */

const money = (n) => "$" + (n || 0).toFixed(n && n < 0.01 ? 4 : 2);
const whenever = (t) => new Date(t * 1000).toLocaleString();

async function openCosts() {
  $("#costWrap").hidden = false;
  const body = $("#costBody");
  body.textContent = "Loading…";
  let d;
  try {
    d = await api("/api/agent/costs");
  } catch (e) {
    body.textContent = e.message;
    return;
  }

  const t = d.tokens || {};
  const peak = Math.max(...(d.by_day || []).map((x) => x.cost), 0);

  const tile = (k, v, cls) =>
    `<div class="cost-tile ${cls || ""}"><div class="k">${k}</div><div class="v">${v}</div></div>`;

  const rows = (d.recent || []).map((a) => `
    <tr>
      <td>${whenever(a.at)}</td>
      <td class="ask">${escapeHtml(a.prompt)}</td>
      <td class="num">${(a.input || 0).toLocaleString()}</td>
      <td class="num">${(a.output || 0).toLocaleString()}</td>
      <td class="num">${a.cost == null ? "—" : money(a.cost)}</td>
    </tr>`).join("");

  const bars = (d.by_day || []).map((x) => {
    const h = peak > 0 ? Math.max(2, Math.round((x.cost / peak) * 62)) : 2;
    return `<div class="cost-bar" style="height:${h}px"
                 title="${x.day}: ${money(x.cost)} over ${x.asks} ask(s)"></div>`;
  }).join("");

  const models = (d.by_model || []).map((m) => `
    <tr><td>${escapeHtml(m.model)}</td>
        <td class="num">${m.asks}</td>
        <td class="num">${money(m.cost)}</td></tr>`).join("");

  body.innerHTML = `
    <div class="cost-top">
      ${tile("Total spend", money(d.total), "spend")}
      ${tile("Asks", d.asks)}
      ${tile("Average ask", money(d.average))}
      ${tile("Tokens in", (t.input || 0).toLocaleString())}
      ${tile("Tokens out", (t.output || 0).toLocaleString())}
    </div>

    ${d.estimated ? `<p class="cost-note cost-est">Some rows have no cost from
      the SDK — a Claude subscription session bills nothing per request — so
      those are priced from the published rate card and marked estimated.</p>` : ""}

    <h3>Per day</h3>
    <div class="cost-bars">${bars || ""}</div>
    <p class="cost-note">${(d.by_day || []).length
        ? `Last ${(d.by_day || []).length} day(s) with activity. Tallest bar = ${money(peak)}.`
        : "Nothing asked yet."}</p>

    <h3>Per model</h3>
    <table class="cost-table">
      <tr><th>Model</th><th>Asks</th><th>Cost</th></tr>
      ${models || `<tr><td colspan="3">Nothing yet.</td></tr>`}
    </table>

    <h3>Recent asks</h3>
    <table class="cost-table">
      <tr><th>When</th><th>Question</th><th>In</th><th>Out</th><th>Cost</th></tr>
      ${rows || `<tr><td colspan="5">Nothing yet.</td></tr>`}
    </table>
    <p class="cost-note">Questions are kept so a cost can be attributed to one.
       Answers are not: this is a ledger, not a transcript.</p>
    <button class="btn sm" id="btnCostClear">Clear the ledger</button>
  `;

  $("#btnCostClear").onclick = async () => {
    await post("/api/agent/costs/clear").catch(() => {});
    openCosts();
  };
}

function closeCosts() { $("#costWrap").hidden = true; }

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text == null ? "" : String(text);
  return div.innerHTML;
}

function wire() {
  // F1 and Escape are handled here rather than in the pane's own key handler:
  // a terminal is entitled to every other key on the keyboard, and help that
  // could not be closed without the mouse would be a poor kind of help.
  addEventListener("keydown", (e) => {
    if (e.key === "F1") { e.preventDefault(); openHelp(); return; }
    if (e.key === "Escape" && !$("#costWrap").hidden) { e.preventDefault(); closeCosts(); return; }
    if (e.key === "Escape" && !$("#helpWrap").hidden) { e.preventDefault(); closeHelp(); return; }
    // Ctrl+Shift+A: the ask bar. Shift keeps it off Ctrl+A, which a shell uses
    // for start-of-line and a terminal has no business intercepting.
    if (e.ctrlKey && e.shiftKey && (e.key === "A" || e.key === "a")) {
      e.preventDefault(); setAskOpen(!ask.open);
    }
  }, true);

  $("#btnNew").onclick = () => openPane({});
  $("#btnFirst").onclick = () => openPane({});
  $("#btnSplitV").onclick = () => splitPane(state.focus, "v");
  $("#btnSplitH").onclick = () => splitPane(state.focus, "h");
  $("#btnSync").onclick = () => setSync(!state.sync);
  $("#selIdle").onchange = (e) => setAntiIdle(e.target.value);
  $("#btnHistory").onclick = () => ($("#drawer").hidden ? openDrawer() : closeDrawer());
  $("#btnHelp").onclick = () => ($("#helpWrap").hidden ? openHelp() : closeHelp());
  $("#btnHelpClose").onclick = closeHelp;
  $("#helpWrap").onclick = (e) => { if (e.target.id === "helpWrap") closeHelp(); };
  $("#btnDrawerClose").onclick = closeDrawer;
  $("#drawerScrim").onclick = closeDrawer;
  $("#btnCloseSend").onclick = () => setSync(false);

  $("#btnAskBar").onclick = () => setAskOpen(!ask.open);
  $("#btnAsk").onclick = doAsk;
  $("#askInput").onkeydown = (e) => { if (e.key === "Enter") doAsk(); };
  $("#btnAskClose").onclick = () => setAskOpen(false);
  $("#btnAskCost").onclick = openCosts;
  $("#btnCostClose").onclick = closeCosts;
  $("#costWrap").onclick = (e) => { if (e.target.id === "costWrap") closeCosts(); };

  for (const b of document.querySelectorAll(".drawer-tabs button")) {
    b.onclick = () => openDrawer(b.dataset.tab);
  }

  $("#btnLaunch").onclick = () => {
    const command = $("#newCommand").value.trim();
    openPane({ command });
    $("#newCommand").value = "";
    closeDrawer();
  };
  $("#newCommand").onkeydown = (e) => { if (e.key === "Enter") $("#btnLaunch").click(); };

  $("#btnSave").onclick = async () => {
    const command = $("#newCommand").value.trim();
    if (!command) { toast("Type a command first", { severity: "warning" }); return; }
    const name = prompt("Name this connection", command) || command;
    try {
      await post("/api/history/save", { name, command });
      toast("Saved", { body: name, severity: "ok" });
      openDrawer("saved");
    } catch (e) {
      toast("Could not save", { body: e.message, severity: "error" });
    }
  };

  const fire = () => {
    const line = $("#sendAll").value;
    if (!line.trim()) return;
    const n = sendToAll(line);
    $("#sendAll").value = "";
    toast(`Sent to ${n} pane(s)`, { body: line, severity: n ? "ok" : "warning" });
  };
  $("#btnSendAll").onclick = fire;
  $("#sendAll").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); fire(); } };

  addEventListener("resize", () => {
    for (const pane of state.panes.values()) pane.refit();
  });

  // Ctrl+Shift+… rather than a tmux prefix key: a prefix would have to be
  // intercepted before xterm sees it, and stealing a keystroke from a terminal
  // is how you break the one program the user needed it for.
  addEventListener("keydown", (e) => {
    if (!e.ctrlKey || !e.shiftKey || e.altKey) return;
    const key = e.key.toLowerCase();
    const map = {
      d: () => splitPane(state.focus, "v"),
      e: () => splitPane(state.focus, "h"),
      s: () => setSync(!state.sync),
      h: () => ($("#drawer").hidden ? openDrawer() : closeDrawer()),
      w: () => state.focus && closePane(state.focus),
      enter: () => openPane({}),
    };
    const fn = map[key === "enter" ? "enter" : key];
    if (fn) { e.preventDefault(); fn(); }
  });
}

async function boot() {
  wire();
  try {
    const health = await api("/api/health");
    if (!health.supported) {
      $("#unsupported").hidden = false;
      $("#emptyState").hidden = true;
      $("#unsupported").append(
        el("p", {}, el("b", {}, "Terminals are not available on this platform.")),
        el("p", { text: health.reason }));
      return;
    }
    setConn(true);
    // Not awaited: whether the assistant is installed has no bearing on
    // getting a pane open, and a slow answer here must not delay one.
    loadAskState();
  } catch (e) {
    setConn(false);
    toast("Backend unreachable", { body: e.message, severity: "error" });
    return;
  }
  // Reattach anything already running -- a reloaded page should come back to
  // its terminals, not to an empty screen.
  try {
    const { sessions } = await api("/api/sessions");
    const alive = (sessions || []).filter((s) => s.alive);
    if (alive.length) {
      for (const s of alive) attachExisting(s);
      toast(`Reattached ${alive.length} session(s)`, { severity: "ok" });
    } else {
      await openPane({});
    }
  } catch (_) {
    await openPane({});
  }
  setInterval(() => refreshDrawer(), 4000);
}

boot();
