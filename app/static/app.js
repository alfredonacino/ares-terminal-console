/*
  ARES Terminal Console — panes, splits, broadcast.

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
  panes: new Map(),        // paneId -> Pane, across every tab
  tabs: [],                // {id, name, custom, tree, focus}
  tab: null,               // the tab on screen
  sync: false,             // broadcast typing -- to the tab on screen
  antiidle: 0,
  nextId: 1,
  nextTab: 1,
  drawerTab: "saved",
  cmdFilter: { session: "", connection: "", label: "" },
};

/* Each tab has its own layout tree and focus. `state.tree` and `state.focus`
   are the tab on screen's, so everything that lays out panes works on one
   tab without knowing tabs exist. A tree is
   {type:'leaf', pane} | {type:'split', dir, a, b, ratio}. */
Object.defineProperties(state, {
  tree: {
    get() { return this.tab ? this.tab.tree : null; },
    set(v) { (this.tab || addTab()).tree = v; },
  },
  focus: {
    get() { return this.tab ? this.tab.focus : null; },
    set(v) { if (this.tab) this.tab.focus = v; },
  },
});

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

    this.tab = state.tab ? state.tab.id : null;
    this.lineStart = null;       // where the command being typed began
    this.where = {};             // host, ip, cwd -- see fetchWhere()
    this.whereAt = 0;
    this.outputAt = Date.now();
    this.el = this.build();
    // A shell that reports its directory (OSC 7, file://host/path) is
    // believed at once; the server-side lookup is the fallback.
    this.term.parser.registerOscHandler(7, (data) => {
      const m = /^file:\/\/([^/]*)(\/.*)$/.exec(data);
      if (m) {
        let cwd = m[2];
        try { cwd = decodeURIComponent(cwd); } catch (_) { /* keep it raw */ }
        this.osc7 = { host: m[1], cwd };
        this.showWhere();
      }
      return true;
    });
    this.term.onData((data) => sendInput(this, data));
    this.term.onResize(({ cols, rows }) => this.send({ t: "resize", cols, rows }));
    this.connect();
  }

  build() {
    this.titleEl = el("span", { class: "pane-title", text: this.session.label });
    this.hostEl = el("span", { class: "pw pw-host", hidden: true });
    this.ipEl = el("span", { class: "pw pw-ip", hidden: true });
    this.cwdText = el("bdi", {});
    this.cwdEl = el("span", { class: "pw pw-cwd", hidden: true,
                              title: "Current directory — click to copy",
                              onClick: (e) => { e.stopPropagation(); this.copyCwd(); } }, this.cwdText);
    this.whereEl = el("span", { class: "pane-where" }, this.hostEl, this.ipEl, this.cwdEl);
    this.showTools();
    queueMicrotask(() => this.showTitle());
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
        this.whereEl,
        this.tagEl,
        el("button", { class: "pane-cmds", title: "Commands sent to this pane",
                       onClick: (e) => { e.stopPropagation(); showCommandsFor(this); } }, "⌘"),
        this.toolsEl,
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
      this.scheduleWhere(1200);
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (_) { this.term.write(ev.data); return; }
      if (msg.t === "out") { this.term.write(msg.d); this.outputAt = Date.now(); }
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
    this.showTitle();
    renderTabs();
  }

  showTitle() {
    // An ssh pane is titled by where it goes, not by its options; the whole
    // command is in the tooltip.
    const s = this.session;
    const named = s.label && s.label !== s.command ? s.label : "";
    this.titleEl.textContent = named || (s.ssh ? "ssh " + s.ssh : s.command || s.label || "shell");
    this.titleEl.title = s.command || "";
  }

  /* ---- the commands sent to this pane

     Read back off the screen, not reassembled from keystrokes: what reaches
     the shell is what tab-completion, the arrow keys and Ctrl+R produced, and
     the screen is where that is written down. The line's start is marked at
     the first key after the prompt; on Enter, that line (and any wrapped
     continuation) is read a moment later, once its echo has arrived. A
     password prompt does not echo, so a password is never recorded. Inside a
     full-screen program (the alternate screen) nothing is recorded at all. */

  track(data) {
    const buf = this.term.buffer.active;
    if (buf.type === "alternate") { this.dropLine(); return; }
    if (data === "\x03") { this.dropLine(); return; }           // Ctrl+C
    if (data.length > 1 && /[\r\n]/.test(data.slice(0, -1))) {   // a multi-line paste
      for (const line of data.split(/\r\n|\r|\n/)) if (line.trim()) this.logCommand(line, "pasted");
      this.dropLine();
      return;
    }
    if (!this.lineStart) {
      const marker = this.term.registerMarker(0);
      if (marker) this.lineStart = { marker, x: buf.cursorX };
    }
    if (data.endsWith("\r") || data.endsWith("\n")) {
      const start = this.lineStart;
      this.lineStart = null;
      if (start) setTimeout(() => this.captureLine(start), 350);
    }
  }

  dropLine() {
    if (this.lineStart) { try { this.lineStart.marker.dispose(); } catch (_) { /* gone */ } }
    this.lineStart = null;
  }

  captureLine(start) {
    const b = this.term.buffer.normal;
    const { marker } = start;
    if (marker.isDisposed || marker.line < 0) return;
    let y = marker.line;
    let text = (b.getLine(y)?.translateToString(true) || "").slice(start.x);
    while (b.getLine(y + 1)?.isWrapped) { y++; text += b.getLine(y).translateToString(true); }
    marker.dispose();
    text = text.trim();
    if (text) this.logCommand(text, "typed");
  }

  logCommand(text, how) {
    post(`/api/sessions/${encodeURIComponent(this.session.id)}/command`, { command: text, how })
      .then(() => { if (!$("#drawer").hidden && state.drawerTab === "commands") refreshDrawer(); })
      .catch(() => {});
    this.scheduleWhere(900);
  }

  /* ---- where this pane is: host, address, directory */

  scheduleWhere(delay = 900) {
    clearTimeout(this.whereTimer);
    this.whereTimer = setTimeout(() => this.fetchWhere(), delay);
  }

  async fetchWhere() {
    if (this.dead || this.whereBusy) return;
    this.whereBusy = true;
    try {
      this.where = await api(`/api/sessions/${encodeURIComponent(this.session.id)}/where`);
    } catch (_) {
      /* the title bar keeps what it had */
    } finally {
      this.whereBusy = false;
      this.whereAt = Date.now();
    }
    this.showWhere();
  }

  /* ◈ server on an SSH pane, or on a local pane whose shell has run `ssh`
     (the tools follow it there); ◈ system on any other local pane. */
  showTools() {
    if (!this.toolsEl) {
      this.toolsEl = el("button", { class: "pane-tools",
        onClick: (e) => { e.stopPropagation(); openInsight(this); } });
    }
    const dest = this.session.ssh || (this.where && this.where.hop) || "";
    this.toolsEl.textContent = dest ? "◈ server" : "◈ system";
    this.toolsEl.title = (dest ? `Server tools for ${dest}` : "System tools for this computer") +
      " (Ctrl+Shift+X)";
  }

  showWhere() {
    this.showTools();
    const w = this.where || {};
    const ssh = this.session.ssh || "";
    let host = w.host || (this.osc7 && this.osc7.host) || (ssh ? ssh.replace(/^.*@/, "").replace(/:\d+$/, "") : "");
    const user = w.user || (ssh.includes("@") ? ssh.split("@")[0] : "");
    const cwd = (this.osc7 && this.osc7.cwd) || w.cwd || "";
    this.hostEl.hidden = !host;
    this.hostEl.textContent = (w.hop ? "→ " : "⌂ ") + host;
    this.hostEl.title = w.hop
      ? `This shell has connected on to ${w.hop}`
      : `${user ? user + "@" : ""}${host}${w.remote ? " (remote)" : " (this machine)"}`;
    this.ipEl.hidden = !w.ip;
    this.ipEl.textContent = w.ip || "";
    this.ipEl.title = "IP address";
    this.cwdEl.hidden = !cwd;
    this.cwdText.textContent = cwd;
    this.cwdEl.title = `${cwd}\nclick to copy`;
    this.el.dataset.host = host;
    renderTabs();
  }

  copyCwd() {
    const cwd = this.cwdText.textContent;
    if (!cwd) return;
    navigator.clipboard?.writeText(cwd).then(
      () => toast("Path copied", { body: cwd, severity: "ok" }),
      () => toast("Could not copy", { body: cwd, severity: "warning" }));
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
    clearTimeout(this.whereTimer);
    if (this.ws) { try { this.ws.close(); } catch (_) { /* already gone */ } }
    try { this.term.dispose(); } catch (_) { /* already disposed */ }
  }
}

/* ------------------------------------------------------------------- input */

function sendInput(pane, data) {
  // The one place broadcast exists. Every pane's keystrokes arrive here and
  // this decides how many sessions hear them: with broadcast on, every pane
  // in the tab on screen -- never a tab you cannot see.
  const targets = state.sync ? tabPanes(state.tab) : [pane];
  for (const p of targets) {
    if (!p.dead && p.send({ t: "in", d: data })) p.track(data);
  }
}

function sendToAll(line) {
  const text = line.endsWith("\n") ? line : line + "\r";
  let n = 0;
  for (const p of tabPanes(state.tab)) {
    if (!p.dead && p.send({ t: "in", d: text })) {
      n++;
      p.dropLine();
      p.logCommand(line.trim(), "broadcast");
    }
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
  renderTabs();

  for (const pane of state.panes.values()) {
    pane.el.classList.toggle("focus", pane.id === state.focus);
    if (pane.el.isConnected) pane.mounted();
  }
  document.body.classList.toggle("syncing", state.sync);

  const live = [...state.panes.values()].filter((p) => !p.dead).length;
  const tabs = state.tabs.length;
  $("#paneCount").textContent = state.panes.size
    ? `${state.panes.size} pane${state.panes.size === 1 ? "" : "s"} · ${live} live` +
      (tabs > 1 ? ` · ${tabs} tabs` : "")
    : "no panes";
  requestAnimationFrame(() => {
    for (const pane of tabPanes(state.tab)) { pane.refit(); if (!pane.whereAt) pane.scheduleWhere(300); }
  });
  saveLayout();
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

async function openPane({ command = "", cwd = "", label = "", split = null, newTab = false } = {}) {
  const cols = 80, rows = 24;
  let data;
  try {
    data = await post("/api/sessions", { command, cwd, label, cols, rows });
  } catch (e) {
    toast("Could not open a terminal", { body: e.message, severity: "error" });
    return null;
  }
  // A new connection gets a tab of its own -- unless the tab on screen is
  // empty, in which case it is that tab.
  if (!state.tab || (newTab && state.tree)) switchTab(addTab(), false);
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

function closePane(paneId, { quiet = false } = {}) {
  const pane = state.panes.get(paneId);
  if (!pane) return;
  // The pane goes; the session only goes if it is still running, because a
  // finished one is exactly what somebody comes back to read.
  if (!pane.dead) post(`/api/sessions/${encodeURIComponent(pane.session.id)}/kill`).catch(() => {});
  pane.dispose();
  state.panes.delete(paneId);
  const tab = state.tabs.find((t) => t.id === pane.tab) || state.tab;
  tab.tree = removeLeaf(tab.tree, paneId);
  if (tab.focus === paneId) {
    const next = firstLeaf(tab.tree);
    tab.focus = next ? next.pane : null;
  }
  // A tab whose last pane closed goes too, unless it is the only one.
  if (!tab.tree && state.tabs.length > 1) dropTab(tab);
  if (quiet) return;
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
  const pane = state.panes.get(paneId);
  if (pane && Date.now() - pane.whereAt > 10_000) pane.scheduleWhere(100);
  saveLayout();
}

/* -------------------------------------------------------------------- tabs

   A tab is a workspace: its own split layout, its own focus. New connections
   open in a new tab; + Pane and the splits work inside the tab on screen.
   Panes in other tabs keep running and keep their scrollback -- switching
   only changes which tree is drawn. */

function tabPanes(tab) {
  if (!tab) return [];
  return [...state.panes.values()].filter((p) => p.tab === tab.id);
}

function addTab(name = "") {
  const tab = { id: "t" + state.nextTab++, name, custom: !!name, tree: null, focus: null };
  state.tabs.push(tab);
  if (!state.tab) state.tab = tab;
  return tab;
}

function switchTab(tab, draw = true) {
  if (!tab) return;
  state.tab = tab;
  if (!draw) return;
  render();
  const pane = state.focus && state.panes.get(state.focus);
  if (pane) { pane.term.focus(); if (Date.now() - pane.whereAt > 10_000) pane.scheduleWhere(100); }
}

function dropTab(tab) {
  const i = state.tabs.indexOf(tab);
  if (i < 0) return;
  state.tabs.splice(i, 1);
  if (state.tab === tab) state.tab = state.tabs[Math.min(i, state.tabs.length - 1)] || null;
}

function closeTab(tab) {
  for (const p of tabPanes(tab)) closePane(p.id, { quiet: true });
  if (state.tabs.includes(tab)) {          // the only tab: keep it, empty
    tab.tree = null; tab.focus = null;
    if (tab.custom === false) tab.name = "";
  }
  render();
  const pane = state.focus && state.panes.get(state.focus);
  if (pane) pane.term.focus();
  refreshDrawer();
}

function tabName(tab) {
  if (tab.custom && tab.name) return tab.name;
  const panes = tabPanes(tab);
  const first = (tab.focus && state.panes.get(tab.focus)) || panes[0];
  if (!first) return "new tab";
  const s = first.session;
  return s.ssh || (s.label && s.label !== s.command ? s.label : "") ||
         (first.where && first.where.host ? first.where.host : "") || "local";
}

function renderTabs() {
  const bar = $("#tabList");
  if (!bar) return;
  const frag = document.createDocumentFragment();
  state.tabs.forEach((tab, i) => {
    const panes = tabPanes(tab);
    const live = panes.filter((p) => !p.dead).length;
    const ssh = panes.some((p) => p.session.ssh);
    const name = el("span", { class: "tab-name", text: tabName(tab) });
    const close = el("button", {
      class: "tab-x", title: live ? `Close this tab and its ${live} terminal(s)` : "Close this tab",
      onClick: (e) => {
        e.stopPropagation();
        // Closing a tab ends its terminals. One click arms it; the second
        // does it -- a tab can hold a session somebody cannot get back.
        if (live && !close.classList.contains("arm")) {
          close.classList.add("arm");
          close.textContent = `close ${live}?`;
          setTimeout(() => { close.classList.remove("arm"); close.textContent = "×"; }, 3000);
          return;
        }
        closeTab(tab);
      },
    }, "×");
    const node = el("div", {
      class: "tab" + (tab === state.tab ? " on" : "") + (ssh ? " ssh" : ""),
      role: "tab", title: `${tabName(tab)} — ${panes.length} pane(s), ${live} live` +
                          "\nDouble-click to rename · Ctrl+PageUp/PageDown to switch",
      onClick: () => { if (tab !== state.tab) switchTab(tab); },
      onDblclick: () => renameTab(tab, name),
    },
      el("span", { class: "tab-dot" + (live ? "" : " dead") }),
      el("span", { class: "tab-kind", text: ssh ? "⇄" : "▸" }),
      name,
      panes.length > 1 ? el("span", { class: "tab-count", text: String(panes.length) }) : null,
      close);
    frag.append(node);
  });
  bar.replaceChildren(frag);
  const on = bar.querySelector(".tab.on");
  if (on) on.scrollIntoView({ block: "nearest", inline: "nearest" });
}

function renameTab(tab, nameEl) {
  const input = el("input", { class: "tab-rename", value: tabName(tab), spellcheck: "false" });
  const done = (keep) => {
    if (keep) {
      const v = input.value.trim();
      tab.custom = !!v;
      tab.name = v;
    }
    renderTabs();
    saveLayout();
  };
  input.onkeydown = (e) => {
    e.stopPropagation();
    if (e.key === "Enter") done(true);
    if (e.key === "Escape") done(false);
  };
  input.onblur = () => done(true);
  nameEl.replaceWith(input);
  input.focus();
  input.select();
}

function cycleTab(step) {
  if (state.tabs.length < 2) return;
  const i = state.tabs.indexOf(state.tab);
  switchTab(state.tabs[(i + step + state.tabs.length) % state.tabs.length]);
}

/* The layout is remembered in this browser (by session id), so a reload
   comes back to the same tabs and splits rather than one long row. */
const LAYOUT_KEY = "ares-tc.layout";

function saveLayout() {
  const ser = (node) => {
    if (!node) return null;
    if (node.type === "leaf") {
      const p = state.panes.get(node.pane);
      return p ? { type: "leaf", session: p.session.id } : null;
    }
    return { type: "split", dir: node.dir, ratio: node.ratio, a: ser(node.a), b: ser(node.b) };
  };
  const data = {
    active: state.tabs.indexOf(state.tab),
    tabs: state.tabs.map((t) => ({
      name: t.custom ? t.name : "", tree: ser(t.tree),
      focus: t.focus && state.panes.get(t.focus) ? state.panes.get(t.focus).session.id : "",
    })),
  };
  try { localStorage.setItem(LAYOUT_KEY, JSON.stringify(data)); } catch (_) { /* private mode */ }
}

function restoreLayout(alive) {
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(LAYOUT_KEY) || "null"); } catch (_) { saved = null; }
  const bySid = new Map(alive.map((s) => [s.id, s]));
  const grow = (node, tab) => {
    if (!node) return null;
    if (node.type === "leaf") {
      const info = bySid.get(node.session);
      if (!info) return null;
      bySid.delete(node.session);
      const pane = new Pane(info);
      pane.tab = tab.id;
      state.panes.set(pane.id, pane);
      if (node.session === tab.wantFocus) tab.focus = pane.id;
      return leaf(pane.id);
    }
    const a = grow(node.a, tab), b = grow(node.b, tab);
    if (!a) return b;
    if (!b) return a;
    return { type: "split", dir: node.dir, ratio: node.ratio, a, b };
  };
  let active = null;
  if (saved && Array.isArray(saved.tabs)) {
    saved.tabs.forEach((st, i) => {
      const tab = addTab(st.name || "");
      tab.wantFocus = st.focus;
      tab.tree = grow(st.tree, tab);
      delete tab.wantFocus;
      if (!tab.tree) { dropTab(tab); return; }
      if (!tab.focus) tab.focus = firstLeaf(tab.tree).pane;
      if (i === saved.active) active = tab;
    });
  }
  // Anything running that the saved layout does not know: one tab each, so
  // a connection still gets a tab of its own.
  for (const info of bySid.values()) {
    const tab = addTab();
    const pane = new Pane(info);
    pane.tab = tab.id;
    state.panes.set(pane.id, pane);
    tab.tree = leaf(pane.id);
    tab.focus = pane.id;
  }
  state.tab = active || state.tabs[0] || null;
  render();
  const pane = state.focus && state.panes.get(state.focus);
  if (pane) pane.term.focus();
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
  $(".launcher").hidden = state.drawerTab === "colors" || state.drawerTab === "commands";
  $("#cmdFilterBar").hidden = state.drawerTab !== "commands";
  for (const b of document.querySelectorAll(".drawer-tabs button")) {
    b.classList.toggle("on", b.dataset.tab === state.drawerTab);
  }
  refreshDrawer();
  if (state.drawerTab === "commands") $("#cmdSearch").focus();
  else if (state.drawerTab !== "colors") $("#newCommand").focus();
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

async function refreshDrawer(poll = false) {
  if ($("#drawer").hidden) return;
  if (state.drawerTab === "commands") return renderCommands();
  if (state.drawerTab === "servers") return poll ? undefined : renderServers();
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
                     onClick: () => { openPane({ command: entry.command, cwd: entry.cwd, label: entry.name, newTab: true }); closeDrawer(); } },
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
                     onClick: () => { openPane({ command: entry.command, cwd: entry.cwd, newTab: true }); closeDrawer(); } },
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
  if (!state.tab) addTab();
  const pane = new Pane(info);
  state.panes.set(pane.id, pane);
  state.tree = state.tree
    ? { type: "split", dir: "v", ratio: 0.5, a: state.tree, b: leaf(pane.id) }
    : leaf(pane.id);
  state.focus = pane.id;
  render();
  pane.term.focus();
}

/* ------------------------------------------------- commands sent, servers */

function showCommandsFor(pane) {
  state.cmdFilter = { session: pane.session.id, connection: "",
                      label: pane.session.label || pane.session.command || "this pane" };
  openDrawer("commands");
}

function showCommandsOn(connection) {
  state.cmdFilter = { session: "", connection, label: connection };
  openDrawer("commands");
}

const clock = (t) => {
  const d = new Date(t * 1000);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString() : d.toLocaleString();
};

async function renderCommands() {
  const f = state.cmdFilter;
  const chip = $("#cmdScope");
  clear(chip);
  if (f.session || f.connection) {
    chip.append(el("span", { class: "pill live", text: (f.connection ? "server " : "pane ") + f.label }),
      el("button", { class: "btn sm", title: "Show every pane",
                     onClick: () => { state.cmdFilter = { session: "", connection: "", label: "" }; renderCommands(); } },
        "all panes"));
  } else {
    const pane = state.focus && state.panes.get(state.focus);
    chip.append(el("span", { class: "pill", text: "every pane" }),
      pane ? el("button", { class: "btn sm", onClick: () => showCommandsFor(pane) }, "this pane") : null);
  }
  const q = $("#cmdSearch").value.trim();
  const qs = new URLSearchParams({ limit: "400" });
  if (f.session) qs.set("session", f.session);
  if (f.connection) qs.set("connection", f.connection);
  if (q) qs.set("q", q);
  let rows;
  try {
    rows = (await api("/api/commands?" + qs)).commands || [];
  } catch (e) {
    $("#drawerList").replaceChildren(el("p", { class: "hint", text: "Could not load: " + e.message }));
    return;
  }
  if (state.drawerTab !== "commands" || $("#drawer").hidden) return;
  const frag = document.createDocumentFragment();
  if (!rows.length) {
    frag.append(el("p", { class: "hint" }, q ? "Nothing matches." :
      "No commands yet. Each line you run in a pane is listed here as it was sent."));
  }
  for (const c of rows) frag.append(commandRow(c));
  frag.append(el("p", { class: "hint" },
    "Read off the screen when Enter is pressed, so it is what the shell received after completion and history. " +
    "Lines nothing echoed — passwords — are never recorded, and ", el("kbd", {}, "--password"),
    "-style secrets are blanked before saving."));
  $("#drawerList").replaceChildren(frag);
}

function commandRow(c) {
  const where = c.connection || c.pane || "";
  return el("div", { class: "row cmd-row" },
    el("div", { class: "row-main" },
      el("div", { class: "row-cmd mono", title: c.command, text: c.command }),
      el("div", { class: "row-meta" },
        clock(c.t), where ? " · " : "", where,
        c.how && c.how !== "typed" ? el("span", { class: "pill cmd-how", text: c.how }) : null)),
    el("div", { class: "row-actions" },
      el("button", { class: "btn sm", title: "Put it on the focused pane's prompt, unsent",
                     onClick: () => { insertCommand(c.command); closeDrawer(); } }, "Insert"),
      el("button", { class: "btn sm", title: "Copy",
                     onClick: () => navigator.clipboard?.writeText(c.command).then(
                       () => toast("Copied", { body: c.command, severity: "ok" })) }, "Copy")));
}

async function renderServers() {
  let rows;
  try {
    rows = (await api("/api/connections")).connections || [];
  } catch (e) {
    $("#drawerList").replaceChildren(el("p", { class: "hint", text: "Could not load: " + e.message }));
    return;
  }
  if (state.drawerTab !== "servers" || $("#drawer").hidden) return;
  const frag = document.createDocumentFragment();
  if (!rows.length) {
    frag.append(el("p", { class: "hint" },
      "No servers yet. Every ", el("kbd", {}, "ssh"), " connection opened here is listed, with when and how often."));
  }
  for (const s of rows) frag.append(serverRow(s));
  $("#drawerList").replaceChildren(frag);
}

const span = (a, b) => {
  const s = Math.max(0, Math.round((b || Date.now() / 1000) - a));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.round(s / 60) + "m";
  return (s / 3600).toFixed(1) + "h";
};

function serverRow(s) {
  const forget = el("button", { class: "btn sm danger", title: "Forget this server's connection history",
    onClick: async (e) => {
      if (!forget.classList.contains("arm")) {
        forget.classList.add("arm"); forget.textContent = "forget?";
        setTimeout(() => { forget.classList.remove("arm"); forget.textContent = "×"; }, 3000);
        return;
      }
      e.stopPropagation();
      await post("/api/connections/forget", { connection: s.connection });
      renderServers();
    } }, "×");
  const facts = [s.hostname && s.hostname !== s.host ? s.hostname : "", s.os_name || "",
                 (s.addresses || []).slice(0, 2).join(", ")].filter(Boolean).join(" · ");
  const sessions = el("div", { class: "srv-sessions" },
    ...(s.sessions || []).map((x) => el("div", { class: "srv-session" },
      el("span", { text: clock(x.started) }),
      el("span", { class: "row-meta", text: x.ended ? `${span(x.started, x.ended)}${x.exit_code ? " · exit " + x.exit_code : ""}` : "running" }))));
  return el("details", { class: "row srv-row" },
    el("summary", {},
      el("div", { class: "row-main" },
        el("div", { class: "row-cmd" }, el("b", { text: s.connection })),
        el("div", { class: "row-meta" },
          facts ? facts + " · " : "",
          `${s.count} connection${s.count === 1 ? "" : "s"} · last ${ago(s.last)} · first ${new Date(s.first * 1000).toLocaleDateString()}`)),
      s.live ? el("span", { class: "pill live", text: `${s.live} open` }) : null,
      s.commands ? el("span", { class: "pill", text: `${s.commands} cmd` }) : null,
      el("div", { class: "row-actions" },
        el("button", { class: "btn sm primary", title: s.command,
                       onClick: (e) => { e.preventDefault(); openPane({ command: s.command, label: s.label || "", newTab: true }); closeDrawer(); } },
          "Connect"),
        el("button", { class: "btn sm", onClick: (e) => { e.preventDefault(); showCommandsOn(s.connection); } }, "Commands"),
        forget)),
    el("div", { class: "srv-body" },
      el("div", { class: "row-meta mono", text: s.command }),
      s.uid ? el("div", { class: "row-meta", text: `Known to the server tools as ${s.uid}${s.events ? ` · ${s.events} report(s) in its history` : ""}` }) : null,
      sessions));
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

async function loadAskState(refresh = false) {
  try {
    ask.ready = await api("/api/agent/state" + (refresh ? "?refresh=1" : ""));
  } catch (_) {
    ask.ready = { available: false, detail: "The backend did not answer." };
  }
  const r = ask.ready || {};
  const usable = !!r.available;
  $("#askUnavailable").hidden = usable;
  $("#askUnavailableText").textContent = usable ? "" : (r.detail || "The assistant is unavailable.");
  // Signing in is a terminal job: `claude auth login` opens the browser for
  // the Claude account and finishes in the pane, where the operator can see it.
  $("#btnAskLogin").hidden = !(r.reason === "login" && r.login_command);
  $("#askInput").disabled = !usable;
  $("#btnAsk").disabled = !usable;

  const who = $("#askAccount");
  const acct = r.account || null;
  if (usable && acct) {
    const sub = acct.subscription || "";
    who.textContent = sub ? `Claude ${sub[0].toUpperCase()}${sub.slice(1)}`
                          : (acct.method === "claude.ai" ? "Claude subscription" : (acct.method || "Claude"));
    who.title = `Signed in to Claude Code${acct.email ? " as " + acct.email : ""}`
      + (acct.org ? ` (${acct.org})` : "")
      + (r.masked_api_key ? ". ANTHROPIC_API_KEY is set but not used: asks go through the subscription." : "");
    who.hidden = false;
  } else if (usable && r.mode === "api-key") {
    who.textContent = "API key";
    who.title = "ARES_ASK_AUTH=api-key: asks are billed to the API key";
    who.hidden = false;
  } else {
    who.hidden = true;
  }
}

async function askLogin() {
  const r = ask.ready || {};
  if (!r.login_command) return;
  await openPane({ command: r.login_command, label: "Sign in to Claude" });
  toast("Signing in", { body: "Finish in the new pane, then press Check again.", severity: "info" });
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
    bits.push(u.subscription
      ? `<span title="What this would have cost at API rates. Asks through a subscription are not billed per token.">included in subscription (~$${u.cost.toFixed(4)} at API rates)</span>`
      : `<b>$${u.cost.toFixed(4)}</b>${u.estimated ? " (estimated)" : ""}`);
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
  if (pane.send({ t: "in", d: command })) pane.track(command);
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

    ${d.subscription ? `<p class="cost-note">Asks made through your Claude subscription
      are not billed per token; their amounts are what they would cost at API rates,
      shown so you can see the usage.</p>` : ""}
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
  $("#btnTabNew").onclick = () => openPane({ newTab: true });
  $("#btnTabConnect").onclick = () => openDrawer("servers");
  let searchTimer = null;
  $("#cmdSearch").oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(renderCommands, 200); };
  $("#btnCmdClear").onclick = async () => {
    const b = $("#btnCmdClear");
    if (!b.classList.contains("arm")) {
      b.classList.add("arm"); b.textContent = "clear all?";
      setTimeout(() => { b.classList.remove("arm"); b.textContent = "Clear"; }, 3000);
      return;
    }
    b.classList.remove("arm"); b.textContent = "Clear";
    await post("/api/commands/clear");
    renderCommands();
  };
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
  $("#btnAskLogin").onclick = () => askLogin();
  $("#btnAskRecheck").onclick = () => loadAskState(true);
  $("#btnAskClose").onclick = () => setAskOpen(false);
  $("#btnAskCost").onclick = openCosts;
  $("#btnCostClose").onclick = closeCosts;
  $("#costWrap").onclick = (e) => { if (e.target.id === "costWrap") closeCosts(); };

  for (const b of document.querySelectorAll(".drawer-tabs button")) {
    b.onclick = () => openDrawer(b.dataset.tab);
  }

  $("#btnLaunch").onclick = () => {
    const command = $("#newCommand").value.trim();
    openPane({ command, newTab: true });
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
      t: () => openPane({ newTab: true }),
      l: () => (state.focus && state.panes.get(state.focus) ? showCommandsFor(state.panes.get(state.focus)) : openDrawer("commands")),
      enter: () => openPane({}),
    };
    const fn = map[key === "enter" ? "enter" : key];
    if (fn) { e.preventDefault(); fn(); }
  });
  // Tabs: Ctrl+PageUp / PageDown, as in most terminals. Not Alt+digit:
  // full-screen programs (irssi, weechat, mc) use those.
  addEventListener("keydown", (e) => {
    if (e.ctrlKey && !e.altKey && !e.shiftKey && (e.key === "PageUp" || e.key === "PageDown")) {
      e.preventDefault(); cycleTab(e.key === "PageUp" ? -1 : 1);
    }
  }, true);
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
      restoreLayout(alive);
      toast(`Reattached ${alive.length} session(s)`, { severity: "ok" });
    } else {
      await openPane({});
    }
  } catch (_) {
    await openPane({});
  }
  setInterval(() => refreshDrawer(true), 4000);
  // Keep the title bars current: a pane that printed something since its
  // last look is looked at again. Only the tab on screen -- nobody is
  // reading the others.
  setInterval(() => {
    for (const p of tabPanes(state.tab)) {
      if (!p.dead && p.outputAt > p.whereAt && Date.now() - p.whereAt > 20_000) p.fetchWhere();
    }
  }, 5000);
}

boot();
