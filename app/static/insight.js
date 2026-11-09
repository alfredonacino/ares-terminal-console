/*
  Server tools — the seven analyses of ARES Ultimate Console and TractorBeam,
  for the server an SSH pane is connected to, or for this computer when the
  pane is local.

  Everything here is a view of app/insight/service.py: the browser draws what
  the server measured and never talks to the far side itself. The two AI
  analyses show exactly what would be sent and send only that, on a click.
*/
"use strict";

const TOOLS = [
  { key: "health", icon: "♥", label: "Health & processes" },
  { key: "perf",   icon: "⚡", label: "Performance analysis" },
  { key: "logs",   icon: "☰", label: "Log analysis" },
  { key: "ai",     icon: "✦", label: "AI log analysis" },
  { key: "pkgs",   icon: "▤", label: "Packages & technologies" },
  { key: "vulns",  icon: "⛨", label: "Vulnerability scan" },
  { key: "hist",   icon: "↺", label: "Server history" },
];

const ins = { pane: null, sid: "", tool: "health", timer: null, ident: null, cache: {} };

const SEV_CLASS = { ok: "ok", info: "info", warn: "warn", warning: "warn", crit: "crit",
                    critical: "crit", fail: "crit", high: "warn", medium: "info", low: "ok",
                    healthy: "ok", degraded: "warn", unhealthy: "crit" };
const sevClass = (s) => "sev-" + (SEV_CLASS[String(s || "").toLowerCase()] || "info");
const iapi = (tool, opts) => api(`/api/insight/${encodeURIComponent(ins.sid)}/${tool}`, opts);
const ipost = (tool, body) => post(`/api/insight/${encodeURIComponent(ins.sid)}/${tool}`, body);

function bytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
}
const pct = (v) => (v == null ? "—" : `${Number(v).toFixed(1)}%`);
const when = (t) => new Date(t * 1000).toLocaleString();

/* A small, safe markdown: the AI answers are headings, lists, bold and code. */
function md(text) {
  const esc = escapeHtml(text || "");
  const blocks = esc.split(/```[\w-]*\n?/);
  return blocks.map((b, i) => {
    if (i % 2) return `<pre class="ins-code">${b.replace(/\n$/, "")}</pre>`;
    return b.split(/\n{2,}/).map((para) => {
      const lines = para.split("\n");
      if (lines.every((l) => /^\s*([-*]|\d+\.)\s/.test(l) || !l.trim())) {
        return "<ul>" + lines.filter((l) => l.trim())
          .map((l) => `<li>${inline(l.replace(/^\s*([-*]|\d+\.)\s/, ""))}</li>`).join("") + "</ul>";
      }
      return lines.map((l) => {
        const h = l.match(/^(#{1,4})\s+(.*)$/);
        return h ? `<h4>${inline(h[2])}</h4>` : inline(l);
      }).join("<br>").replace(/<\/h4><br>/g, "</h4>");
    }).map((p) => (p.startsWith("<ul>") || p.startsWith("<h4>") ? p : `<p>${p}</p>`)).join("");
  }).join("");
}
function inline(s) {
  return s.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
}

/* -------------------------------------------------------------- the sheet */

/* "the server" or "this computer", for the words on screen. */
function machine() {
  if (ins.ident) return ins.ident.local ? "this computer" : "the server";
  return ins.pane && !ins.pane.session.ssh && !(ins.pane.where && ins.pane.where.hop)
    ? "this computer" : "the server";
}

function openInsight(pane, tool = "health") {
  if (!pane || !pane.session) return;
  if (ins.sid !== pane.session.id) { ins.cache = {}; ins.ident = null; ins.conn = null; }
  ins.pane = pane; ins.sid = pane.session.id;
  $("#insightTitle").textContent = pane.session.ssh || (pane.where && pane.where.hop) || "This computer";
  $("#insightIdent").textContent = "identifying…";
  $("#insightWrap").hidden = false;
  buildNav();
  identify();
  selectTool(tool);
}

function closeInsight() {
  $("#insightWrap").hidden = true;
  stopTimer();
}

function stopTimer() { if (ins.timer) { clearTimeout(ins.timer); ins.timer = null; } }

function buildNav() {
  const nav = clear($("#insightNav"));
  for (const t of TOOLS) {
    nav.append(el("button", { class: "ins-tool" + (t.key === ins.tool ? " on" : ""), type: "button",
                              dataset: { tool: t.key }, onClick: () => selectTool(t.key) },
      el("span", { class: "ins-icon", text: t.icon }), el("span", { text: t.label })));
  }
}

async function identify() {
  try {
    const id = ins.ident = await iapi("identity");
    // A local pane's shell went to a server, or came back: different machine.
    if (ins.conn && ins.conn !== id.connection) ins.cache = {};
    ins.conn = id.connection;
    $("#insightTitle").textContent = id.local ? "This computer" : id.connection;
    $("#insightIdent").textContent =
      [id.hostname, id.os_name].filter(Boolean).join(" · ") || id.connection;
    $("#insightIdent").title = [`Identity: ${id.uid}`, `From: ${id.source_label}`,
      id.kernel && `Kernel: ${id.kernel}`, (id.addresses || []).length && `Addresses: ${id.addresses.join(", ")}`]
      .filter(Boolean).join("\n");
  } catch (e) {
    $("#insightIdent").textContent = e.message;
  }
}

function selectTool(key) {
  stopTimer();
  ins.tool = key;
  for (const b of document.querySelectorAll(".ins-tool")) b.classList.toggle("on", b.dataset.tool === key);
  const body = clear($("#insightBody"));
  const t = TOOLS.find((x) => x.key === key);
  body.append(el("h3", { class: "ins-h" }, el("span", { class: "ins-icon", text: t.icon }), t.label));
  const host = el("div", { class: "ins-content" });
  body.append(host);
  ({ health: showHealth, perf: showPerf, logs: showLogs, ai: showAI, pkgs: showPackages,
     vulns: showVulns, hist: showHistory })[key](host);
}

function busy(host, text) {
  clear(host).append(el("div", { class: "ins-busy" }, el("span", { class: "ins-spin" }), text));
}
function failed(host, e, retry) {
  clear(host).append(el("div", { class: "ins-card sev-crit" }, el("b", { text: `Could not read ${machine()}` }),
    el("p", { text: e.message || String(e) }),
    retry ? el("button", { class: "btn sm", onClick: retry }, "Try again") : null));
}
const stillOn = (key, sid) => ins.tool === key && ins.sid === sid && !$("#insightWrap").hidden;

function findingsList(findings) {
  if (!findings || !findings.length) return el("p", { class: "ins-dim", text: "Nothing to report." });
  return el("div", { class: "ins-findings" }, findings.map((f) =>
    el("div", { class: "ins-finding " + sevClass(f.severity || f.status) },
      el("b", { text: f.title }), f.detail ? el("div", { text: f.detail }) : null,
      f.action ? el("div", { class: "ins-action", html: null }, el("span", { html: null }, "→ "),
                                                                   el("span", { text: f.action })) : null)));
}

function table(headers, rows, { numeric = [], cls = "" } = {}) {
  return el("div", { class: "ins-table-wrap" }, el("table", { class: "ins-table " + cls },
    el("thead", {}, el("tr", {}, headers.map((h, i) => el("th", { class: numeric.includes(i) ? "num" : "" }, h)))),
    el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c, i) =>
      el("td", { class: numeric.includes(i) ? "num" : "" }, c)))))));
}

function tile(label, value, sub, status) {
  return el("div", { class: "ins-tile " + (status ? sevClass(status) : "") },
    el("div", { class: "k", text: label }), el("div", { class: "v", text: value }),
    sub ? el("div", { class: "s", text: sub }) : null);
}

function meter(label, value, levels, sub) {
  const [warn, bad] = levels || [75, 90];
  const lvl = value >= bad ? "crit" : value >= warn ? "warn" : "ok";
  return el("div", { class: "ins-meter sev-" + lvl },
    el("div", { class: "ins-mrow" }, el("span", { text: label }), el("b", { text: pct(value) })),
    el("div", { class: "bar" }, el("i", { style: { width: `${Math.min(100, Math.max(0, value || 0))}%` } })),
    sub ? el("div", { class: "s", text: sub }) : null);
}

/* Line chart: one SVG, several series, values may be null. */
const PALETTE = ["#00f0ff", "#ff2ed1", "#ffb020", "#39ff88", "#b14cff", "#7aa9ff", "#ff3860", "#d8e3f5"];
function chart(title, unit, series, labels) {
  const W = 560, H = 130, P = 6;
  const all = series.flatMap((s) => s.values).filter((v) => v != null);
  const max = Math.max(1, ...all) * 1.1;
  const n = Math.max(...series.map((s) => s.values.length), 2);
  const x = (i) => P + (i * (W - 2 * P)) / (n - 1);
  const y = (v) => H - P - (v / max) * (H - 2 * P);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("class", "ins-chart");
  for (const g of [0.25, 0.5, 0.75]) {
    const l = document.createElementNS(ns, "line");
    Object.entries({ x1: P, x2: W - P, y1: y(max * g), y2: y(max * g), class: "grid" }).forEach(([k, v]) => l.setAttribute(k, v));
    svg.append(l);
  }
  series.forEach((s, si) => {
    const pts = s.values.map((v, i) => (v == null ? null : `${x(i).toFixed(1)},${y(v).toFixed(1)}`)).filter(Boolean);
    if (!pts.length) return;
    const pl = document.createElementNS(ns, "polyline");
    pl.setAttribute("points", pts.join(" ")); pl.setAttribute("stroke", PALETTE[si % PALETTE.length]);
    pl.setAttribute("fill", "none"); pl.setAttribute("stroke-width", "1.6");
    svg.append(pl);
  });
  const legend = el("div", { class: "ins-legend" }, series.map((s, si) =>
    el("span", {}, el("i", { style: { background: PALETTE[si % PALETTE.length] } }), s.name)));
  const span = labels && labels.length ? `${labels[0]} – ${labels[labels.length - 1]}` : "";
  return el("div", { class: "ins-chart-box" },
    el("div", { class: "ins-chart-head" }, el("b", { text: title }),
      el("span", { class: "ins-dim", text: `${unit}${span ? " · " + span : ""} · max ${(max / 1.1).toFixed(1)}` })),
    svg, legend);
}

/* ----------------------------------------------------------------- health */

async function showHealth(host) {
  const sid = ins.sid;
  if (!ins.cache.health) busy(host, `Reading /proc on ${machine()}…`);
  const tick = async () => {
    try {
      const d = ins.cache.health = await iapi("health");
      if (stillOn("health", sid)) drawHealth(host, d);
    } catch (e) {
      if (stillOn("health", sid)) failed(host, e, () => showHealth(host));
      return;
    }
    if (stillOn("health", sid)) ins.timer = setTimeout(tick, 5000);
  };
  if (ins.cache.health) drawHealth(host, ins.cache.health);
  tick();
}

function drawHealth(host, d) {
  const s = d.sample || {}, lv = d.levels || {}, h = d.history || [];
  clear(host);
  host.append(el("div", { class: "ins-status " + sevClass(s.status) },
    el("b", { text: (s.status || "unknown").toUpperCase() }),
    ` ${s.hostname || ""} · up ${d.uptime} · ${s.ncpu} CPU · load ${(s.load || []).map((x) => x.toFixed(2)).join(" / ")} · refreshes every 5 s`));
  host.append(el("div", { class: "ins-meters" },
    meter("CPU", s.cpu, lv.cpu),
    meter("Memory", s.mem, lv.mem, `${bytes(s.mem_used)} of ${bytes(s.mem_total)}`),
    meter("Swap", s.swap, lv.swap, s.swap_total ? `${bytes(s.swap_used)} of ${bytes(s.swap_total)}` : "none"),
    meter("Fullest disk", s.disk, lv.disk)));
  host.append(el("div", { class: "ins-tiles" },
    tile("Network in", `${bytes(s.net_rx)}/s`), tile("Network out", `${bytes(s.net_tx)}/s`),
    tile("Processes", String(s.proc_count), s.zombies ? `${s.zombies} zombie(s)` : "", s.zombies ? "warn" : ""),
    tile("Connections", String((s.connections || {}).established ?? "—"),
         `${(s.connections || {}).unique_ips ?? 0} source(s) · ${(s.connections || {}).syn_recv ?? 0} half-open`)));
  if (h.length > 1) {
    host.append(el("div", { class: "ins-charts" },
      chart("CPU and memory", "%", [{ name: "CPU", values: h.map((x) => x.cpu) }, { name: "Memory", values: h.map((x) => x.mem) }]),
      chart("Load (1 min)", "processes", [{ name: "Load", values: h.map((x) => x.load1) }])));
  }
  if ((d.alerts || []).length) {
    host.append(el("h4", { text: "Alerts" }),
      findingsList(d.alerts.slice().reverse().map((a) => ({ severity: a.severity, title: a.title, detail: `${a.message} · ${when(a.ts)}` }))));
  }
  const procRows = (list) => list.slice(0, 10).map((p) => [String(p.pid), p.user, p.name, pct(p.cpu), bytes(p.rss), String(p.threads), stopButton(p)]);
  host.append(el("h4", { text: "Top processes by CPU" }),
    table(["PID", "User", "Process", "CPU (core)", "Memory", "Threads", ""], procRows(s.top_cpu || []), { numeric: [0, 3, 4, 5] }));
  host.append(el("h4", { text: "Top processes by memory" }),
    table(["PID", "User", "Process", "CPU (core)", "Memory", "Threads", ""], procRows(s.top_mem || []), { numeric: [0, 3, 4, 5] }));
  const c = s.connections || {};
  if ((c.top_ips || []).length) {
    host.append(el("h4", { text: "Inbound connections by source" }),
      table(["Source", "Connections"], c.top_ips.map(([ip, n]) => [ip, String(n)]), { numeric: [1] }));
  }
  if ((s.disks || []).length) {
    host.append(el("h4", { text: "Disks" }), table(["Mount", "Used", "Size", "Use"],
      s.disks.map((k) => [k.mount || k.path || "", bytes(k.used), bytes(k.total), pct(k.percent)]), { numeric: [1, 2, 3] }));
  }
}

/* Stopping a process is the one write the tools make: two clicks, no dialog. */
function stopButton(p) {
  if (p.pid <= 1) return "";
  const b = el("button", { class: "btn xs", type: "button", text: "Stop" });
  let armed = false, timer = null;
  b.onclick = async () => {
    if (!armed) {
      armed = true; b.textContent = `Stop ${p.name}?`; b.classList.add("danger");
      timer = setTimeout(() => { armed = false; b.textContent = "Stop"; b.classList.remove("danger"); }, 4000);
      return;
    }
    clearTimeout(timer); b.disabled = true;
    try {
      const r = await ipost("health/stop", { pid: p.pid });
      toast(r.ok ? "Process stopped" : "Could not stop it", { body: r.message, severity: r.ok ? "ok" : "warning" });
    } catch (e) { toast("Could not stop it", { body: e.message, severity: "error" }); }
  };
  return b;
}

/* ------------------------------------------------------------ performance */

async function showPerf(host) {
  const sid = ins.sid;
  try {
    const d = await iapi(`perf?tzo=${new Date().getTimezoneOffset()}`);
    if (!stillOn("perf", sid)) return;
    drawPerf(host, d);
    if (d.state === "running") ins.timer = setTimeout(() => showPerf(host), 2500);
  } catch (e) { failed(host, e, () => showPerf(host)); }
}

function perfControls(running) {
  const mode = el("select", { class: "ins-input" },
    el("option", { value: "quick" }, "Quick — 15 s"), el("option", { value: "standard" }, "Standard — 30 s"),
    el("option", { value: "long" }, "Long — choose"));
  const dur = el("select", { class: "ins-input", hidden: true },
    [5, 10, 30, 60, 120].map((m) => el("option", { value: m * 60 }, `${m} min`)));
  const every = el("select", { class: "ins-input", hidden: true },
    [5, 10, 15, 30, 60].map((s) => el("option", { value: s }, `every ${s} s`)));
  mode.onchange = () => { dur.hidden = every.hidden = mode.value !== "long"; };
  const start = el("button", { class: "btn sm primary", disabled: running, text: "Start check" });
  start.onclick = async () => {
    start.disabled = true;
    try {
      await ipost("perf/start", { mode: mode.value, duration: Number(dur.value), interval: Number(every.value) });
      showPerf(start.closest(".ins-content"));
    } catch (e) { toast("Could not start", { body: e.message, severity: "error" }); start.disabled = false; }
  };
  const stop = el("button", { class: "btn sm", hidden: !running, text: "Stop" });
  stop.onclick = () => ipost("perf/stop").catch(() => {});
  return el("div", { class: "ins-controls" }, mode, dur, every, start, stop);
}

function drawPerf(host, d) {
  clear(host);
  const running = d.state === "running";
  host.append(el("p", { class: "ins-lede" },
    "TractorBeam's performance check: CPU, load, memory, swap, network and connections sampled over a window, ",
    "attributed to processes and judged. Read-only."));
  host.append(perfControls(running));
  if (d.state === "none") return;
  if (running) {
    host.append(el("div", { class: "ins-progress" }, el("i", { style: { width: `${Math.round(d.progress * 100)}%` } })),
      el("p", { class: "ins-dim", text: `${d.label}: ${d.elapsed} s of ${d.total} s — the report fills in as samples arrive.` }));
  }
  if (d.error) host.append(el("div", { class: "ins-card sev-warn", text: d.error }));
  if (d.fallback) {
    host.append(el("div", { class: "ins-card " + sevClass(d.fallback.severity) }, el("b", { text: d.fallback.headline })),
      el("pre", { class: "ins-pre", text: d.fallback.text }));
    return;
  }
  const L = d.layout;
  if (!L) return;
  host.append(el("div", { class: "ins-status " + sevClass(L.verdict) }, el("b", { text: d.headline || "Performance check" })),
    el("p", { class: "ins-dim", text: `${L.source} — ${L.window}` }));
  host.append(el("div", { class: "ins-tiles" }, (L.tiles || []).map((t) => tile(t.label, t.value, t.sub, t.status))));
  host.append(el("h4", { text: "Findings" }), findingsList(L.findings));
  if (!running && d.state === "finished") {
    const ask = el("button", { class: "btn sm primary", text: d.diagnosis ? "Ask Claude again" : "✦ Ask Claude to investigate" });
    ask.onclick = () => aiPreview("perf", host);
    host.append(el("div", { class: "ins-controls" }, ask));
  }
  for (const sec of L.sections || []) {
    host.append(el("div", { class: "ins-ai" }, el("h4", { text: sec.title }), el("div", { class: "ins-md", html: null })));
    host.lastChild.querySelector(".ins-md").innerHTML = md(sec.text);
  }
  host.append(el("div", { class: "ins-charts" }, (L.charts || []).map((c) => chart(c.title, c.unit, c.series, c.t))));
  for (const t of L.tables || []) {
    const numeric = [];
    for (let i = t.numeric_from ?? 99; i <= (t.numeric_to ?? -1); i++) numeric.push(i);
    host.append(el("h4", { text: t.title }), t.note ? el("p", { class: "ins-dim", text: t.note }) : null,
      table(t.headers, t.rows, { numeric }));
  }
}

/* ------------------------------------------------------------------- logs */

async function showLogs(host, force = false) {
  const sid = ins.sid;
  if (ins.cache.logs && !force) return drawLogs(host, ins.cache.logs);
  busy(host, "Reading the journal and /var/log for errors…");
  try {
    const d = ins.cache.logs = await ipost("logs");
    if (stillOn("logs", sid)) drawLogs(host, d);
  } catch (e) { if (stillOn("logs", sid)) failed(host, e, () => showLogs(host, true)); }
}

function drawLogs(host, d) {
  clear(host);
  host.append(el("div", { class: "ins-status " + sevClass(d.severity) }, el("b", { text: d.headline })),
    el("p", { class: "ins-dim", text: d.summary }),
    el("div", { class: "ins-controls" },
      el("button", { class: "btn sm", onClick: () => showLogs(host, true) }, "Read again"),
      el("button", { class: "btn sm primary", onClick: () => selectTool("ai") }, "✦ Ask Claude about these")));
  const cats = Object.entries(d.categories || {});
  if (cats.length) {
    host.append(el("div", { class: "ins-tiles" }, cats.map(([k, n]) =>
      tile(d.category_labels[k] || k, String(n), (d.advice || {})[k] || "", ["kernel", "disk", "memory"].includes(k) ? "warn" : ""))));
  }
  if ((d.signatures || []).length) {
    host.append(el("h4", { text: "Recurring errors" }),
      table(["Count", "Kind", "Pattern", "Where"], d.signatures.map((s) =>
        [String(s.count), d.category_labels[s.category] || s.category,
         el("code", { text: s.pattern, title: s.example }), (s.sources || []).join(", ")]), { numeric: [0] }));
  }
  if ((d.unreadable || []).length) {
    host.append(el("p", { class: "ins-dim", text: `Out of reach for this login: ${d.unreadable.join(", ")}` }));
  }
}

/* --------------------------------------------------------------------- AI */

async function showAI(host) {
  const sid = ins.sid;
  busy(host, "Gathering the error lines (redacted) that would be sent…");
  try {
    const p = await ipost("logs/ai/preview");
    ins.cache.logs = p.report;
    if (!stillOn("ai", sid)) return;
    clear(host);
    if (!p.payload) {
      host.append(el("div", { class: "ins-card sev-ok" }, el("b", { text: p.report.headline }),
        el("p", { text: "There is nothing to send for analysis." })));
      return;
    }
    consent(host, p.payload, "These error lines go to Claude through your Claude Code subscription. Secrets were replaced with *** before you see them; nothing else — not the address, not the machine's identity — is sent.",
      async (out) => {
        const r = await ipost("logs/ai", { payload: p.payload });
        return r;
      });
  } catch (e) { if (stillOn("ai", sid)) failed(host, e, () => showAI(host)); }
}

async function aiPreview(kind, perfHost) {
  try {
    const p = await ipost(`${kind}/ai/preview`);
    const host = perfHost;
    const box = el("div", { class: "ins-ai" });
    host.prepend(box);
    consent(box, p.payload, "The analysis pack below goes to Claude through your Claude Code subscription. Command lines were redacted; nothing about the connection is added.",
      async () => { const r = await ipost(`${kind}/ai`, { payload: p.payload }); showPerf(host); return r; });
    box.scrollIntoView({ behavior: "smooth" });
  } catch (e) { toast("Cannot ask yet", { body: e.message, severity: "warning" }); }
}

function consent(host, payload, note, send) {
  const go = el("button", { class: "btn sm primary", text: "Send to Claude" });
  const answer = el("div", { class: "ins-md" });
  go.onclick = async () => {
    go.disabled = true; go.textContent = "Claude is reading…";
    try {
      const r = await send();
      answer.innerHTML = md(r.answer);
      const u = r.usage || {};
      if (u.cost != null) answer.append(el("p", { class: "ins-dim",
        text: u.subscription ? `Included in your subscription (~$${u.cost.toFixed(3)} at API rates)` : `$${u.cost.toFixed(4)}` }));
      go.textContent = `Answered — saved to ${machine()}'s history`;
      pre.hidden = true;
    } catch (e) { answer.textContent = e.message; go.disabled = false; go.textContent = "Send to Claude"; }
  };
  const pre = el("pre", { class: "ins-pre", text: payload });
  host.append(el("div", { class: "ins-card sev-info" }, el("b", { text: "Exactly what will be sent" }), el("p", { text: note })),
    pre, el("div", { class: "ins-controls" }, go, el("span", { class: "ins-dim", text: `${payload.length.toLocaleString()} characters` })),
    answer);
}

/* --------------------------------------------------------------- packages */

async function showPackages(host, force = false) {
  const sid = ins.sid;
  if (ins.cache.pkgs && !force) return drawPackages(host, ins.cache.pkgs);
  busy(host, "Listing packages, versions, processes and listening ports…");
  try {
    const d = ins.cache.pkgs = await ipost("packages");
    if (stillOn("pkgs", sid)) drawPackages(host, d);
  } catch (e) { if (stillOn("pkgs", sid)) failed(host, e, () => showPackages(host, true)); }
}

function drawPackages(host, d) {
  clear(host);
  host.append(el("div", { class: "ins-status " + sevClass(d.severity) }, el("b", { text: d.headline })),
    el("p", { class: "ins-dim", text: [d.os_name, d.kernel].filter(Boolean).join(" · ") }));
  if ((d.technologies || []).length) {
    host.append(el("h4", { text: "Technologies" }), table(["Software", "Kind", "Version", "Ports", "Evidence"],
      d.technologies.map((t) => [el("b", { text: t.name }), t.category, t.version || "—",
        (t.ports || []).join(", "), (t.evidence || []).join(", ") + (t.guessed ? " (guessed)" : "")])));
  }
  if ((d.listeners || []).length) {
    host.append(el("h4", { text: "Listening ports" }), table(["Port", "Proto", "Address", "Process", "Reachable"],
      d.listeners.map((l) => [String(l.port), l.proto, l.address, l.process || "—",
        el("span", { class: l.exposed ? "sev-warn-text" : "ins-dim", text: l.exposed ? "from the network" : "this host only" })]),
      { numeric: [0] }));
  }
  const filter = el("input", { class: "ins-input wide", placeholder: `Search ${d.packages.length} packages…` });
  const out = el("div");
  const draw = () => {
    const q = filter.value.trim().toLowerCase();
    const rows = d.packages.filter((p) => !q || p.name.toLowerCase().includes(q) || (p.version || "").includes(q));
    clear(out).append(table(["Package", "Version", "Manager", "Arch"],
      rows.slice(0, 400).map((p) => [p.name, p.version, p.manager, p.arch || ""])),
      rows.length > 400 ? el("p", { class: "ins-dim", text: `${rows.length - 400} more — narrow the search.` }) : null);
  };
  filter.oninput = draw;
  host.append(el("h4", { text: "Installed packages" }), filter, out);
  draw();
}

/* -------------------------------------------------------- vulnerabilities */

async function showVulns(host, force = false) {
  const sid = ins.sid;
  if (ins.cache.vulns && !force) return drawVulns(host, ins.cache.vulns);
  busy(host, "Checking pending security updates, support status and weak settings…");
  try {
    const d = ins.cache.vulns = await ipost("vulns");
    if (stillOn("vulns", sid)) drawVulns(host, d);
  } catch (e) { if (stillOn("vulns", sid)) failed(host, e, () => showVulns(host, true)); }
}

function drawVulns(host, d) {
  clear(host);
  host.append(el("div", { class: "ins-status " + sevClass(d.severity) }, el("b", { text: d.headline })));
  host.append(el("h4", { text: machine() === "the server" ? "On the server" : "On this computer" }), findingsList(d.findings));
  if (d.looked_up) {
    const c = d.counts || {};
    host.append(el("h4", { text: `Known vulnerabilities (OSV, ${d.packages_checked} packages, ${d.ecosystem})` }),
      el("div", { class: "ins-tiles" }, tile("Critical", String(c.critical || 0), "", c.critical ? "crit" : "ok"),
        tile("High", String(c.high || 0), "", c.high ? "warn" : "ok"), tile("Medium", String(c.medium || 0)),
        tile("Low", String(c.low || 0)), tile("Unrated", String(c.unknown || 0))));
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    const rows = (d.vulns || []).slice().sort((a, b) => (order[a.level] ?? 4) - (order[b.level] ?? 4) || (b.score || 0) - (a.score || 0));
    host.append(table(["Level", "Score", "ID", "Package", "Version", "Fixed in", "Summary"],
      rows.slice(0, 300).map((v) => [el("span", { class: sevClass(v.level) + "-text", text: v.level }),
        v.score != null ? v.score.toFixed(1) : "—",
        el("a", { href: v.url, target: "_blank", rel: "noopener noreferrer", text: v.id }),
        v.package, v.version, v.fixed || "—", el("span", { class: "ins-clip", text: v.summary, title: v.summary })]),
      { numeric: [1] }));
    if (d.online_error) host.append(el("div", { class: "ins-card sev-warn", text: d.online_error }));
    return;
  }
  const osv = d.osv || {};
  if (!osv.preview) {
    host.append(el("p", { class: "ins-dim", text: osv.reason || d.online_note || "" }));
    return;
  }
  const go = el("button", { class: "btn sm primary", text: `Look up ${osv.packages} packages in OSV` });
  go.onclick = async () => {
    go.disabled = true; go.textContent = "Asking OSV…";
    try { ins.cache.vulns = await ipost("vulns/lookup"); drawVulns(host, ins.cache.vulns); }
    catch (e) { toast("Lookup failed", { body: e.message, severity: "error" }); go.disabled = false; }
  };
  host.append(el("h4", { text: "Known vulnerabilities" }),
    el("div", { class: "ins-card sev-info" }, el("b", { text: "Look the packages up in OSV.dev?" }),
      el("p", { text: "This sends package names and versions — and nothing else — to Google's open vulnerability database. Exactly this:" })),
    el("pre", { class: "ins-pre short", text: osv.preview }), el("div", { class: "ins-controls" }, go));
}

/* ---------------------------------------------------------------- history */

async function showHistory(host) {
  const sid = ins.sid;
  busy(host, `Reading what is known about ${machine() === "the server" ? "this server" : "this computer"}…`);
  try {
    const d = await iapi("history");
    if (!stillOn("hist", sid)) return;
    clear(host);
    const id = d.identity || {}, s = d.server;
    host.append(el("div", { class: "ins-tiles" },
      tile("Identity", id.uid ? id.uid.slice(0, 22) + (id.uid.length > 22 ? "…" : "") : "unknown", id.source_label),
      tile("Host", id.hostname || "—", id.os_name),
      tile("First seen", s ? new Date(s.first_seen * 1000).toLocaleDateString() : "—", s ? `last ${when(s.last_seen)}` : ""),
      tile("Reached as", String((s && s.connections || []).length), (s && s.connections || []).slice(0, 3).join(", "))));
    if (!s || !s.events.length) {
      host.append(el("p", { class: "ins-dim", text: "Nothing studied here yet. Every analysis you run is kept here, against the machine's own identity — not its address." }));
      return;
    }
    host.append(el("div", { class: "ins-timeline" }, s.events.map((e) => {
      const kind = { performance: "⚡", logs: "☰", ai: "✦", inventory: "▤", vulns: "⛨", action: "■" }[e.kind] || "•";
      const det = el("details", { class: "ins-event " + sevClass(e.severity) },
        el("summary", {}, el("span", { class: "ins-icon", text: kind }), el("b", { text: e.title }),
          el("span", { class: "ins-dim", text: `${when(e.t)} · ${e.connection}` })));
      det.addEventListener("toggle", () => {
        if (det.open && !det.querySelector(".ins-md")) {
          const body = el("div", { class: "ins-md" });
          if (e.kind === "ai") body.innerHTML = md(e.body); else body.append(el("pre", { class: "ins-pre", text: e.body }));
          det.append(body);
        }
      }, { once: false });
      return det;
    })));
  } catch (e) { if (stillOn("hist", sid)) failed(host, e, () => showHistory(host)); }
}

/* ------------------------------------------------------------------ wiring */

document.addEventListener("DOMContentLoaded", () => {
  $("#btnInsightClose").onclick = closeInsight;
  $("#insightWrap").onclick = (e) => { if (e.target.id === "insightWrap") closeInsight(); };
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("#insightWrap").hidden) { e.preventDefault(); closeInsight(); }
    // Ctrl+Shift+X: browsers keep Ctrl+Shift+T and Ctrl+Shift+I for themselves.
    if (e.ctrlKey && e.shiftKey && (e.key === "X" || e.key === "x")) {
      const pane = state.focus ? state.panes.get(state.focus) : null;
      if (pane && pane.session) { e.preventDefault(); openInsight(pane); }
    }
  }, true);
});
