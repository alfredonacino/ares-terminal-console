"use strict";
// Shared by the account and administration pages. No framework: small DOM helpers, a JSON fetch
// that sends people to the sign-in page when their session ends, a confirm dialog, and copy buttons.
window.GW = (function () {
  const $ = (id) => document.getElementById(id);
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "onclick") e.addEventListener("click", v);
      else if (k === "onchange") e.addEventListener("change", v);
      else if (k === "text") e.textContent = v;
      else if (k === "checked" || k === "disabled" || k === "selected") e[k] = !!v;
      else if (k === "value") e.value = v;
      else if (v !== false && v != null) e.setAttribute(k, v);
    }
    for (const k of kids) {
      if (k == null || k === false) continue;
      e.append(typeof k === "string" || typeof k === "number" ? document.createTextNode(String(k)) : k);
    }
    return e;
  }
  const fmt = (t) => (t ? new Date(t * 1000).toLocaleString() : "—");
  const ago = (t) => {
    if (!t) return "—";
    const s = Math.max(0, Date.now() / 1000 - t);
    if (s < 60) return Math.round(s) + " s ago";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  };
  const size = (n) => {
    if (n == null) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  };
  const pill = (text, kind) => el("span", { class: "pill " + (kind || ""), text });
  const td = (...kids) => el("td", {}, ...kids);

  function flash(text, kind) {
    const f = $("flash");
    if (!f) return;
    f.textContent = text;
    f.className = "msg " + (kind || "ok") + " show";
    f.setAttribute("role", kind === "err" ? "alert" : "status");
    clearTimeout(flash._t);
    flash._t = setTimeout(() => { f.className = "msg"; }, kind === "err" ? 10000 : 4500);
  }

  async function api(url, method, body, opts) {
    const o = { method: method || "GET", credentials: "same-origin", headers: {} };
    if (opts && opts.raw !== undefined) {
      o.body = opts.raw;
      o.headers["Content-Type"] = "application/octet-stream";
      Object.assign(o.headers, opts.headers || {});
    } else if (body !== undefined) {
      o.headers["Content-Type"] = "application/json";
      o.body = JSON.stringify(body);
    }
    const r = await fetch(url, o);
    if (r.status === 401) {
      location.replace("/login?next=" + encodeURIComponent(location.pathname + location.hash));
      throw new Error("Your session has ended.");
    }
    let data = {};
    try { data = await r.json(); } catch (e) { /* none */ }
    if (!r.ok) {
      if (r.status === 403 && (data.code === "password_change_required" || data.code === "mfa_enroll_required")) {
        location.replace("/login?next=" + encodeURIComponent(location.pathname));
      }
      throw new Error(data.detail || data.message || r.statusText);
    }
    return data;
  }

  function confirmBox(title, text, yes) {
    return new Promise((resolve) => {
      $("dc-title").textContent = title;
      $("dc-text").textContent = text;
      $("dc-yes").textContent = yes || "Confirm";
      const d = $("d-confirm");
      const done = (v) => { d.close(); $("dc-yes").onclick = $("dc-no").onclick = d.oncancel = null; resolve(v); };
      $("dc-yes").onclick = () => done(true);
      $("dc-no").onclick = () => done(false);
      d.oncancel = () => done(false);
      d.showModal();
      $("dc-no").focus();
    });
  }

  // Show a secret once (generated password, new token) in the "show once" dialog.
  function showOnce(title, text, value, extra) {
    $("so-title").textContent = title;
    $("so-text").textContent = text;
    $("so-value").value = value;
    $("so-extra").textContent = extra || "";
    $("so-extra").hidden = !extra;
    $("d-once").showModal();
  }

  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    const inp = $(b.dataset.copy);
    navigator.clipboard.writeText(inp.value).then(() => {
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = "Copy"), 1500);
    }, () => inp.select());
  });
  document.addEventListener("DOMContentLoaded", () => {
    const ok = $("so-ok");
    if (ok) ok.addEventListener("click", () => { $("so-value").value = ""; $("d-once").close(); });
  });

  function table(target, headers, rows, empty) {
    const t = $(target);
    t.replaceChildren(el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { scope: "col", text: h })))));
    const tb = el("tbody");
    if (!rows.length) tb.append(el("tr", {}, el("td", { colspan: headers.length, class: "empty", text: empty || "Nothing here yet." })));
    for (const r of rows) tb.append(r);
    t.append(tb);
  }

  function svgFrom(markup) {
    const doc = new DOMParser().parseFromString(markup, "image/svg+xml");
    const svg = doc.documentElement;
    return svg && svg.nodeName.toLowerCase() === "svg" ? document.importNode(svg, true) : null;
  }

  return { $, el, fmt, ago, size, pill, td, flash, api, confirmBox, showOnce, table, svgFrom };
})();
