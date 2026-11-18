"use strict";
// Administration: users, sessions, terminals, audit & activity, tokens, log forwarding,
// backup & restore, single sign-on and policies. On the desktop (mode "local") only the
// pages that make sense without users are shown.
(function () {
  const { $, el, fmt, ago, size, pill, td, flash, api, confirmBox, showOnce, table } = window.GW;
  let me = null;
  let mode = "users";

  // ─── forms from a field list ───────────────────────────────────────────────
  // {k, label, type: text|number|password|secret|secretarea|textarea|list|select|check|checks|time,
  //  options: [[value, label]], hint, placeholder, min, max}
  function buildForm(container, spec, vals) {
    vals = vals || {};
    const fields = [];
    const root = el("div", { class: "grid2" });
    let n = 0;
    for (const f of spec) {
      const id = "ff-" + f.k + "-" + (++n) + "-" + Math.random().toString(36).slice(2, 6);
      const v = vals[f.k];
      let input, wrap, extra = null;
      if (f.type === "check") {
        input = el("input", { type: "checkbox", id, checked: !!v });
        wrap = el("div", {}, el("label", { class: "check", for: id }, input, " ", f.label));
      } else if (f.type === "checks") {
        const boxes = f.options.map(([ov, ol]) => {
          const cb = el("input", { type: "checkbox", value: ov, checked: (v || []).includes(ov) });
          return [cb, el("label", { class: "check" }, cb, " ", ol)];
        });
        input = { checks: boxes.map((b) => b[0]) };
        wrap = el("div", {}, el("fieldset", {}, el("legend", { text: f.label }), ...boxes.map((b) => b[1])));
      } else {
        if (f.type === "select") {
          input = el("select", { id }, ...f.options.map(([ov, ol]) => el("option", { value: String(ov), text: ol })));
          input.value = v == null ? String(f.options[0][0]) : String(v);
        } else if (f.type === "textarea" || f.type === "list" || f.type === "secretarea") {
          input = el("textarea", { id, placeholder: f.placeholder || "" });
          input.value = f.type === "list" ? (v || []).join("\n") : f.type === "secretarea" ? "" : (v || "");
        } else {
          const t = f.type === "secret" ? "password" : (f.type || "text");
          input = el("input", { id, type: t, placeholder: f.placeholder || "", autocomplete: t === "password" ? "new-password" : "off",
            min: f.min != null ? f.min : null, max: f.max != null ? f.max : null });
          input.value = f.type === "secret" ? "" : (v == null ? "" : String(v));
        }
        if (f.type === "secret" || f.type === "secretarea") {
          const isSet = v === "set" || v === true;
          input.placeholder = isSet ? "set — leave empty to keep it" : "not set";
          if (isSet) {
            const cb = el("input", { type: "checkbox" });
            extra = cb;
            wrap = el("div", {}, el("label", { for: id, text: f.label }), input,
              el("label", { class: "check" }, cb, " remove it"));
          }
        }
        if (f.readonly) input.disabled = true;
        if (!wrap) wrap = el("div", {}, el("label", { for: id, text: f.label }), input);
      }
      if (f.hint) wrap.append(el("div", { class: "hint", text: f.hint }));
      if (f.wide) wrap.style.gridColumn = "1 / -1";
      root.append(wrap);
      fields.push({ f, input, extra });
    }
    container.replaceChildren(root);
    return {
      read() {
        const out = {};
        for (const { f, input, extra } of fields) {
          if (f.readonly) continue;
          if (f.type === "check") out[f.k] = input.checked;
          else if (f.type === "checks") out[f.k] = input.checks.filter((c) => c.checked).map((c) => c.value);
          else if (f.type === "number") { if (input.value !== "") out[f.k] = Number(input.value); }
          else if (f.type === "list") out[f.k] = input.value.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
          else if (f.type === "secret" || f.type === "secretarea") {
            if (extra && extra.checked) out[f.k] = "";
            else if (input.value !== "") out[f.k] = input.value;
          } else out[f.k] = input.value;
        }
        return out;
      },
    };
  }

  function formDialog(title, text, spec, vals, onSave, yes) {
    $("df-title").textContent = title;
    $("df-text").textContent = text || "";
    $("df-text").hidden = !text;
    $("df-msg").className = "msg err";
    $("df-yes").textContent = yes || "Save";
    const form = buildForm($("df-body"), spec, vals);
    const d = $("d-form");
    $("df-form").onsubmit = async (ev) => {
      ev.preventDefault();
      $("df-yes").disabled = true;
      try { await onSave(form.read()); d.close(); }
      catch (e) { $("df-msg").textContent = e.message; $("df-msg").className = "msg err show"; }
      finally { $("df-yes").disabled = false; }
    };
    $("df-no").onclick = () => d.close();
    d.showModal();
    const first = $("df-body").querySelector("input,select,textarea");
    if (first) first.focus();
  }
  const btn = (text, onclick, cls, label) => el("button", { type: "button", class: cls || "", text, onclick, "aria-label": label || null });
  const run = (fn) => async (...a) => { try { await fn(...a); } catch (e) { flash(e.message, "err"); } };

  // ─── tabs ──────────────────────────────────────────────────────────────────
  const loaders = {};
  function showTab(name) {
    const tabs = [...document.querySelectorAll("#tabs button")].filter((b) => !b.hidden);
    if (!tabs.some((b) => b.dataset.tab === name)) name = "overview";
    for (const b of tabs) {
      const on = b.dataset.tab === name;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    }
    for (const p of document.querySelectorAll(".panel")) p.classList.toggle("active", p.id === "p-" + name);
    if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
    run(loaders[name] || (() => {}))();
  }
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-tab]"); if (b) showTab(b.dataset.tab); });
  $("tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const tabs = [...document.querySelectorAll("#tabs button")].filter((b) => !b.hidden);
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const t = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    t.focus(); showTab(t.dataset.tab);
  });
  window.addEventListener("hashchange", () => showTab(location.hash.slice(1)));

  // ─── overview ──────────────────────────────────────────────────────────────
  loaders.overview = async () => {
    const s = await api("/admin/api/summary");
    const card = (n, l, kind) => el("div", { class: "card " + (kind || "") }, el("div", { class: "n", text: String(n) }), el("div", { class: "l", text: l }));
    const cards = [];
    if (s.mode === "users") {
      cards.push(card(s.users, "users"), card(s.admins, "administrators"), card(s.active_now, "online now"),
        card(s.mfa_enabled, "with 2FA"), card(s.signins_24h, "sign-ins, 24 h"),
        card(s.failures_24h, "failed sign-ins, 24 h", s.failures_24h ? "warn" : ""));
    }
    cards.push(card(s.terminals, "open terminals"), card(s.events_24h, "audit events, 24 h"),
      el("div", { class: "card " + (s.backup_last_ok_at ? "ok" : "warn") },
        el("div", { class: "n small", text: s.backup_last_ok_at ? ago(s.backup_last_ok_at) : "never" }),
        el("div", { class: "l", text: "last good backup" })));
    $("ov-cards").replaceChildren(...cards);
    $("ov-note").textContent = "ARES Terminal Console " + s.version + (s.mode === "local"
      ? " · desktop edition: no sign-in; backups, audit, log forwarding and API tokens are managed here."
      : " · web edition.");
  };

  // ─── users ─────────────────────────────────────────────────────────────────
  const ROLES = [["user", "user"], ["admin", "administrator"]];
  const SOURCES = [["local", "local password"], ["ldap", "LDAP / Active Directory"], ["oidc", "Microsoft Entra ID / OIDC"], ["saml", "SAML"]];
  let users = [];
  function renderUsers() {
    const q = $("u-filter").value.trim().toLowerCase();
    const rows = users.filter((u) => !q || [u.username, u.display_name, u.email, u.role, u.auth_source].join(" ").toLowerCase().includes(q))
      .map((u) => el("tr", {},
        td(el("b", { text: u.username }), u.display_name ? el("div", { class: "sub", text: u.display_name }) : null,
          u.email ? el("div", { class: "sub", text: u.email }) : null),
        td(pill(u.role, u.role === "admin" ? "violet" : "")),
        td((SOURCES.find((s) => s[0] === u.auth_source) || [0, u.auth_source])[1]),
        td(u.mfa_enabled ? pill("on", "ok") : pill(u.mfa_required ? "owed" : "off", u.mfa_required ? "warn" : "")),
        td(u.disabled ? pill("disabled", "err") : u.online ? pill("online", "ok") : pill("offline"),
          u.must_change ? el("div", {}, pill("must change password", "warn")) : null),
        td(String(u.terminals)),
        td(fmt(u.last_login_at), u.last_login_ip ? el("div", { class: "sub mono", text: u.last_login_ip }) : null),
        el("td", { class: "actions" },
          btn("Edit", () => editUser(u), "", "Edit " + u.username), " ",
          u.auth_source === "local" ? btn("Password", () => resetPassword(u), "", "Reset password of " + u.username) : null, " ",
          u.mfa_enabled ? btn("Reset 2FA", run(async () => {
            if (!await confirmBox("Reset 2FA of " + u.username + "?", "Their authenticator and recovery codes stop working. They set it up again at the next sign-in when required.", "Reset 2FA")) return;
            await api("/admin/api/users/" + u.id + "/2fa/reset", "POST", {}); flash("2FA reset for " + u.username + "."); loaders.users();
          }), "", "Reset 2FA of " + u.username) : null, " ",
          btn("Sign out", run(async () => {
            if (!await confirmBox("Sign out " + u.username + "?", "Ends every sign-in of this user and closes their terminals.", "Sign out")) return;
            const r = await api("/admin/api/users/" + u.id + "/signout", "POST", {});
            flash(`Ended ${r.sessions_ended} sign-in(s), closed ${r.terminals_closed} terminal(s).`); loaders.users();
          }), "", "Sign out " + u.username), " ",
          btn("Delete", run(async () => {
            if (!await confirmBox("Delete " + u.username + "?", "The account, its API tokens, terminals, history and saved connections are removed. Audit entries keep the name. This cannot be undone.", "Delete")) return;
            await api("/admin/api/users/" + u.id, "DELETE"); flash("Deleted " + u.username + "."); loaders.users();
          }), "danger", "Delete " + u.username))));
    table("u-list", ["User", "Role", "Signs in with", "2FA", "State", "Terminals", "Last sign-in", ""], rows, "No users match.");
  }
  loaders.users = async () => { users = (await api("/admin/api/users")).users; renderUsers(); };
  $("u-filter").addEventListener("input", renderUsers);
  $("u-add").addEventListener("click", () => formDialog("Add user",
    "For a local account, leave the password empty to generate one (shown once). Directory and SSO accounts have no password here.",
    [{ k: "username", label: "Username" }, { k: "display_name", label: "Display name" }, { k: "email", label: "Email", type: "email" },
      { k: "role", label: "Role", type: "select", options: ROLES }, { k: "auth_source", label: "Signs in with", type: "select", options: SOURCES },
      { k: "password", label: "Password (local accounts)", type: "password" },
      { k: "must_change", label: "Must change the password at first sign-in", type: "check" }],
    { role: "user", auth_source: "local", must_change: true },
    async (v) => {
      if (!v.password) delete v.password;
      const r = await api("/admin/api/users", "POST", v);
      loaders.users();
      if (r.password) showOnce("Password for " + r.user.username, "Give it to the user through a safe channel. It is shown only now; they choose their own at the first sign-in.", r.password);
      else flash("Created " + r.user.username + ".");
    }, "Create"));
  function editUser(u) {
    formDialog("Edit " + u.username, "", [
      { k: "display_name", label: "Display name" }, { k: "email", label: "Email", type: "email" },
      { k: "role", label: "Role", type: "select", options: ROLES }, { k: "auth_source", label: "Signs in with", type: "select", options: SOURCES },
      { k: "disabled", label: "Disabled (cannot sign in; terminals are closed)", type: "check" },
      { k: "must_change", label: "Must change the password at the next sign-in", type: "check" }], u,
    async (v) => { await api("/admin/api/users/" + u.id, "PUT", v); flash("Saved " + u.username + "."); loaders.users(); });
  }
  function resetPassword(u) {
    formDialog("New password for " + u.username, "Leave it empty to generate one (shown once). Their other sign-ins end.", [
      { k: "password", label: "New password", type: "password" },
      { k: "must_change", label: "Must change it at the next sign-in", type: "check" }], { must_change: true },
    async (v) => {
      if (!v.password) delete v.password;
      const r = await api("/admin/api/users/" + u.id + "/password", "POST", v);
      if (r.password) showOnce("New password for " + u.username, "Give it to the user through a safe channel. It is shown only now.", r.password);
      else flash("Password changed for " + u.username + ".");
    }, "Set password");
  }

  // ─── active sessions ───────────────────────────────────────────────────────
  const sessRow = (s, ended) => el("tr", {},
    td(el("b", { text: s.username || "?" }), s.display_name ? el("div", { class: "sub", text: s.display_name }) : null),
    td(pill(s.method), s.stage === "mfa" ? pill("2FA owed", "warn") : null),
    td(el("span", { class: "mono", text: s.ip || "" }), el("div", { class: "sub", text: (s.user_agent || "").slice(0, 90) })),
    td(fmt(s.created_at)), td(ago(s.last_seen)),
    ended ? td(s.ended_at ? fmt(s.ended_at) : pill("open", "ok"), s.end_reason ? el("div", { class: "sub", text: s.end_reason }) : null) : td(fmt(s.expires_at)));
  loaders.active = async () => {
    const [now, hist] = await Promise.all([api("/admin/api/active"), api("/admin/api/sessions?limit=200")]);
    table("a-now", ["User", "Method", "From", "Signed in", "Last seen", "Expires"], now.sessions.map((s) => sessRow(s, false)), "Nobody is signed in.");
    table("a-hist", ["User", "Method", "From", "Signed in", "Last seen", "Ended"], hist.sessions.map((s) => sessRow(s, true)), "No sign-ins yet.");
  };

  // ─── terminals ─────────────────────────────────────────────────────────────
  loaders.terminals = async () => {
    const r = await api("/admin/api/terminals");
    const rows = r.terminals.sort((a, b) => b.created - a.created).map((t) => el("tr", {},
      td(el("b", { text: t.label || t.command }), el("div", { class: "sub mono", text: t.id })),
      mode === "users" ? td(t.owner || "—") : null,
      td(t.ssh ? el("span", { class: "mono", text: t.ssh }) : pill("local shell", "warn")),
      td(t.alive ? pill("running", "ok") : pill("ended" + (t.exit_code != null ? " (" + t.exit_code + ")" : ""))),
      td(fmt(t.created)), td(String(t.viewers)), td(t.alive ? t.idle_for + " s" : "—"),
      el("td", { class: "actions" }, t.alive ? btn("Close", run(async () => {
        if (!await confirmBox("Close this terminal?", "Its process is ended" + (t.owner ? " (" + t.owner + "'s session)" : "") + ".", "Close")) return;
        await api("/admin/api/terminals/" + encodeURIComponent(t.id) + "/kill", "POST", {}); flash("Terminal closed."); loaders.terminals();
      }), "danger", "Close terminal " + (t.label || t.id)) : null)));
    const head = ["Terminal"].concat(mode === "users" ? ["Owner"] : [], ["Connection", "State", "Opened", "Viewers", "Idle", ""]);
    table("t-list", head, rows, "No terminals are open.");
  };
  $("t-refresh").addEventListener("click", run(() => loaders.terminals()));

  // ─── audit & activity ──────────────────────────────────────────────────────
  let stream = "audit";
  let lastId = null;
  function auditQuery() {
    const p = new URLSearchParams();
    const t = (id) => { const v = $(id).value; return v ? String(Math.floor(new Date(v).getTime() / 1000)) : ""; };
    const add = (k, v) => { if (v) p.set(k, v); };
    add("since", t("au-since")); add("until", t("au-until"));
    add("username", $("au-user").value.trim()); add("outcome", $("au-out").value);
    add("q", $("au-q").value.trim()); add("path", $("au-path").value.trim());
    if (stream === "audit") add("category", $("au-cat").value); else add("method", $("au-method").value);
    return p;
  }
  function setStream(s) {
    stream = s;
    for (const b of document.querySelectorAll("[data-stream]")) b.classList.toggle("active", b.dataset.stream === s);
    for (const d of document.querySelectorAll("[data-only]")) d.hidden = d.dataset.only !== s;
    const outs = s === "audit" ? [["", "any"], ["ok", "ok"], ["fail", "fail"], ["denied", "denied"], ["error", "error"]]
      : [["", "any"], ["ok", "ok (2xx/3xx)"], ["fail", "failed (4xx/5xx)"]];
    $("au-out").replaceChildren(...outs.map(([v, l]) => el("option", { value: v, text: l })));
  }
  const detailText = (d) => (d == null ? "" : typeof d === "string" ? d : JSON.stringify(d)).slice(0, 600);
  function auditRow(e) {
    if (stream === "audit") {
      return el("tr", {}, td(fmt(e.ts)), td(e.username || "—", e.token_id ? el("div", { class: "sub mono", text: "token " + e.token_id }) : null),
        td(pill(e.category)), td(el("b", { text: e.action }), e.target ? el("div", { class: "sub mono", text: e.target }) : null),
        td(pill(e.outcome, e.outcome === "ok" ? "ok" : e.outcome === "denied" ? "warn" : "err")),
        td(el("span", { class: "mono", text: e.ip || "" })), el("td", { class: "detail", text: detailText(e.detail) }));
    }
    return el("tr", {}, td(fmt(e.ts)), td(e.username || "—", e.token_id ? el("div", { class: "sub mono", text: "token " + e.token_id }) : null),
      td(el("span", { class: "mono", text: e.method + " " + e.path })),
      td(pill(String(e.status), e.status < 400 ? "ok" : e.status < 500 ? "warn" : "err")),
      td(Math.round(e.duration_ms) + " ms"), td(el("span", { class: "mono", text: e.ip || "" })));
  }
  async function loadAudit(more) {
    const p = auditQuery();
    p.set("limit", "200");
    if (more && lastId) p.set("before_id", String(lastId));
    const r = await api("/admin/api/" + stream + "?" + p.toString());
    const head = stream === "audit" ? ["Time", "Who", "Category", "Action", "Outcome", "IP", "Detail"]
      : ["Time", "Who", "Request", "Status", "Duration", "IP"];
    if (!more) table("au-list", head, r.events.map(auditRow), "No events match.");
    else for (const e of r.events) $("au-list").querySelector("tbody").append(auditRow(e));
    if (r.events.length) lastId = r.events[r.events.length - 1].id;
    $("au-more").hidden = r.events.length < 200;
    const q = auditQuery().toString();
    $("au-csv").href = "/admin/api/" + stream + ".csv" + (q ? "?" + q : "");
    $("au-json").href = "/admin/api/" + stream + ".json" + (q ? "?" + q : "");
  }
  loaders.audit = () => loadAudit(false);
  setStream("audit");
  for (const b of document.querySelectorAll("[data-stream]")) b.addEventListener("click", run(() => { setStream(b.dataset.stream); return loadAudit(false); }));
  $("au-form").addEventListener("submit", (ev) => { ev.preventDefault(); run(() => loadAudit(false))(); });
  $("au-more").addEventListener("click", run(() => loadAudit(true)));

  // ─── API tokens ────────────────────────────────────────────────────────────
  loaders.tokens = async () => {
    const r = await api("/admin/api/tokens");
    const rows = r.tokens.map((t) => el("tr", {},
      td(el("b", { text: t.name }), el("div", { class: "sub mono", text: t.id })), td(t.username || String(t.user_id)),
      td(...t.scopes.map((x) => pill(x, x === "admin" ? "violet" : x === "write" ? "accent" : ""))),
      td(fmt(t.created_at)), td(t.expires_at ? fmt(t.expires_at) : pill("never", "warn")),
      td(fmt(t.last_used_at), t.last_used_ip ? el("div", { class: "sub mono", text: t.last_used_ip }) : null),
      td(pill(t.state, t.state === "active" ? "ok" : t.state === "expired" ? "warn" : "err")),
      el("td", { class: "actions" }, t.state === "active" ? btn("Revoke", run(async () => {
        if (!await confirmBox("Revoke " + t.name + "?", "Anything using this token stops working immediately.", "Revoke")) return;
        await api("/admin/api/tokens/" + t.id, "DELETE"); flash("Revoked."); loaders.tokens();
      }), "danger", "Revoke " + t.name) : null)));
    table("k-list", ["Token", "Owner", "Scopes", "Created", "Expires", "Last used", "State", ""], rows, "No API tokens.");
  };

  $("k-add").addEventListener("click", run(async () => {
    const mine = await api("/auth/tokens");
    const exp = [["30", "30 days"], ["90", "90 days (default)"], ["180", "180 days"], ["365", "1 year"]];
    if (mine.can_never_expire) exp.push(["never", "Never"]);
    formDialog("Create an API token for yourself", "It is shown once. Use it as Authorization: Bearer <token> against /api/v1/.", [
      { k: "name", label: "Name (what will use it)" },
      { k: "scopes", label: "Scopes", type: "checks", options: [["read", "read"], ["write", "write"], ["admin", "admin"]] },
      { k: "expires_days", label: "Expires", type: "select", options: exp }],
    { scopes: ["read"], expires_days: "90" },
    async (v) => {
      const r = await api("/auth/tokens", "POST", v);
      loaders.tokens();
      showOnce("Your new token", "Copy it now. It is shown only this once; only a hash of it is kept.", r.token,
        `curl -fsS -H "Authorization: Bearer $TOKEN" ${location.origin}/api/v1/me`);
    }, "Create");
  }));

  // ─── log forwarding ────────────────────────────────────────────────────────
  let logInfo = null;
  function logSpec(type, d) {
    const common = [{ k: "name", label: "Name" }, { k: "enabled", label: "Enabled", type: "check" },
      { k: "streams", label: "Streams", type: "checks", options: logInfo.streams.map((s) => [s, s]) },
      { k: "min_level", label: "Minimum level (application stream)", type: "select", options: logInfo.levels.map((s) => [s, s]) }];
    const tls = [{ k: "verify_tls", label: "Verify the TLS certificate", type: "check" },
      { k: "ca_pem", label: "Private CA certificate (PEM, optional)", type: "textarea", wide: true }];
    if (type === "syslog") {
      return common.concat([{ k: "host", label: "Host" }, { k: "port", label: "Port", type: "number", min: 1, max: 65535 },
        { k: "transport", label: "Transport", type: "select", options: [["udp", "UDP"], ["tcp", "TCP"], ["tls", "TLS"]] },
        { k: "facility", label: "Facility", type: "select", options: (Array.isArray(logInfo.facilities) ? logInfo.facilities : Object.keys(logInfo.facilities)).map((f) => [f, f]) }], tls);
    }
    return common.concat([{ k: "url", label: "URL", placeholder: "https://splunk.example:8088/services/collector/raw", wide: true },
      { k: "auth_header", label: "Auth header", type: "secret", placeholder: "Authorization: Splunk <token>",
        hint: "One line, such as 'Authorization: Splunk <token>' or 'Authorization: ApiKey <key>'. Stored encrypted." },
      { k: "batch_size", label: "Batch size", type: "number", min: 1, max: 5000 },
      { k: "timeout", label: "Timeout (s)", type: "number", min: 1, max: 120 }], tls);
  }
  function editDest(type, d) {
    const vals = d ? Object.assign({}, d, { auth_header: d.auth_set ? "set" : "" })
      : { type, enabled: true, streams: ["audit", "activity", "app"], min_level: "info", verify_tls: true,
        port: 514, transport: type === "syslog" ? "tcp" : undefined, facility: "local0", batch_size: 200, timeout: 10 };
    formDialog((d ? "Edit " : "Add ") + (type === "syslog" ? "syslog" : "HTTP(S)") + " destination",
      type === "syslog" ? "RFC 5424 with octet counting over TCP/TLS; one line per event over UDP." :
        "NDJSON batches by POST: Splunk HEC (raw endpoint), Elastic, Graylog, Loki, Wazuh, Sentinel.",
      logSpec(type, d), vals, async (v) => {
        v.type = type;
        if (d) await api("/admin/api/logging/destinations/" + d.id, "PUT", v);
        else await api("/admin/api/logging/destinations", "POST", v);
        flash("Saved."); loaders.logging();
      });
  }
  loaders.logging = async () => {
    logInfo = await api("/admin/api/logging");
    $("lg-info").textContent = (logInfo.stdout_json ? "One ECS JSON object per line on standard output" : "Plain text on standard error (LOG_FORMAT is not json)")
      + (logInfo.file ? ", and in " + logInfo.file + " in the data folder" : "") + ". Datasets " + logInfo.dataset_prefix
      + ".app, .audit and .activity; environment " + logInfo.environment + ".";
    const rows = logInfo.destinations.map((d) => {
      const s = d.status || {};
      return el("tr", {},
        td(el("b", { text: d.name }), el("div", { class: "sub mono", text: d.type === "syslog" ? `${d.transport}://${d.host}:${d.port}` : d.url })),
        td(pill(d.type), d.enabled ? null : pill("disabled", "warn"), d.readonly ? pill("from environment", "accent") : null),
        td(...(d.streams || []).map((x) => pill(x))),
        td(el("div", { class: "counters" }, el("span", { text: "sent " + (s.sent || 0) }), el("span", { text: "failed " + (s.failed || 0) }),
          el("span", { text: "dropped " + (s.dropped || 0) }), el("span", { text: "backlog " + (s.backlog || 0) })),
        s.last_error ? el("div", { class: "sub", text: "last error " + ago(s.last_error_at) + ": " + s.last_error }) : null,
        s.last_sent_at ? el("div", { class: "sub", text: "last delivery " + ago(s.last_sent_at) }) : null),
        el("td", { class: "actions" },
          btn("Send test event", run(async () => {
            const r = await api("/admin/api/logging/destinations/" + d.id + "/test", "POST", {});
            flash(r.ok ? "Test event delivered to " + d.name + "." : "Test failed: " + r.error, r.ok ? "ok" : "err");
          }), "", "Send a test event to " + d.name), " ",
          d.readonly ? null : btn("Edit", () => editDest(d.type, d), "", "Edit " + d.name), " ",
          d.readonly ? null : btn("Delete", run(async () => {
            if (!await confirmBox("Remove " + d.name + "?", "Events stop being forwarded to it.", "Remove")) return;
            await api("/admin/api/logging/destinations/" + d.id, "DELETE"); flash("Removed."); loaders.logging();
          }), "danger", "Delete " + d.name)));
    });
    table("lg-list", ["Destination", "Type", "Streams", "Delivery", ""], rows, "No forwarding destinations.");
  };
  $("lg-add-syslog").addEventListener("click", run(async () => { if (!logInfo) await loaders.logging(); editDest("syslog", null); }));
  $("lg-add-http").addEventListener("click", run(async () => { if (!logInfo) await loaders.logging(); editDest("http", null); }));

  // ─── backup & restore ──────────────────────────────────────────────────────
  let bk = null;
  function destSpec(type) {
    const base = [{ k: "name", label: "Name" }, { k: "enabled", label: "Enabled", type: "check" },
      { k: "retention_days", label: "Keep for (days, 0 = keep all)", type: "number", min: 0, max: 3650 }];
    if (type === "sftp") {
      return base.concat([{ k: "host", label: "Host" }, { k: "port", label: "Port", type: "number", min: 1, max: 65535 },
        { k: "user", label: "User" }, { k: "directory", label: "Directory", placeholder: "backups/ares-terminal-console" },
        { k: "password", label: "Password", type: "secret" },
        { k: "private_key", label: "Private key (PEM / OpenSSH)", type: "secretarea", wide: true },
        { k: "key_passphrase", label: "Key passphrase", type: "secret" },
        { k: "host_key", label: "Pinned host key", placeholder: "ssh-ed25519 AAAA… (empty: pinned at the first connection)", wide: true,
          hint: "Pinned automatically on the first test or backup. Clear it only when the server's key really changed." }]);
    }
    if (type === "s3") {
      return base.concat([{ k: "endpoint", label: "Endpoint", placeholder: "https://s3.example.com (empty for AWS S3)" },
        { k: "region", label: "Region", placeholder: "us-east-1" }, { k: "bucket", label: "Bucket" },
        { k: "prefix", label: "Prefix (folder)", placeholder: "ares-terminal-console/" },
        { k: "access_key", label: "Access key" }, { k: "secret_key", label: "Secret key", type: "secret" },
        { k: "path_style", label: "Path-style addressing (MinIO, Ceph, most non-AWS)", type: "check" }]);
    }
    return base;
  }
  function editBackupDest(type, d) {
    formDialog((d ? "Edit " : "Add ") + (type === "local" ? "local" : type.toUpperCase()) + " destination",
      type === "local" ? "Backups in DATA_DIR/backups on this server." : "Credentials are stored encrypted and never shown again. Remote backups are always encrypted with the passphrase.",
      destSpec(type), d || { enabled: true, retention_days: 30, port: 22 },
      async (v) => {
        if (!d) v.type = type;
        if (d) await api("/admin/api/backup/destinations/" + d.id, "PUT", v);
        else await api("/admin/api/backup/destinations", "POST", v);
        flash("Saved."); loaders.backup();
      });
  }
  async function listBackups(d) {
    const r = await api("/admin/api/backup/destinations/" + d.id + "/backups");
    $("bk-files-sec").hidden = false;
    $("bk-files-title").textContent = "Backups in " + d.name;
    const rows = r.backups.map((b) => el("tr", {},
      td(el("span", { class: "mono", text: b.name })), td(size(b.size)), td(fmt(b.created_at || b.modified)),
      td(b.encrypted ? pill("encrypted", "ok") : pill("not encrypted", "warn")),
      el("td", { class: "actions" },
        el("a", { href: "/admin/api/backup/destinations/" + encodeURIComponent(d.id) + "/backups/" + encodeURIComponent(b.name), download: b.name },
          el("button", { type: "button", tabindex: "-1", text: "Download" })), " ",
        btn("Restore", () => restoreDialog({ destination: d.id, name: b.name }, b.name, b.encrypted), "danger", "Restore " + b.name))));
    table("bk-files", ["Backup", "Size", "Created", "Encryption", ""], rows, "No backups here yet.");
    $("bk-files-sec").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  function restoreDialog(target, label, encrypted) {
    formDialog("Restore " + label + "?",
      "The archive is checked, a safety backup of the current state is taken, then the server restarts with the restored data. Everyone is signed out and every terminal closes.",
      encrypted ? [{ k: "passphrase", label: "The backup's passphrase", type: "password" }] : [], {},
      async (v) => { await doRestore(Object.assign({}, target, v)); }, "Restore");
  }
  async function doRestore(body) {
    await api("/admin/api/backup/restore", "POST", body);
    $("restarting").hidden = false;
    const started = Date.now();
    let seenDown = false;
    const poll = async () => {
      try {
        const r = await fetch("/healthz", { cache: "no-store" });
        if (r.ok && (seenDown || Date.now() - started > 8000)) { location.reload(); return; }
        if (!r.ok) seenDown = true;
      } catch (e) { seenDown = true; }
      if (Date.now() - started > 180000) {
        $("restarting-text").textContent = "The server has not come back after three minutes. Check its logs (pm2 or Kubernetes), then reload this page.";
        return;
      }
      setTimeout(poll, 1500);
    };
    setTimeout(poll, 1500);
  }
  loaders.backup = async () => {
    bk = await api("/admin/api/backup");
    const card = (n, l, kind) => el("div", { class: "card " + (kind || "") }, el("div", { class: "n small", text: n }), el("div", { class: "l", text: l }));
    const last = bk.last;
    $("bk-cards").replaceChildren(
      card(bk.last_ok_at ? ago(bk.last_ok_at) : "never", "last good backup", bk.last_ok_at ? "ok" : "warn"),
      card(last ? (last.ok ? "ok" : "failed") : "—", "last run" + (last ? " (" + ago(last.at) + ")" : ""), last ? (last.ok ? "ok" : "err") : ""),
      card(bk.schedule_text, "schedule"),
      card(bk.next_run_at ? fmt(bk.next_run_at) : "—", "next run"),
      card(bk.passphrase_set ? "set" : "not set", "passphrase", bk.passphrase_set ? "ok" : "warn"),
      card(bk.running ? "running…" : "idle", "now", bk.running ? "warn" : ""));
    const pend = $("bk-pending");
    pend.textContent = bk.restore_pending ? "A restore is staged and is applied when the server restarts." : "";
    pend.className = "msg info" + (bk.restore_pending ? " show" : "");
    $("bk-tz").textContent = bk.timezone;
    $("bk-mode").value = bk.schedule.mode;
    $("bk-hours").value = bk.schedule.hours;
    $("bk-time").value = bk.schedule.time;
    $("bk-weekday").value = String(bk.schedule.weekday);
    schedVis();
    const rows = bk.destinations.map((d) => el("tr", {},
      td(el("b", { text: d.name }), el("div", { class: "sub mono", text: d.type === "sftp" ? `${d.user}@${d.host}:${d.port}/${d.directory}`
        : d.type === "s3" ? `${d.endpoint || "AWS S3"} · ${d.bucket}/${d.prefix || ""}` : "DATA_DIR/backups" }),
      d.host_key_fingerprint ? el("div", { class: "sub mono", text: "host key " + d.host_key_fingerprint }) : null),
      td(pill(d.type), d.enabled ? null : pill("disabled", "warn")),
      td(d.retention_days ? d.retention_days + " days" : "keep all"),
      td(d.last ? pill(d.last.ok ? "ok" : "failed", d.last.ok ? "ok" : "err") : "—",
        d.last ? el("div", { class: "sub", text: ago(d.last.at) + (d.last.error ? ": " + d.last.error : "") }) : null),
      el("td", { class: "actions" },
        btn("Backups", run(() => listBackups(d)), "", "Backups in " + d.name), " ",
        btn("Test", run(async () => {
          const r = await api("/admin/api/backup/destinations/" + d.id + "/test", "POST", {});
          flash(r.ok ? r.message : "Test failed: " + r.error, r.ok ? "ok" : "err"); loaders.backup();
        }), "", "Test " + d.name), " ",
        btn("Edit", () => editBackupDest(d.type, d), "", "Edit " + d.name), " ",
        d.type === "local" ? null : btn("Delete", run(async () => {
          if (!await confirmBox("Remove " + d.name + "?", "It is removed from the settings. Its backups stay where they are.", "Remove")) return;
          await api("/admin/api/backup/destinations/" + d.id, "DELETE"); flash("Removed."); loaders.backup();
        }), "danger", "Delete " + d.name))));
    table("bk-dests", ["Destination", "Type", "Retention", "Last result", ""], rows);
    table("bk-hist", ["When", "Backup", "Reason", "By", "Size", "Result"], (bk.history || []).map((h) => el("tr", {},
      td(fmt(h.at)), td(el("span", { class: "mono", text: h.name || "—" })), td(h.reason), td(h.by || "scheduler"),
      td(size(h.size)), td(pill(h.ok ? "ok" : "failed", h.ok ? "ok" : "err"),
        h.error ? el("div", { class: "sub", text: h.error }) : null,
        ...(h.results || []).filter((x) => !x.ok).map((x) => el("div", { class: "sub", text: x.name + ": " + x.error }))))), "No backups yet.");
  };
  function schedVis() {
    const m = $("bk-mode").value;
    for (const d of document.querySelectorAll("[data-sched]")) d.hidden = !d.dataset.sched.split(" ").includes(m);
  }
  $("bk-mode").addEventListener("change", schedVis);
  $("bk-sched-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    run(async () => {
      await api("/admin/api/backup/schedule", "PUT", { mode: $("bk-mode").value, hours: Number($("bk-hours").value || 6),
        time: $("bk-time").value || "02:30", weekday: Number($("bk-weekday").value) });
      flash("Schedule saved."); loaders.backup();
    })();
  });
  $("bk-pass-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    run(async () => {
      if ($("bk-pass").value !== $("bk-pass2").value) throw new Error("The passphrases do not match.");
      if (!$("bk-pass").value) throw new Error("Enter a passphrase (or use Remove).");
      await api("/admin/api/backup/passphrase", "PUT", { passphrase: $("bk-pass").value });
      $("bk-pass").value = $("bk-pass2").value = "";
      flash("Passphrase saved. Keep a copy offline: without it, encrypted backups cannot be restored."); loaders.backup();
    })();
  });
  $("bk-pass-remove").addEventListener("click", run(async () => {
    if (!await confirmBox("Remove the backup passphrase?", "New local backups are then not encrypted, and SFTP and S3 backups fail until a passphrase is set again.", "Remove")) return;
    await api("/admin/api/backup/passphrase", "PUT", { passphrase: "" }); flash("Passphrase removed."); loaders.backup();
  }));
  $("bk-run").addEventListener("click", run(async () => {
    $("bk-run").disabled = true;
    flash("Backing up…", "info");
    try {
      const r = await api("/admin/api/backup/run", "POST", {});
      const b = r.backup;
      flash(b.ok ? "Backup " + b.name + " written (" + size(b.size) + ")." : "Backup failed: " + (b.error || b.results.filter((x) => !x.ok).map((x) => x.name + ": " + x.error).join("; ")), b.ok ? "ok" : "err");
    } finally { $("bk-run").disabled = false; loaders.backup(); }
  }));
  $("bk-prune").addEventListener("click", run(async () => {
    const r = await api("/admin/api/backup/prune", "POST", {});
    const n = r.results.reduce((a, x) => a + (x.pruned || []).length, 0);
    const errs = r.results.filter((x) => x.error);
    flash(errs.length ? "Retention errors: " + errs.map((x) => x.name + ": " + x.error).join("; ") : "Removed " + n + " old backup(s).", errs.length ? "err" : "ok");
    loaders.backup();
  }));
  $("bk-add-sftp").addEventListener("click", () => editBackupDest("sftp", null));
  $("bk-add-s3").addEventListener("click", () => editBackupDest("s3", null));
  $("rs-go").addEventListener("click", run(async () => {
    const f = $("rs-file").files[0];
    if (!f) throw new Error("Choose an archive first.");
    if (!await confirmBox("Restore " + f.name + "?", "The current data is replaced (a safety backup is taken first). The server restarts; everyone is signed out and every terminal closes.", "Upload and restore")) return;
    $("rs-go").disabled = true;
    flash("Uploading " + f.name + "…", "info");
    try {
      const up = await api("/admin/api/backup/upload", "POST", undefined, { raw: f, headers: { "X-Filename": f.name.replace(/[^A-Za-z0-9._-]/g, "_") } });
      await doRestore({ upload: up.upload, passphrase: $("rs-pass").value });
      $("rs-pass").value = "";
    } finally { $("rs-go").disabled = false; }
  }));

  // ─── single sign-on ────────────────────────────────────────────────────────
  let forms = {};
  const roleOpts = [["user", "user"], ["admin", "administrator"]];
  const provision = [{ k: "auto_provision", label: "Create accounts at the first sign-in", type: "check" },
    { k: "default_role", label: "Role of new accounts", type: "select", options: roleOpts },
    { k: "admin_groups", label: "Administrator groups (one per line)", type: "list" },
    { k: "allowed_groups", label: "Allowed groups (empty: everyone the provider lets through)", type: "list" },
    { k: "sync_role", label: "Update the role from the groups at every sign-in", type: "check" }];
  loaders.sso = async () => {
    const s = await api("/admin/api/settings");
    $("oidc-redirect").value = s.oidc_redirect_uri;
    $("sp-entity").value = s.sp.entity_id; $("sp-acs").value = s.sp.acs_url;
    $("sp-meta").value = s.sp.metadata_url; $("sp-signon").value = s.sp.sign_on_url;
    forms.oidc = buildForm($("oidc-form"), [{ k: "enabled", label: "Enabled", type: "check" },
      { k: "provider", label: "Provider", type: "select", options: [["entra", "Microsoft Entra ID"], ["generic", "Other OpenID Connect provider"]] },
      { k: "tenant_id", label: "Directory (tenant) ID or domain", hint: "Entra only. 'organizations' allows any work account." },
      { k: "discovery_url", label: "Discovery URL", hint: "Other providers: https://idp/.well-known/openid-configuration" },
      { k: "client_id", label: "Application (client) ID" }, { k: "client_secret", label: "Client secret", type: "secret" },
      { k: "scopes", label: "Scopes" },
      { k: "username_claim", label: "Username from", type: "select", options: [["preferred_username", "preferred_username (UPN)"], ["email", "email"], ["upn", "upn"], ["sub", "sub"]] },
      { k: "groups_claim", label: "Groups claim" }, { k: "button_label", label: "Button label" }].concat(provision), s.oidc);
    forms.saml = buildForm($("saml-form"), [{ k: "enabled", label: "Enabled", type: "check" },
      { k: "idp_entity_id", label: "IdP entity ID", wide: true }, { k: "idp_sso_url", label: "IdP sign-on URL", wide: true },
      { k: "idp_slo_url", label: "IdP sign-out URL (optional)", wide: true },
      { k: "idp_certs", label: "IdP signing certificate(s), PEM", type: "textarea", wide: true },
      { k: "metadata_url", label: "Metadata URL (for reference)", wide: true },
      { k: "sp_entity_id", label: "SP entity ID override (optional)" },
      { k: "username_claim", label: "Username from", type: "select", options: [["upn", "UPN / name claim"], ["email", "email"], ["nameid", "NameID"]] },
      { k: "allow_idp_initiated", label: "Allow IdP-initiated sign-in (from the My Apps portal)", type: "check" },
      { k: "button_label", label: "Button label" }].concat(provision),
    Object.assign({}, s.saml, { idp_certs: (s.saml.idp_certs || []).join("\n") }));
    forms.ldap = buildForm($("ldap-form"), [{ k: "enabled", label: "Enabled", type: "check" },
      { k: "server_url", label: "Server URL(s)", placeholder: "ldaps://dc1.example.com:636 ldaps://dc2.example.com:636", wide: true },
      { k: "start_tls", label: "StartTLS (on ldap://)", type: "check" }, { k: "verify_tls", label: "Verify the server certificate", type: "check" },
      { k: "ca_pem", label: "Private CA certificate (PEM, optional)", type: "textarea", wide: true },
      { k: "bind_dn", label: "Service account DN", placeholder: "CN=svc-ares,OU=Service,DC=example,DC=com" },
      { k: "bind_password", label: "Service account password", type: "secret" },
      { k: "base_dn", label: "Base DN", placeholder: "DC=example,DC=com" },
      { k: "user_filter", label: "User filter (optional)", placeholder: "(&(objectClass=user)(sAMAccountName={username}))" },
      { k: "username_attr", label: "Username attribute" }, { k: "email_attr", label: "Email attribute" },
      { k: "name_attr", label: "Display name attribute" }, { k: "group_attr", label: "Group attribute" },
      { k: "timeout", label: "Timeout (s)", type: "number", min: 2, max: 60 }].concat(provision), s.ldap);
  };
  $("oidc-save").addEventListener("click", run(async () => { await api("/admin/api/settings/oidc", "PUT", forms.oidc.read()); flash("Saved."); loaders.sso(); }));
  $("oidc-test").addEventListener("click", run(async () => {
    const r = await api("/admin/api/settings/oidc/test", "POST", {});
    flash(r.ok ? r.message : "Test failed: " + r.error, r.ok ? "ok" : "err");
  }));
  $("saml-save").addEventListener("click", run(async () => { await api("/admin/api/settings/saml", "PUT", forms.saml.read()); flash("Saved."); loaders.sso(); }));
  async function applyMetadata(body) {
    const m = await api("/admin/api/settings/saml/metadata", "POST", body);
    const vals = { idp_entity_id: m.idp_entity_id, idp_sso_url: m.idp_sso_url, idp_slo_url: m.idp_slo_url || "",
      idp_certs: (m.idp_certs || []).join("\n") };
    if (m.metadata_url) vals.metadata_url = m.metadata_url;
    const inputs = [...$("saml-form").querySelectorAll("input,textarea")];
    for (const [k, v] of Object.entries(vals)) {
      const inp = inputs.find((i) => i.id.startsWith("ff-" + k + "-"));
      if (inp) inp.value = v || "";
    }
    flash("Loaded the IdP values. Check them and press Save.", "info");
  }
  $("saml-md-load").addEventListener("click", run(() => applyMetadata({ url: $("saml-md-url").value.trim() })));
  $("saml-md-parse").addEventListener("click", run(() => applyMetadata({ xml: $("saml-md-xml").value })));
  $("ldap-save").addEventListener("click", run(async () => { await api("/admin/api/settings/ldap", "PUT", forms.ldap.read()); flash("Saved."); loaders.sso(); }));
  $("ldap-test").addEventListener("click", run(async () => {
    const r = await api("/admin/api/settings/ldap/test", "POST", { username: $("ldap-t-user").value.trim(), password: $("ldap-t-pass").value });
    $("ldap-t-pass").value = "";
    flash(r.ok ? r.message : "Test failed: " + r.error, r.ok ? "ok" : "err");
  }));

  // ─── policies ──────────────────────────────────────────────────────────────
  loaders.policy = async () => {
    const s = await api("/admin/api/settings");
    const p = Object.assign({}, s.policy, { public_url: s.public_url });
    forms.policy = buildForm($("pol-form"), [
      { k: "mfa_required", label: "Two-factor authentication required for", type: "select",
        options: [["all", "everyone (local and LDAP accounts)"], ["admins", "administrators"], ["optional", "nobody (optional)"]] },
      { k: "mfa_for_sso", label: "Also ask Entra ID / SAML users for a code here (usually the identity provider does MFA)", type: "check" },
      { k: "local_shell", label: "Who may open a shell on this server", type: "select",
        options: [["admins", "administrators (recommended)"], ["all", "everyone"], ["none", "nobody: ssh connections only"]] },
      { k: "local_login", label: "Password sign-in for local accounts", type: "select", options: [["enabled", "everyone"], ["admins_only", "administrators only (others use SSO)"]] },
      { k: "session_idle_minutes", label: "Sign out after idle (minutes)", type: "number", min: 5, max: 1440 },
      { k: "session_max_hours", label: "Longest sign-in (hours)", type: "number", min: 1, max: 720 },
      { k: "lockout_threshold", label: "Lock out after failed sign-ins", type: "number", min: 3, max: 100 },
      { k: "lockout_minutes", label: "Lockout (minutes)", type: "number", min: 1, max: 1440 },
      { k: "audit_retention_days", label: "Keep audit events (days)", type: "number", min: 7, max: 3650 },
      { k: "activity_retention_days", label: "Keep activity events (days)", type: "number", min: 7, max: 3650 },
      { k: "public_url", label: "Public URL", placeholder: "https://ares-terminal-console.example.com",
        hint: s.public_url_from_env ? "Set by ARES_PUBLIC_URL in the deployment." : "Used for SSO redirect and reply URLs. Empty: taken from the request.",
        readonly: s.public_url_from_env }], p);
  };
  $("pol-save").addEventListener("click", run(async () => { await api("/admin/api/settings/policy", "PUT", forms.policy.read()); flash("Policies saved."); loaders.policy(); }));

  // ─── start ─────────────────────────────────────────────────────────────────
  $("signout").addEventListener("click", async () => {
    try { await api("/auth/logout", "POST", {}); } catch (e) { /* ignore */ }
    location.replace("/login");
  });
  (async () => {
    try { me = await api("/auth/me"); } catch (e) { flash(e.message, "err"); return; }
    mode = me.mode;
    $("me").textContent = mode === "local" ? "this computer" : (me.user.display_name || me.user.username);
    if (mode === "local") {
      for (const b of document.querySelectorAll("[data-users-only]")) b.hidden = true;
      $("signout").hidden = true;
      $("account-link").hidden = true;
    }
    showTab(location.hash.slice(1) || "overview");
  })();
})();
