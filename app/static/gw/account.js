"use strict";
// Your account: password, two-factor authentication, API tokens.
(function () {
  const { $, el, fmt, pill, td, flash, api, confirmBox, showOnce, table, svgFrom } = window.GW;
  let me = null;
  let tokInfo = null;
  let codes = [];

  const SOURCES = { local: "a password here", ldap: "LDAP / Active Directory", oidc: "Microsoft Entra ID / OpenID Connect", saml: "SAML single sign-on" };

  async function loadMe() {
    me = await api("/auth/me");
    const u = me.user;
    $("me").textContent = u.display_name || u.username;
    $("admin-link").hidden = u.role !== "admin";
    $("t-admin-row").hidden = u.role !== "admin";
    $("p-user").textContent = u.username;
    $("p-role").replaceChildren(pill(u.role, u.role === "admin" ? "violet" : ""));
    $("p-source").textContent = SOURCES[u.auth_source] || u.auth_source;
    $("p-last").textContent = fmt(u.last_login_at) + (u.last_login_ip ? " from " + u.last_login_ip : "");
    $("sec-password").hidden = u.auth_source !== "local";
    $("mfa-state").textContent = u.mfa_enabled
      ? "On. " + u.recovery_codes_left + " recovery code" + (u.recovery_codes_left === 1 ? "" : "s") + " left."
      : (u.mfa_required ? "Required by your administrator, and not set up yet." : "Off. Turn it on to protect this account with a code from your phone.");
    $("mfa-on").hidden = !u.mfa_enabled;
    $("mfa-off").hidden = u.mfa_enabled;
    const pol = (me.policy || {}).mfa_required;
    const requiredForMe = u.auth_source === "local" || u.auth_source === "ldap"
      ? (pol === "all" || (pol === "admins" && u.role === "admin")) : false;
    $("mfa-required-hint").hidden = !requiredForMe;
    $("mfa-disable").hidden = requiredForMe;
  }

  // ── password ──
  $("pw-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if ($("pw-new").value !== $("pw-new2").value) return flash("The new passwords do not match.", "err");
    try {
      await api("/auth/password", "POST", { current: $("pw-cur").value, new: $("pw-new").value });
      for (const id of ["pw-cur", "pw-new", "pw-new2"]) $(id).value = "";
      flash("Password changed. Your other sessions were signed out.");
    } catch (e) { flash(e.message, "err"); }
  });

  // ── 2FA ──
  function showCodes(list) {
    codes = list || [];
    $("codes").replaceChildren(...codes.map((c) => el("span", { text: c })));
    $("d-codes").showModal();
  }
  $("codes-copy").addEventListener("click", () => navigator.clipboard.writeText(codes.join("\n")).then(() => { $("codes-copy").textContent = "Copied"; }));
  $("codes-dl").addEventListener("click", () => {
    const a = el("a", { download: "ares-terminal-console-recovery-codes.txt",
      href: URL.createObjectURL(new Blob(["ARES Terminal Console recovery codes (" + location.host + ")\n\n" + codes.join("\n") + "\n"], { type: "text/plain" })) });
    document.body.append(a); a.click(); a.remove();
  });
  $("codes-ok").addEventListener("click", () => { codes = []; $("codes").replaceChildren(); $("d-codes").close(); });

  $("mfa-start").addEventListener("click", async () => {
    try {
      const s = await api("/auth/2fa/setup", "POST", {});
      $("mfa-secret").value = s.secret;
      const svg = s.qr_svg ? svgFrom(s.qr_svg) : null;
      $("mfa-qr").replaceChildren(...(svg ? [svg] : []));
      $("mfa-qr").hidden = !svg;
      $("mfa-setup").hidden = false;
      $("mfa-start").hidden = true;
      $("mfa-enable-code").focus();
    } catch (e) { flash(e.message, "err"); }
  });
  $("mfa-enable-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      const r = await api("/auth/2fa/enable", "POST", { code: $("mfa-enable-code").value.trim() });
      $("mfa-enable-code").value = "";
      $("mfa-secret").value = "";
      $("mfa-setup").hidden = true;
      $("mfa-start").hidden = false;
      showCodes(r.recovery_codes);
      flash("Two-factor authentication is on.");
      loadMe();
    } catch (e) { flash(e.message, "err"); }
  });
  $("mfa-code-form").addEventListener("submit", (ev) => ev.preventDefault());
  $("mfa-recovery").addEventListener("click", async () => {
    try {
      const r = await api("/auth/2fa/recovery", "POST", { code: $("mfa-code").value.trim() });
      $("mfa-code").value = "";
      showCodes(r.recovery_codes);
      loadMe();
    } catch (e) { flash(e.message, "err"); }
  });
  $("mfa-disable").addEventListener("click", async () => {
    if (!await confirmBox("Turn off two-factor authentication?", "Anyone with your password could then sign in as you.", "Turn off")) return;
    try {
      await api("/auth/2fa/disable", "POST", { code: $("mfa-code").value.trim() });
      $("mfa-code").value = "";
      flash("Two-factor authentication is off.");
      loadMe();
    } catch (e) { flash(e.message, "err"); }
  });

  // ── tokens ──
  const stateKind = (s) => (s === "active" ? "ok" : s === "expired" ? "warn" : "err");
  async function loadTokens() {
    tokInfo = await api("/auth/tokens");
    const rows = tokInfo.tokens.map((t) => el("tr", {},
      td(el("b", { text: t.name }), el("div", { class: "sub mono", text: tokInfo.prefix + "_" + t.id + "_…" })),
      td(...t.scopes.map((x) => pill(x, x === "admin" ? "violet" : x === "write" ? "accent" : ""))),
      td(fmt(t.created_at)),
      td(t.expires_at ? fmt(t.expires_at) : pill("never", "warn")),
      td(fmt(t.last_used_at), t.last_used_ip ? el("div", { class: "sub mono", text: t.last_used_ip }) : null),
      td(pill(t.state, stateKind(t.state))),
      el("td", { class: "actions" }, ...(t.state === "active" ? [
        el("button", { type: "button", text: "Rotate", "aria-label": "Rotate " + t.name, onclick: async () => {
          if (!await confirmBox("Rotate " + t.name + "?", "A new token replaces it, with the same name, scopes and expiry period. The old one stops working now.", "Rotate")) return;
          try { const r = await api("/auth/tokens/" + t.id + "/rotate", "POST", {}); newToken(r.token); loadTokens(); }
          catch (e) { flash(e.message, "err"); }
        } }), " ",
        el("button", { type: "button", class: "danger", text: "Revoke", "aria-label": "Revoke " + t.name, onclick: async () => {
          if (!await confirmBox("Revoke " + t.name + "?", "Anything using this token stops working immediately. This cannot be undone.", "Revoke")) return;
          try { await api("/auth/tokens/" + t.id, "DELETE"); flash("Revoked " + t.name + "."); loadTokens(); }
          catch (e) { flash(e.message, "err"); }
        } })] : []))));
    table("t-list", ["Token", "Scopes", "Created", "Expires", "Last used", "State", ""], rows, "You have no API tokens.");
  }
  function newToken(token) {
    showOnce("Your new token", "Copy it now. It is shown only this once; only a hash of it is kept.", token,
      `curl -fsS -H "Authorization: Bearer $TOKEN" ${location.origin}/api/v1/me`);
  }
  $("t-create").addEventListener("click", async () => {
    const scopes = ["read", "write", "admin"].filter((s) => $("t-" + s).checked && !$("t-" + s).closest("[hidden]"));
    try {
      const r = await api("/auth/tokens", "POST", { name: $("t-name").value.trim(), scopes, expires_days: $("t-exp").value });
      $("t-name").value = "";
      newToken(r.token);
      loadTokens();
    } catch (e) { flash(e.message, "err"); }
  });

  $("signout").addEventListener("click", async () => {
    try { await api("/auth/logout", "POST", {}); } catch (e) { /* ignore */ }
    location.replace("/login");
  });

  (async () => {
    try { await loadMe(); } catch (e) { flash(e.message, "err"); return; }
    if (me.mode === "local") $("signout").hidden = true;
    try {
      await loadTokens();
      const opts = [[30, "30 days"], [90, "90 days (default)"], [180, "180 days"], [365, "1 year"]];
      if (tokInfo.can_never_expire) opts.push(["never", "Never (administrators only)"]);
      $("t-exp").replaceChildren(...opts.map(([v, l]) => el("option", { value: String(v), text: l })));
      $("t-exp").value = String(tokInfo.default_days);
    } catch (e) { flash(e.message, "err"); }
  })();
})();
