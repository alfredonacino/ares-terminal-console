"use strict";
// Sign-in: password (local or LDAP), SSO buttons, 2FA code, forced password change, 2FA enrolment.
(function () {
  const $ = (id) => document.getElementById(id);
  const qs = new URLSearchParams(location.search);
  const next = (() => {
    const n = qs.get("next") || "/";
    return n.startsWith("/") && !n.startsWith("//") && !n.includes("\\") && !n.startsWith("/login") ? n : "/";
  })();
  let codes = [];

  function show(el, text, kind) {
    el.textContent = text || "";
    el.className = "msg " + (kind || "err") + (text ? " show" : "");
  }
  function step(id) {
    for (const s of ["signin", "mfa", "change", "enroll", "recovery"]) $(s).hidden = s !== id;
    const f = $(id).querySelector("input:not([readonly])");
    if (f) f.focus();
  }
  async function post(url, body) {
    const r = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await r.json(); } catch (e) { /* empty */ }
    if (!r.ok) {
      const err = new Error(data.detail || data.message || r.statusText);
      err.status = r.status;
      throw err;
    }
    return data;
  }

  // What is still owed after a step: {stage, must_change, needs_enroll}.
  async function advance(r) {
    if (r.stage === "mfa") return step("mfa");
    if (r.must_change) return step("change");
    if (r.needs_enroll) return startEnroll();
    location.replace(next);
  }

  async function startEnroll() {
    step("enroll");
    show($("emsg"), "");
    try {
      const s = await post("/auth/2fa/setup");
      $("secret").value = s.secret;
      const box = $("qr");
      box.replaceChildren();
      if (s.qr_svg) {
        const doc = new DOMParser().parseFromString(s.qr_svg, "image/svg+xml");
        const svg = doc.documentElement;
        if (svg && svg.nodeName.toLowerCase() === "svg") {
          svg.setAttribute("role", "img");
          svg.setAttribute("aria-label", "QR code for the authenticator app");
          box.append(document.importNode(svg, true));
          box.hidden = false;
        }
      } else box.hidden = true;
      $("enroll-code").focus();
    } catch (e) { show($("emsg"), e.message); }
  }

  async function init() {
    if (qs.get("error")) show($("msg"), qs.get("error"));
    let cfg = {};
    try {
      cfg = await (await fetch("/auth/config", { credentials: "same-origin" })).json();
      $("ver").textContent = "v" + cfg.version;
      if (cfg.mode === "local") { location.replace("/"); return; }
      const sso = cfg.sso || {};
      if (sso.oidc && sso.oidc.enabled) { $("oidc-btn").hidden = false; $("oidc-label").textContent = sso.oidc.label; }
      if (sso.saml && sso.saml.enabled) { $("saml-btn").hidden = false; $("saml-label").textContent = sso.saml.label; }
      $("sso-block").hidden = !((sso.oidc && sso.oidc.enabled) || (sso.saml && sso.saml.enabled));
      $("ldap-hint").hidden = !(sso.ldap && sso.ldap.enabled);
      $("admins-only").hidden = cfg.local_login !== "admins_only";
      $("fresh-hint").hidden = !cfg.fresh_install;
    } catch (e) { /* the form still works */ }
    // Already part-way signed in (an SSO landing, or a reload): resume at the owed step.
    try {
      const r = await fetch("/auth/me", { credentials: "same-origin" });
      if (r.ok) {
        const me = await r.json();
        const n = me.needs || {};
        if (n.mfa_verify) return step("mfa");
        if (n.password_change) return step("change");
        if (n.mfa_enroll) return startEnroll();
        if (!qs.get("error")) { location.replace(next); return; }
      }
    } catch (e) { /* not signed in */ }
    step("signin");
  }

  $("oidc-btn").addEventListener("click", () => { location.href = "/auth/oidc/login?next=" + encodeURIComponent(next); });
  $("saml-btn").addEventListener("click", () => { location.href = "/saml/login?next=" + encodeURIComponent(next); });

  $("login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    show($("msg"), "");
    $("login-btn").disabled = true;
    try {
      const r = await post("/auth/login", { username: $("username").value.trim(), password: $("password").value });
      if (r.must_change) $("current").value = $("password").value;
      $("password").value = "";
      await advance(r);
    } catch (e) {
      show($("msg"), e.message);
      $("password").select();
    } finally { $("login-btn").disabled = false; }
  });

  $("mfa-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    show($("mmsg"), "");
    try {
      const r = await post("/auth/2fa/verify", { code: $("mfa-code").value.trim() });
      $("mfa-code").value = "";
      await advance(r);
    } catch (e) {
      if (e.status === 401) { step("signin"); show($("msg"), e.message); return; }
      show($("mmsg"), e.message);
      $("mfa-code").select();
    }
  });

  $("change-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    show($("cmsg"), "");
    if ($("new1").value !== $("new2").value) { show($("cmsg"), "The new passwords do not match."); return; }
    try {
      const r = await post("/auth/password", { current: $("current").value, new: $("new1").value });
      for (const id of ["current", "new1", "new2"]) $(id).value = "";
      await advance(r);
    } catch (e) { show($("cmsg"), e.message); }
  });

  $("copy-secret").addEventListener("click", () => {
    navigator.clipboard.writeText($("secret").value).then(() => { $("copy-secret").textContent = "Copied"; }, () => $("secret").select());
  });

  $("enroll-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    show($("emsg"), "");
    try {
      const r = await post("/auth/2fa/enable", { code: $("enroll-code").value.trim() });
      $("secret").value = "";
      codes = r.recovery_codes || [];
      $("codes").replaceChildren(...codes.map((c) => { const s = document.createElement("span"); s.textContent = c; return s; }));
      step("recovery");
      $("codes-done").focus();
    } catch (e) { show($("emsg"), e.message); $("enroll-code").select(); }
  });

  $("copy-codes").addEventListener("click", () => {
    navigator.clipboard.writeText(codes.join("\n")).then(() => { $("copy-codes").textContent = "Copied"; });
  });
  $("dl-codes").addEventListener("click", () => {
    const blob = new Blob(["ARES Terminal Console recovery codes (" + location.host + ")\n\n" + codes.join("\n") + "\n"],
      { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "ares-terminal-console-recovery-codes.txt";
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $("codes-done").addEventListener("click", () => { codes = []; location.replace(next); });

  for (const b of document.querySelectorAll(".signout")) {
    b.addEventListener("click", async () => {
      try { await post("/auth/logout"); } catch (e) { /* ignore */ }
      location.replace("/login");
    });
  }

  init();
})();
