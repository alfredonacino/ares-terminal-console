/* Who is using the console, for the web edition's sign-in. Loaded before app.js.
 *
 * Web edition (mode "users"): shows the signed-in person (a link to their account), an Admin
 * link for administrators, and Sign out; any 401 from the API sends the browser to /login.
 * Desktop and ./run.sh (mode "local"): no sign-in; only the Admin link (backup, audit, logs).
 * Without the web layer (/auth/me answers 404) nothing changes.
 */
(function () {
  "use strict";
  let mode = "";
  let leaving = false;

  function toLogin() {
    if (leaving || mode !== "users") return;
    leaving = true;
    const next = location.pathname + location.search;
    location.href = "/login?next=" + encodeURIComponent(next);
  }
  window.aresSignedOut = toLogin;

  const nativeFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const res = await nativeFetch(input, init);
    if (res.status === 401 && mode === "users") {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.startsWith("/api/") || url.startsWith(location.origin + "/api/")) toLogin();
    }
    return res;
  };

  let lastCheck = 0;
  window.aresAuthCheck = function () {
    if (mode !== "users" || Date.now() - lastCheck < 5000) return;
    lastCheck = Date.now();
    nativeFetch("/auth/me", { credentials: "same-origin" })
      .then((r) => { if (r.status === 401 || r.status === 403) toLogin(); })
      .catch(() => {});
  };

  function show(me) {
    const menu = document.getElementById("userMenu");
    if (!menu) return;
    const admin = document.getElementById("lnkAdmin");
    const account = document.getElementById("lnkAccount");
    const out = document.getElementById("btnSignOut");
    menu.hidden = false;
    admin.hidden = me.user.role !== "admin";
    if (mode === "users") {
      account.hidden = false;
      account.textContent = me.user.display_name || me.user.username;
      account.title = `Signed in as ${me.user.username}: password, two-factor authentication, API tokens`;
      out.hidden = false;
      out.addEventListener("click", async () => {
        out.disabled = true;
        try {
          await nativeFetch("/auth/logout", { method: "POST", credentials: "same-origin",
                                              headers: { "Content-Type": "application/json" }, body: "{}" });
        } finally {
          leaving = true;
          location.href = "/login";
        }
      });
    }
  }

  function start() {
    nativeFetch("/auth/me", { credentials: "same-origin" })
      .then(async (r) => {
        if (r.status === 404) return;                       // no web layer: the classic console
        const me = await r.json().catch(() => null);
        if (!me) return;
        if (r.status === 401 || r.status === 403) { mode = "users"; toLogin(); return; }
        mode = me.mode || "users";
        const owed = me.needs || {};
        if (mode === "users" && (owed.mfa_verify || owed.password_change || owed.mfa_enroll)) { toLogin(); return; }
        show(me);
      })
      .catch(() => {});
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
