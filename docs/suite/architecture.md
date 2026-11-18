# ARES Terminal Console - Architecture (overview)

One Python codebase, standard library at its core, three ways to run:

```
 browser ──HTTPS──► edge proxy ──► ares-terminal-console-web (nginx) ──► ares-terminal-console-api :3222
                                                                           │ app/main.py (web edition)
                                                                           │  sign-in, 2FA, SSO, users, API, audit
                                                                           │  PTYs ◄─WebSocket─► xterm.js panes
                                                                           └─ DATA_DIR: SQLite + per-user data
 desktop window (Qt / WebView) ──loopback──► the same server, local mode (no sign-in)
```

- **Server**: `http.server` + its own WebSocket, one PTY per pane, sessions that outlive their socket.
  Web edition adds a SQLite database (users, sessions, tokens, settings, audit and activity), TOTP 2FA,
  OpenID Connect (Entra ID), SAML 2.0 and LDAP, per-user data folders and homes, and policies
  (2FA, local shells, lockout, sessions).
- **Web tier**: nginx forwarding HTTP and WebSockets; identical image in every environment.
- **`prod`**: both tiers on the production Kubernetes cluster, the server as one replica with the PVC
  `ares-terminal-console-data`. **`pre`**: web tier on the preproduction cluster, server under pm2 on the
  preproduction app server(s), watch on.
- **Desktop**: PyInstaller bundle with a native window; no sign-in, data in the user's profile.
- **Backups**: `suite-backup/1` archives (database snapshot + data folder + key), AES-256-GCM, to local,
  SFTP and S3, scheduled with retention. **Logs**: ECS JSON on stdout and forwarded to a SIEM.

Details: `docs/ARCHITECTURE.md`.
