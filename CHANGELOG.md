# Changelog

## [2.4.2]
### Fixed
- Two-factor enrolment: phone cameras could not read the QR code. It was drawn 285 px wide in a 200 px box and cropped; it now scales to its box (an SVG `viewBox`) with the standard four-module quiet zone. The `otpauth://` link writes spaces as `%20` instead of `+`, which some authenticator apps showed in the account name.

## [2.4.1]
### Added
- `GET /healthz/pingmora`: the health status APEX Pingmora reads (`suite-health/1`): a public summary, and with an API token (`read`) or `PINGMORA_HEALTH_TOKEN` the version, uptime and the database, disk and terminal checks.

### Changed
- Suite documents: diagrams throughout the Executive Summary, Product Description and Architecture, and a Changes document built from this changelog.
- CI builds the macOS installers on the `macos-15` (Apple silicon) and `macos-15-intel` runners; the `macos-13` and `macos-14` runners are retired.
- macOS Intel installer: cryptography stays on 48.x (the last release with a macOS Intel wheel), so the bundled OpenSSL matches.
- `packaging/build-remote.sh` writes the merged `SHA256SUMS` even when `dist/desktop` has none yet.

## [2.4.0]
- **Web application.** `app/main.py` serves ARES Terminal Console as a web app (Docker, the `pre` pm2 app server, the `prod` Kubernetes pod), with sign-in in front of everything but `/healthz`. The desktop app, `./run.sh` and ApexBuild stay as they were: **no sign-in**.
- **User administration**: users with roles (administrator, user), created by an administrator or on first SSO sign-in; disable, reset password, reset 2FA, sign out everywhere, delete. The first administrator is **`aresadmin`**, with a one-time password in `DATA_DIR/initial-admin-password.txt` (or `ARES_ADMIN_PASSWORD`) that must be changed at first sign-in.
- **Two-factor authentication** (TOTP, any authenticator app) with ten single-use recovery codes; required for every local and LDAP account by default (policy: everyone, administrators, optional; optionally SSO accounts too).
- **Single sign-on**: Microsoft Entra ID through OpenID Connect (PKCE, ID token verified against the tenant's keys, groups and app roles to roles), any SAML 2.0 identity provider (metadata import, signed assertions), and LDAP / Active Directory (LDAPS or StartTLS, service bind, group-based admin and access).
- **Per-user isolation**: each user's terminals, scrollback, command and connection history, server tools data and SSH home are their own. Local shells on the server are for administrators only by default; other users open `ssh` connections, with options that would run or read local things refused.
- **Policies**: session idle and maximum length, lockout, password sign-in for everyone or administrators only, 2FA, local shells, retention.
- **Backup & Restore** (ARES Suite standard `suite-backup/1`): local, SFTP and S3-compatible destinations, AES-256-GCM with a scrypt passphrase that is never in a backup, schedule and retention per destination, restore from the page, the first-run screen or `python app/main.py backup create|list|restore|prune`. Also in the desktop app.
- **API tokens** (`ares_<id>_<secret>`, scopes, expiry, rotate, revoke) for every function under `/api/v1/`, with `GET /api/v1/openapi.json`.
- **Audit & Activity** log in the database (sign-ins, 2FA, users, tokens, settings, backups, terminals opened and closed, commands run), filters and CSV / JSON export, retention.
- **JSON logs** (ECS) on stdout and forwarding to syslog (UDP/TCP/TLS) and HTTPS collectors (Splunk, Elastic, Graylog, Loki, Wazuh, Sentinel), at least once for audit and activity.
- **Deployed in `prod` and `pre`** with the ARES Suite standard: `ares.app.json`, server and nginx images `docker.cybercontrol.tech/ares/ares-terminal-console[-web]`, Kubernetes manifests, pm2 with watch, CI on GitLab and GitHub.
- Desktop installers for every platform: Linux `.deb`, `.rpm`, `.pkg.tar.zst`, `.AppImage`, `.tar.gz`; Windows `-setup.exe`, `.msi`, `.zip`; macOS `.dmg` and `.zip` for Apple silicon and Intel; all named `ares-terminal-console-<version>-<os>-<arch>.<ext>`.
- The version lives in `VERSION` (mirrored in `apexmodule.toml` for ApexBuild).
- The Docker image is now `docker.cybercontrol.tech/ares/ares-terminal-console` on port 3222 with data in `/app/data`, and requires a sign-in instead of the access-token link.

## [2.3.1]
- The server tools are a card floating in the top-right corner of the focused pane's terminal, as on TractorBeam's SSH tab: the machine's name and OS, and the seven tools one click away, instead of the ◈ button in the pane's title bar. ▸ folds it to a single ◈ server / ◈ system button, for every pane, remembered between runs.

## [2.3.0]
- Linux: the desktop app opens in a native Qt window (PySide6 + Qt WebEngine, bundled), like ARES Ultimate Console, instead of a Chrome/Chromium app window. It has its own name and icon in the task bar, keeps its layout between runs, sends other sites to the default browser, and needs no browser installed. F11 toggles full screen. `ARES_WINDOW=browser` brings back the browser window.

## [2.2.2]
- The server tools follow an `ssh` typed into a local pane: while the shell is logged in to a server, ◈ server and every tool work on that server over the pane's own login (a small `ssh` wrapper on local panes' PATH adds connection sharing for interactive logins); after `exit` they are back on this computer.
- The wrapper directory is always put on PATH as an absolute path.

## [2.2.1]
- The server tools now work on local panes too (◈ system, Ctrl+Shift+X): health & processes, performance, logs, AI log analysis, packages, vulnerability scan and history for this computer. Its Stop refuses the app's own process.

## [2.2.0]
- Server tools for SSH panes (◈ server, Ctrl+Shift+X): health & processes, performance analysis, log analysis, AI log analysis, packages & technologies, vulnerability scan and server history, from ARES Ultimate Console and TractorBeam.
- The tools run read-only scripts over the pane's own SSH connection (OpenSSH multiplexing), so a password or one-time code is typed once, in the pane.
- Servers are recognised by machine identity, or by SSH host key fingerprint, and their history is kept across sessions.
- AI analysis of logs and performance shows exactly what will be sent and sends it only on "Send to Claude", through the Claude Code subscription; vulnerability lookups on OSV.dev ask first too.
- Tabs: each connection opens in a tab of its own with its own splits (+ for a local shell, ⇄ connect… for a server, Ctrl+Shift+T, Ctrl+PageUp/PageDown). Tabs can be renamed, and the layout survives a reload. Broadcast is limited to the tab on screen.
- Each pane's bar shows the host, IP address and current directory, for local and SSH panes alike.
- Commands sent to each pane are recorded (time, pane, server) and listed in the new Commands tab and under ⌘ on a pane, searchable, with Insert and Copy. Passwords are never recorded.
- The new Servers tab lists every SSH destination connected to, with connection count, first and last time, sessions and commands sent, and reconnects in a new tab.
- History entries now record when a session ended and its exit code.
- Fixed: a closing terminal could raise a TypeError in its reader thread.
- The window has the ARES icon, and the top bar reads ARES TERMINAL CONSOLE.

## [2.1.0]
- The assistant ("ask") works in the desktop app and uses your Claude subscription: it runs on the Claude Code you installed and signed in to, with no API key to paste.
- The ask bar shows the plan it is using (for example Claude Max). When Claude Code is not signed in it offers "Sign in with Claude", which opens a pane running `claude auth login`, and "Check again".
- An ANTHROPIC_API_KEY in the environment no longer outranks the subscription for asks (set ARES_ASK_AUTH=api-key to use the key).
- Claude Code is found in its usual install folders too, for an app started from a menu with a short PATH.
- Costs of subscription asks are labelled "included in subscription" and shown at API rates as a measure of usage.
- MIT licensed.

## [2.0.0]
- Renamed: Apex Terminal is now ARES Terminal Console. Your 1.x history and saved connections are carried across on first start.
- Desktop application for Linux (.deb, Arch package, tarball), macOS (Apple silicon .dmg) and Windows (installer and portable zip), in a window of its own.
- Windows: terminals run through ConPTY, with PowerShell as the default shell.
- Docker image (ares/terminal-console): the console served to a browser, with its shells inside the container.
- An access token is required whenever the console is reachable by more than its own user: the desktop app always, and any listener beyond loopback (the Docker image).
- WebSocket connections are accepted from https:// pages, for running behind a TLS proxy.
