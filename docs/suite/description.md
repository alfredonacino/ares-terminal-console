# ARES Terminal Console

ARES Terminal Console is the terminal of the ARES Suite: split-pane shells and SSH sessions side by
side, in a browser or a desktop window, with a memory of everything that was opened and run.

## Features
- **Splits and tabs.** `Ctrl+Shift+D` / `E` split the focused pane; the layout is a tree, so closing a
  pane gives its space back. Each connection gets a tab with its own splits; the layout survives a reload.
- **Broadcast.** Type into every pane of the tab at once (the bar turns amber while it is on), or send a
  single line to all of them.
- **Sessions that outlive the window.** Close the tab, lose Wi-Fi, suspend the laptop: the command keeps
  running, and reopening replays the scrollback. Server pings and an optional anti-idle keep connections up.
- **Where every pane is.** Host, IP address and current directory in each pane's bar, for local and SSH panes.
- **History.** Every SSH destination, every session (start, end, exit code) and every command line, read
  off the screen as Enter is pressed; passwords that were not echoed are never recorded, and
  `--password`-style secrets are blanked.
- **Server tools.** Health & processes, performance analysis, log analysis, AI log analysis (consent
  first, exactly what is sent is shown), packages & technologies, vulnerability scan (OSV.dev) and server
  history, all read-only scripts over the pane's own SSH login: nothing is installed on the server.
- **Ask.** An assistant that proposes the command for what you describe and never runs it.

## Web edition
- **Users and roles** (administrator, user), created by an administrator or provisioned on first SSO
  sign-in; the first administrator is `aresadmin`.
- **Two-factor authentication** with any authenticator app (TOTP) and single-use recovery codes, required
  for everyone by default.
- **Single sign-on**: Microsoft Entra ID through OpenID Connect (PKCE, group-based roles), any SAML 2.0
  identity provider, and LDAP / Active Directory (LDAPS or StartTLS, group-based roles and access).
- **Isolation**: each user's terminals, history and SSH known hosts are their own; local shells on the
  server are for administrators only unless the policy says otherwise.
- **Operations**: encrypted backups (AES-256-GCM) to local storage, SFTP and S3 on a schedule with
  retention; restore from the UI or the command line; an API for everything with scoped, expiring tokens;
  an append-only audit and activity log with CSV / JSON export; ECS JSON logs forwarded to Splunk,
  Elastic, Graylog, Loki, Wazuh or Sentinel over syslog or HTTPS.

## Platforms
- **Web**: https://ares-terminal-console.nacino.net (demo: https://ares-terminal-console-demo.nacino.net),
  or the Docker image `docker.cybercontrol.tech/ares/ares-terminal-console`.
- **Desktop**: Windows 10/11 (setup.exe, MSI, zip), macOS 11+ on Apple silicon and Intel (DMG, zip),
  Linux: Debian/Ubuntu (deb), Red Hat/Rocky/Fedora (rpm), Arch/CachyOS (pkg.tar.zst), any distribution
  (AppImage, tar.gz). Downloads on the ARES Repository.
