# Changelog

## [2.2.0]
- Server tools for SSH panes (◈ server, Ctrl+Shift+X): health & processes, performance analysis, log analysis, AI log analysis, packages & technologies, vulnerability scan and server history, from ARES Ultimate Console and TractorBeam.
- The tools run read-only scripts over the pane's own SSH connection (OpenSSH multiplexing), so a password or one-time code is typed once, in the pane.
- Servers are recognised by machine identity, or by SSH host key fingerprint, and their history is kept across sessions.
- AI analysis of logs and performance shows exactly what will be sent and sends it only on "Send to Claude", through the Claude Code subscription; vulnerability lookups on OSV.dev ask first too.
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
