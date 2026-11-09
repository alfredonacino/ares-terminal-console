# Changelog

## [2.0.0]
- Renamed: Apex Terminal is now ARES Terminal Console. Your 1.x history and saved connections are carried across on first start.
- Desktop application for Linux (.deb, Arch package, tarball), macOS (Apple silicon .dmg) and Windows (installer and portable zip), in a window of its own.
- Windows: terminals run through ConPTY, with PowerShell as the default shell.
- Docker image (ares/terminal-console): the console served to a browser, with its shells inside the container.
- An access token is required whenever the console is reachable by more than its own user: the desktop app always, and any listener beyond loopback (the Docker image).
- WebSocket connections are accepted from https:// pages, for running behind a TLS proxy.
