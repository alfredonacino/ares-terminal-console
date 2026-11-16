# ARES Terminal Console: Architecture

Version 2.3.0 · 16 November 2026 · Authored by Alfredo Nacino · Part of the ARES Application Suite

| Where | Address |
|---|---|
| **Downloads (signed)** | https://aresrepo.cybercontrol.tech |
| **Docker image** | `docker.cybercontrol.tech/ares/terminal-console` |
| **Listed on** | https://ares-suite.nacino.net |

The drawn blueprint (diagrams of every section below) is `docs/blueprint.html`.

Related documents: [Executive Summary](EXECUTIVE-SUMMARY.md) · [Executive Presentation](EXECUTIVE-PRESENTATION.md) · [Application Description](DESCRIPTION.md).

## 1. Design goals

| Goal | What it means in the design |
|---|---|
| **Opens on a broken machine** | The server is Python standard library only. No pip install, no Node, no build step, no network. The one optional dependency (`claude-agent-sdk`) is imported lazily and costs one feature when absent. |
| **One codebase, three hosts** | The same server and UI run as a desktop app, a Docker image and an ApexBuild module. Each host only decides where the server listens, where its data lives and how the window is shown. |
| **Sessions outlive the window** | The PTY belongs to the server, not to the WebSocket. A socket can drop and reattach; the process keeps running. |
| **Never act for the operator** | The AI is advisory: no tools, no permissions. The server tools are read-only scripts. The only state-changing action (Stop a process) takes two clicks. |
| **Nothing leaves without consent** | Anything sent to Claude or OSV.dev is first returned as a preview; only a request carrying that exact text back sends it. |

## 2. Context

```
                 ┌───────────────────────────────────────────────────────┐
   Operator ───▶ │  Window: Qt WebEngine (Linux) · WKWebView (macOS)     │
                 │          WebView2 (Windows) · browser (Docker, suite) │
                 └──────────────┬────────────────────────────────────────┘
                                │ HTTP + WebSocket, 127.0.0.1:<port>
                                │ (access token cookie)
                 ┌──────────────▼────────────────────────────────────────┐
                 │  ARES Terminal Console server (Python stdlib)         │
                 │   PTYs · history · server tools · assistant           │
                 └───┬───────────────┬──────────────────┬────────────────┘
                     │ pty / ConPTY  │ ssh (shared       │ HTTPS, only on
                     ▼               │  ControlMaster)   │ "Send"
               Local shells          ▼                   ▼
               (bash, zsh, fish,   Remote servers      Claude (via the operator's
                PowerShell)        (read-only probes)   Claude Code) · OSV.dev
```

External systems:

| System | Used for | Direction |
|---|---|---|
| Remote servers | SSH sessions typed in panes; read-only probes over the same connection | outbound SSH |
| Claude Code CLI | the ask bar and AI analyses, signed in with the operator's subscription | local process → Anthropic |
| OSV.dev | known vulnerabilities for an installed package list | outbound HTTPS, after preview |
| ARES Repository | signed releases and update manifest | download only |
| ApexBuild | hosts the module, frames it, issues a one-time sign-on ticket | inbound, loopback |

## 3. Components

```
app/
├── server.py        HTTP routes, WebSocket upgrade, JSON API, access token, CSP
├── websocket.py     RFC 6455 framing, 20 s keep-alive ping, 4 MB frame limit
├── pty_session.py   PTY / ConPTY, 256 KB scrollback, coalesced output, session registry
├── desktop.py       one server per user, native window, --self-test
├── remote.py        an SSH pane's target, ControlMaster sharing, running probes
├── where.py         host, IP address and directory of a pane
├── history.py       history, saved connections, commands, servers, redaction
├── shell_env.py     LS_COLORS palette, ls/ll/la/lt and ssh wrappers on PATH
├── agent.py         the ask bar on the Claude Agent SDK, cost ledger
├── sso.py           ApexBuild sign-on ticket (vendored from ApexBuild)
├── insight/         the seven server tools
│   ├── service.py       per-pane Insight, server history, AI previews
│   ├── health.py        CPU, memory, disk, load, network, top processes
│   ├── perfcheck.py     sampled performance check and findings
│   ├── metrics.py       parsing of the probe output
│   ├── inventory.py     packages, runtimes, servers, databases
│   ├── vulnscan.py      pending security updates, server issues, OSV.dev
│   └── serverinsight.py the probe scripts and machine identity
└── static/          UI: index.html, app.js, insight.js, style.css, vendored xterm.js
```

### 3.1 Server (`server.py`)

A `ThreadingHTTPServer`: one thread per request, one thread pair per attached
WebSocket. It serves the static UI, the JSON API and `/ws?session=<id>`.

Main routes:

| Route | Purpose |
|---|---|
| `GET /api/health` | liveness; the only path answered without a token |
| `GET/POST /api/sessions`, `POST /api/sessions/<id>/kill` | list, open, end sessions |
| `GET /api/sessions/<id>/where` | host, address and directory of a pane |
| `POST /api/sessions/<id>/command` | record a command line sent to a pane |
| `GET /api/history`, `POST /api/history/{save,forget,clear}` | connection history and saved entries |
| `GET /api/commands`, `POST /api/commands/clear` | commands sent, searchable |
| `GET /api/connections`, `GET /api/servers[/…]` | SSH destinations and per-server history |
| `GET/POST /api/insight/…` | the seven server tools |
| `GET /api/agent/state`, `POST /api/agent/ask`, `GET /api/agent/costs` | the assistant and its ledger |
| `GET /api/colors` | the colour legend |

### 3.2 Sessions (`pty_session.py`, `websocket.py`)

```
   Browser pane ──ws──▶ reader thread ──▶ Session.write()  ──▶ PTY ──▶ shell
        ▲                                                       │
        └──ws── writer thread ◀── listener queue ◀── reader ◀───┘
                                     │
                                     └──▶ scrollback (256 KB ring)
```

- A `Session` owns the PTY (POSIX `pty`, or ConPTY through `pywinpty` on
  Windows), a reader thread and a 256 KB scrollback buffer.
- Output is coalesced for 12 ms before it is handed to listeners, so a noisy
  command does not become one frame per read.
- Attaching a WebSocket replays the scrollback, then streams. Detaching
  removes the listener; the session keeps running.
- Messages are JSON text frames: `in` (keystrokes), `resize`, `signal`,
  `antiidle`, `ping` from the client; `out`, `info`, `pong` from the server.
- The server pings every idle socket every 20 s so proxies and power managers
  do not drop it. **Anti-idle**, off by default, writes a NUL byte to a quiet
  session so the remote end does not time out.

### 3.3 Server tools (`remote.py`, `insight/`)

```
  pane: ssh admin@db1   ──▶  ssh -o ControlMaster=auto
                                 -o ControlPath=~/.ssh/ares-tc/%C
                                 -o ControlPersist=60  admin@db1
                                        │ master connection (login typed once)
  ◈ server → health probe ──▶ ssh -S ~/.ssh/ares-tc/%C db1 sh -s < probe.sh
                                        │ one more channel, no prompt
                                        ▼
                               JSON-ish report ──▶ insight/metrics ──▶ UI
```

- A pane opened with `ssh …` is given OpenSSH multiplexing. A command that
  already sets ControlMaster, ControlPath or `-S` keeps its own choice.
- Local panes get an `ssh` wrapper on PATH that adds the same options for an
  interactive login only, so the tools follow an `ssh` typed in the pane.
  Git, rsync and scripts get plain ssh.
- Each probe is a read-only POSIX script fed to `sh -s`. Nothing is copied to
  or left on the server.
- With no master (Windows, or a dropped login) a probe connects on its own
  with `BatchMode=yes`: it works with keys and an agent and fails cleanly
  otherwise.
- A server's identity is `/etc/machine-id` (and equivalents), falling back to
  its SSH host key fingerprint. History is filed under that identity.
- Local panes run the same scripts in the local shell (**◈ system**).

### 3.4 Assistant (`agent.py`)

- Uses the Claude Agent SDK, which drives the operator's installed `claude`
  CLI. The CLI signs requests with its own login (Pro, Max, Team or
  Enterprise). No key is stored in the app.
- `allowed_tools` and `tools` are empty and `permission_mode` is `dontAsk`:
  the agent cannot run anything.
- `ANTHROPIC_API_KEY` is masked from the assistant (not from panes) so asks
  use the subscription; `ARES_ASK_AUTH=api-key` opts into the key.
- The ledger records each ask's question, tokens, model and cost
  (`ResultMessage.total_cost_usd`). Answers are not stored.
- AI log and performance analyses reuse ARES Ultimate Console's prompts word
  for word, with excerpt limits of 24 KB (logs) and 96 KB (performance).

### 3.5 Desktop host (`desktop.py`)

- Starts the server on `127.0.0.1`, on a free port, with an access token.
- The first copy owns the server. A second launch finds it and opens another
  window onto the same sessions instead of starting a second server.
- Window: PySide6 + Qt WebEngine on Linux (bundled), pywebview on Windows
  (WebView2) and macOS (WKWebView). Fallback: a Chromium-family app window,
  then the default browser (`ARES_WINDOW=browser` forces it).
- Closing the owning window ends the app and its sessions.
- `--self-test` starts on a temporary data folder, proves a shell runs, and
  exits. Every release build must pass it.

## 4. Data

All state is JSON in one data folder. There is no database.

| File | Contents |
|---|---|
| `history.json` | connections opened (start, end, exit code), saved entries, commands sent, SSH destinations and their sessions |
| `servers.json` | per-server reports and analyses, keyed by machine identity |
| `agent-costs.json` | the assistant's cost ledger |
| `access-token` | the Docker image's persistent token (when not set by environment) |

Data folder: `~/.local/share/ares-terminal-console` (Linux),
`~/Library/Application Support/ARES Terminal Console` (macOS),
`%APPDATA%\ARES Terminal Console` (Windows), `/data` (Docker). A 1.x
`apex-terminal` folder is moved across on first start.

**Redaction.** Before a command line is stored, `history.redact()` blanks
`--password`, `--token`, `sshpass -p`, credentials in URLs and similar.
Options that are needed to reconnect, such as `ssh -p 2222`, are kept. Input
that the terminal did not echo is never recorded.

## 5. Security

| Threat | Control |
|---|---|
| Another local user opens a shell through the port | Desktop app always uses an access token |
| Someone on the network reaches the port | Any listener beyond loopback requires a token (Docker sets it on) |
| A web page opens a WebSocket to localhost | `Origin` is checked on the handshake (browsers do not apply CORS to WebSockets) |
| Token leaks through the address bar or history | `?token=` is exchanged once for an HttpOnly, SameSite=Strict cookie and redirected away |
| Clickjacking | CSP `frame-ancestors 'self'` standalone; `'self'` plus exactly one loopback origin under ApexBuild |
| Injected script in the UI | CSP `script-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`; xterm.js vendored, no CDN |
| AI runs a command | The agent has no tools and no permissions; INSERT never sends a newline |
| Secrets sent to Claude or OSV.dev | Preview first, secrets replaced with `***`, no address or identity, sent only on the operator's click |
| Secrets on disk | Redaction of command lines; unechoed input never recorded |
| Tampered download | Releases signed and verified against ARES Repository's manifest |

Known limits: from source on loopback there is no login, the same trust
boundary as the rest of ApexBuild. A token is a shared secret, not a personal
login; over anything but a private network, put TLS in front (`https://`
origins are accepted on the WebSocket for that purpose).

## 6. Deployment blueprint

### 6.1 Desktop

| Platform | Artifact | Built by |
|---|---|---|
| Linux | `.deb`, `.tar.gz` (per-user `install.sh`) | `packaging/build-linux.sh`, Debian 11 container for old glibc |
| Arch | `.pkg.tar.zst` | `packaging/build-arch.sh` |
| Windows | setup `.exe` (no admin rights), portable `.zip` | `packaging/build-remote.sh` on the Windows build host |
| macOS | `.dmg`, `.zip` (Apple silicon, unsigned) | `packaging/build-remote.sh` on the macOS build host |

PyInstaller does not cross-compile, so each platform builds on its own kind of
machine. `packaging/release.sh` signs and publishes to ARES Repository with a
token and key kept in `~/.config/ares-repository/`, never in the repository.

### 6.2 Docker

```
docker run -d --name ares-terminal -p 8080:8080 -v ares-terminal:/data \
    docker.cybercontrol.tech/ares/terminal-console:latest
```

Shells run inside the container as the unprivileged user `ares`, with bash,
ssh, git, curl, dig, ping, jq, rsync and vim. What a pane can reach is what
the container can reach. Published with `packaging/docker/docker-push.sh`.

### 6.3 ApexBuild module

`apexmodule.toml` (id `terminal`, health `/api/health`, embeddable) and the
`apexmod` launcher make it a module. ApexBuild starts it on a loopback port,
frames it, and signs the user in with a one-time ticket verified by `sso.py`
using a key passed in the environment at launch.

### 6.4 ARES Application Suite

The suite entry and these four documents are published with
`packaging/register-ares-suite.sh`, which uses the suite's integration API and
an integration token. See [`DESCRIPTION.md`](DESCRIPTION.md#ares-application-suite).

## 7. Decisions

| Decision | Reason |
|---|---|
| Standard library only | A terminal must start on a machine in trouble, offline, with nothing installed |
| `Ctrl+Shift+…` keys, not a prefix key | A prefix must be intercepted before the terminal sees it, which breaks the program that needed it |
| `ls` wrappers on PATH, not aliases | Aliases would mean editing bash, zsh and fish rc files; the user's own alias still wins |
| Reuse the pane's SSH connection | A second login would prompt again, from a process with no terminal to prompt in |
| Advisory AI | The operator is there to see the command before it runs |
| JSON files, not a database | Small, per-user data; nothing to install or migrate |
| Releases only on ARES Repository | The signed manifest proves a download; a second copy is a second thing to keep in step |
