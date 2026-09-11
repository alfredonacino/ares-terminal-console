# Apex Terminal

Split-pane terminals in a browser tab, with broadcast, keep-alive and a
connection history. Standalone application and [ApexBuild](../ApexBuild) module
at the same time.

```sh
./run.sh                # then open the URL it prints
./run.sh --port 9001
```

Python 3.11+ and **nothing else** — no pip install, no build step. A terminal is
what you reach for when a machine is already in a bad way, and "install this
first" is the wrong answer at that moment.

## What it does

**Splits, like tmux.** `Ctrl+Shift+D` puts a pane beside the focused one,
`Ctrl+Shift+E` puts one below it. The layout is a binary tree, so closing a pane
collapses its parent back into its sibling instead of leaving a hole. Drag any
divider to re-balance.

**Broadcast.** Turn it on and every keystroke goes to every pane at once —
tmux's `synchronize-panes`. The chrome turns amber and stays amber, because
forgetting it is on is how you run a command on nine machines you meant to run
on one. The **send to all** bar next to it is the deliberate one-shot: type a
line, press Enter, it lands in every pane.

**Sessions outlive their socket.** Close the tab, lose wifi, suspend the laptop
— the command keeps running. Reopening replays the scrollback and carries on.
That is the property people actually want from tmux, and it is why the
**Running** tab lets you attach a session that no pane is currently showing.

**Keep-alive, at both ends.** The server pings every idle socket every 20
seconds, which is what stops a proxy or a power manager deciding the connection
is dead. That only covers the *browser* link, so there is a second control:
**anti-idle** writes a NUL byte to any session that has gone quiet for the
interval you pick. Shells discard it; the far end sees traffic and does not time
you out. It is off by default and the pane says so while it is on — it is still
a write into somebody's shell.

**History.** Everything opened here is recorded with when it started, when it
ended and how. Name one and it moves to **Saved**. Passwords are blanked before
anything reaches the disk — `--password`, `--token`, `sshpass -p`, credentials
in URLs — while `ssh -p 2222` keeps its port, because redacting that would hand
back a command that no longer connects.

## Keys

| | |
| --- | --- |
| `Ctrl+Shift+Enter` | new pane |
| `Ctrl+Shift+D` / `E` | split vertical / horizontal |
| `Ctrl+Shift+W` | close the focused pane |
| `Ctrl+Shift+S` | broadcast on/off |
| `Ctrl+Shift+H` | connections drawer |

`Ctrl+Shift+…` rather than a tmux prefix key: a prefix has to be intercepted
before the terminal sees it, and stealing a keystroke is how you break the one
program the user needed it for.

## Where it runs

POSIX only. The standard library has a `pty` module on Linux and macOS and no
equivalent on Windows, so there the app starts, serves its UI and says exactly
that rather than pretending. A Windows port needs a ConPTY binding
(`pywinpty`), which would be this app's only dependency.

## Scope, stated plainly

It binds loopback and has **no authentication of its own** — anything that can
reach the port can open a shell as you. That is the same trust boundary as every
other tool in the suite, and the reason the WebSocket checks `Origin` (browsers
do not apply CORS to WebSocket handshakes, so without that check any page on the
internet could open one). Keep it on 127.0.0.1. If you need it further away, put
something that authenticates in front.

## Part of ApexBuild

Two files make it a module, and neither changes how it behaves on its own:

| File | What it is |
| --- | --- |
| `apexmodule.toml` | how the suite lists it: name, icon, health path |
| `apexmod` | the uniform launcher: `info`, `check`, `run --host --port` |

```sh
apex modules add /path/to/apex-terminal --link
apex app
```

Under the suite it is framed by the shell on a sibling loopback port, so it
names that one origin in `frame-ancestors` and nothing else. Standalone it
refuses framing entirely. See `docs/EMBEDDING.md` in the ApexBuild repository.

## Layout

```
apex-terminal/
├── apexmodule.toml      manifest
├── apexmod              launcher (info / check / run)
├── run.sh, run.ps1      standalone entry points
└── app/
    ├── server.py        HTTP, WebSocket upgrade, JSON API
    ├── websocket.py     RFC 6455 framing, and the keep-alive ping
    ├── pty_session.py   PTYs, the scrollback ring, the session registry
    ├── history.py       history, saved connections, redaction
    └── static/          the UI (xterm.js vendored, no CDN)
```
