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

There is exactly one optional dependency, `claude-agent-sdk`, and it buys one
optional feature: the [ask bar](#asking-about-a-command). Everything above
still holds without it — the import is lazy, and a missing SDK costs you the
question box and nothing else.

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

**Colour, without touching your shell config.** A listing is monochrome unless
two things are true, and in a plain shell neither is: `LS_COLORS` has to say
what each kind of file looks like, and `ls` has to be *asked* to colour with
`--color=auto`, which normally comes from an alias you may not have. Both are
set up for every pane — a palette matched to the suite's theme, and `ls`/`ll`/
`la`/`lt` wrappers placed first on `PATH`. Wrappers rather than aliases because
an alias would have to be injected into bash, zsh and fish separately, and
editing somebody's rc files to get colour is not a trade worth making. Your own
alias still wins, since aliases resolve before `PATH`. The **Colours** tab in
the drawer is the legend, rendered with the real escape sequences.

One honest limit: **GNU `ls` cannot colour hidden files.** Its scheme takes
two-letter type codes and `*suffix` patterns only — a leading-dot glob is
rejected outright. `eza` does accept one, so where it is installed `ll` and
`la` dim dotfiles; plain `ls` cannot, and no scheme changes that.

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
| `Ctrl+Shift+A` | ask bar on/off |

`Ctrl+Shift+…` rather than a tmux prefix key: a prefix has to be intercepted
before the terminal sees it, and stealing a keystroke is how you break the one
program the user needed it for.

## Asking about a command

The **ask** bar under the panes (`Ctrl+Shift+A`) puts a question to Claude
through the [Claude Agent SDK][sdk] and answers with the command, plus a line
on what it does and what to watch for.

```
ask  how do I find what is listening on port 8443?

  ss -ltnp 'sport = :8443'                                    INSERT
  sudo lsof -iTCP:8443 -sTCP:LISTEN -n -P                     INSERT

  $0.0121  ·  908 in / 181 out  ·  3.0s  ·  claude-opus-5
```

**It never runs anything.** The agent is handed no tools and no permission to
use any, so there is no path from a sentence somebody typed to a command this
machine executes. `INSERT` puts the command at the prompt of the focused pane
*without a newline*: you read it, edit it if you want, and press Enter
yourself. Broadcast is deliberately ignored here — one click means one pane.

That is the whole design argument. A terminal is the one application where
"just run it for me" is least appropriate, because the operator is usually here
precisely to see the command before it runs, often on a machine that is already
in a bad way.

### What it costs

The `$` button opens a cost panel: total spend, per day, per model, and the
recent asks with their tokens. The numbers come from the SDK's own accounting
(`ResultMessage.total_cost_usd` and its per-model breakdown), so they are what
was billed rather than a guess from a rate card. A row is marked *estimated*
only when the SDK reported no cost at all, which is what a Claude subscription
session does rather than an API key.

Questions are stored so a cost can be attributed to one; answers are not. The
ledger lives beside the history, in the data directory, and `Clear the ledger`
empties it.

### The one dependency

`claude-agent-sdk` is the only thing in `requirements.txt`, it is optional, and
it is imported lazily. `apex setup terminal` installs it into the module's own
`.venv`. Without it the bar says so and everything else works unchanged —
a terminal has to open on a machine with no SDK, no Node and no network, which
is generally why you reach for one.

[sdk]: https://code.claude.com/docs/en/agent-sdk

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
    ├── shell_env.py     the colour scheme and the ls/ll/la wrappers
    └── static/          the UI (xterm.js vendored, no CDN)
```
