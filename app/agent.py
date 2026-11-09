"""
Asking Claude for the command you cannot remember, and counting what it cost.

WHAT THIS IS

A question box under the terminal. You type "how do I list listening ports with
the owning process", and it answers with the command and a line about why. It
does not run anything: the answer arrives as text plus the commands it named,
and putting one into a pane is a separate, deliberate click.

WHY IT DOES NOT RUN ANYTHING

The Claude Agent SDK ships a Bash tool and would happily use it. This asks it
not to -- `allowed_tools` and `tools` are both empty and `permission_mode` is
"dontAsk", so there is no path from a sentence somebody typed to a command
this machine executes. A terminal is the one app where that shortcut is least
appropriate: the operator is here *because* they want to see the command before
it runs, often on a box that is already in a bad way.

So the shape is advisory. The agent proposes, the human disposes, and the
proposal lands in the pane's input where they can read it, edit it, and press
Enter themselves.

WHY THE SDK AND NOT THE RAW API

`claude-agent-sdk` is Claude Code as a library: it already owns the model
choice, the auth (an API key, or the CLI's own signed-in session), retries and
the agent loop. Talking to /v1/messages directly would mean re-implementing all
of it here, in a module whose selling point is that it has no dependencies.

WHICH BRINGS US TO THE DEPENDENCY

This is the only part of ARES Terminal Console that needs one, and it is optional on
purpose. The import is lazy and every failure to find it is reported as
"unavailable" rather than raised: a terminal must still open a PTY on a machine
with no SDK, no Node, and no network. See `state()`.

THE COST LEDGER

Every ask records what it cost. Not an estimate -- `ResultMessage` carries
`total_cost_usd` and a per-model `model_usage` breakdown with real token counts,
so the numbers in the panel are the ones Anthropic billed, not a guess from a
price table. `PRICES` exists only for the case where the SDK reports no cost at
all (a subscription session rather than an API key), and says so when it is used.
"""

import json
import os
import re
import threading
import time

# Per million tokens, USD. Only ever used when the SDK reports no cost of its
# own -- a Claude subscription session bills nothing per request, so there is
# nothing to report and an estimate is better than a blank. Anything not listed
# falls back to None and the ledger records the request with no cost rather
# than inventing one.
PRICES = {
    "claude-fable-5-1":  (10.00, 50.00),
    "claude-fable-5":    (10.00, 50.00),
    "claude-opus-5":     (5.00,  25.00),
    "claude-opus-4-8":   (5.00,  25.00),
    "claude-opus-4-7":   (5.00,  25.00),
    "claude-opus-4-6":   (5.00,  25.00),
    "claude-sonnet-5":   (2.00,  10.00),
    "claude-sonnet-4-6": (3.00,  15.00),
    "claude-haiku-4-5":  (1.00,   5.00),
}

# What a cached read and a cache write cost relative to a fresh input token.
CACHE_READ_RATE = 0.10
CACHE_WRITE_RATE = 1.25

MAX_LEDGER = 500

# Long enough for a real answer on a slow link, short enough that a wedged
# request does not hold a worker thread for the life of the process.
ASK_TIMEOUT = 120

MAX_PROMPT = 4000

SYSTEM_PROMPT = """\
You are a command-line assistant embedded in ARES Terminal Console, a split-pane \
terminal emulator. The person asking is a support engineer at a shell.

Answer with the command they need. Put every command in its own fenced code \
block with no shell prompt, no leading $, and nothing but the command itself -- \
the interface lifts those blocks out and offers them as one-click inserts, so a \
prompt character or a stray comment inside the fence becomes part of what they \
paste.

Then, outside the fence, one or two short lines saying what it does and what to \
watch out for. Name the flags that matter. Do not pad, do not restate the \
question, and do not explain that you are an AI.

If the command is destructive, irreversible, or would act on something other \
than the machine it runs on, say so plainly in the explanation.

If the question is not about the command line, say so in one sentence rather \
than guessing.\
"""


def _canonical(model: str) -> str:
    """`claude-opus-5[1m]` and a dated build both land on `claude-opus-5`.

    The SDK reports whichever string the session actually used, which carries a
    context-window suffix or a release date. The price is the same either way,
    and a ledger keyed on the raw string would show one model as four.
    """
    name = (model or "").strip()
    name = re.sub(r"\[[^\]]*\]$", "", name)          # drop a [1m] context suffix
    name = re.sub(r"-(\d{8})$", "", name)            # ...and a -20251001 date
    return name or "unknown"


def estimate_cost(model: str, usage: dict):
    """Dollars for one model's tokens, or None when the price is not known."""
    price = PRICES.get(_canonical(model))
    if not price or not usage:
        return None
    per_in, per_out = price
    fresh = usage.get("inputTokens", 0) or 0
    out = usage.get("outputTokens", 0) or 0
    cached = usage.get("cacheReadInputTokens", 0) or 0
    written = usage.get("cacheCreationInputTokens", 0) or 0
    return ((fresh * per_in)
            + (cached * per_in * CACHE_READ_RATE)
            + (written * per_in * CACHE_WRITE_RATE)
            + (out * per_out)) / 1_000_000


# ------------------------------------------------------------------ the answer

_FENCE = re.compile(r"```(?:[\w.+-]*)\n(.*?)```", re.S)

# A fenced block is a command only if it looks like one. A block of YAML or a
# config file excerpt is useful to read and would be nonsense to paste into a
# shell, and offering it as a one-click insert invites exactly that mistake.
_NOT_A_COMMAND = re.compile(r"^\s*(?:[#{\[]|---|\w+\s*:\s)")


def commands_in(text: str) -> list:
    """The shell commands the answer proposed, in the order it gave them."""
    found = []
    for block in _FENCE.findall(text or ""):
        for line in block.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip a prompt the model added anyway, despite being asked not to.
            line = re.sub(r"^[$>]\s+", "", line)
            if _NOT_A_COMMAND.match(line) or line in found:
                continue
            found.append(line)
    return found[:10]


# --------------------------------------------------------------- availability
#
# THE SUBSCRIPTION
#
# The SDK does not call the API itself: it drives the Claude Code CLI, and the
# CLI signs in the way it always does -- with a Claude subscription (Pro, Max,
# Team, Enterprise) through `claude auth login`. So the assistant uses whatever
# account the operator's own Claude Code is signed in to, and there is no key
# to paste into this app at all.
#
# Two things would quietly undo that, and both are handled here:
#
#   * an ANTHROPIC_API_KEY in the environment takes precedence over the
#     subscription in the CLI, and bills per token to whoever owns the key. In
#     the default mode it is masked from the CLI (not from the panes).
#   * a desktop app launched from a menu gets a minimal PATH, so `claude` in
#     ~/.local/bin is not found. The usual install locations are searched too.
#
# ARES_ASK_AUTH=api-key switches back to using the key, for people who want it.

AUTH_MODE = (os.environ.get("ARES_ASK_AUTH") or "subscription").strip().lower()
_MASKED = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
STATUS_TTL = 60            # seconds a sign-in check is trusted for
_status_cache = {"at": 0.0, "cli": "", "value": None}
_status_lock = threading.Lock()


def subscription_mode() -> bool:
    return AUTH_MODE != "api-key"


def cli_env() -> dict:
    """What the CLI's environment is overlaid with: the API key masked, so the
    subscription is what signs the request."""
    return {k: "" for k in _MASKED} if subscription_mode() else {}


def find_cli() -> str:
    """The operator's own Claude Code, wherever it was installed."""
    import shutil
    explicit = os.environ.get("CLAUDE_CODE_PATH", "").strip()
    if explicit and os.path.isfile(explicit):
        return explicit
    found = shutil.which("claude")
    if found:
        return found
    home = os.path.expanduser("~")
    exe = "claude.exe" if os.name == "nt" else "claude"
    candidates = [
        os.path.join(home, ".local", "bin", exe),           # the native installer
        os.path.join(home, ".claude", "local", exe),         # `claude migrate-installer`
        "/opt/homebrew/bin/claude", "/usr/local/bin/claude", "/usr/bin/claude",
        os.path.join(home, ".npm-global", "bin", "claude"),
        os.path.join(home, ".bun", "bin", "claude"),
    ]
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        candidates += [os.path.join(local, "Programs", "claude", exe),
                       os.path.join(local, "AnthropicClaude", exe)]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def account(cli: str, refresh: bool = False) -> dict:
    """`claude auth status`, cached: who the CLI is signed in as, and how.

    Run with the same environment an ask gets, so the answer describes the
    credential an ask would actually use.
    """
    import subprocess
    with _status_lock:
        cached = _status_cache["value"]
        if (not refresh and cached is not None and _status_cache["cli"] == cli
                and time.time() - _status_cache["at"] < STATUS_TTL):
            return cached
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    env.update(cli_env())
    try:
        out = subprocess.run([cli, "auth", "status", "--json"], capture_output=True,
                             text=True, timeout=20, env=env, stdin=subprocess.DEVNULL,
                             creationflags=0x08000000 if os.name == "nt" else 0)
        data = json.loads(out.stdout or "{}")
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        data = {"loggedIn": False, "error": f"{e.__class__.__name__}: {e}"}
    value = {
        "signed_in": bool(data.get("loggedIn")),
        "method": data.get("authMethod") or "",
        "subscription": data.get("subscriptionType") or "",
        "email": data.get("email") or "",
        "org": data.get("orgName") or "",
        "error": data.get("error") or "",
    }
    with _status_lock:
        _status_cache.update(at=time.time(), cli=cli, value=value)
    return value


def login_command(cli: str) -> str:
    """The command a pane runs to sign in."""
    if os.name == "nt":
        return f'"{cli}" auth login'
    import shlex
    return f"{shlex.quote(cli)} auth login"


def state(refresh: bool = False) -> dict:
    """Whether an ask can succeed, and if not, what is missing.

    Every branch returns rather than raises. The question box is one feature of
    a terminal, and a terminal that refuses to start because an optional SDK is
    absent has its priorities backwards.
    """
    base = {"mode": "subscription" if subscription_mode() else "api-key"}
    try:
        import claude_agent_sdk                                   # noqa: F401
    except Exception as e:
        return {**base, "available": False, "reason": "sdk",
                "detail": f"claude-agent-sdk is not installed ({e.__class__.__name__}). "
                          "Install it with `pip install claude-agent-sdk` in the "
                          "environment this runs from; the desktop app includes it."}

    cli = find_cli()
    if not cli:
        return {**base, "available": False, "reason": "cli",
                "detail": "Claude Code was not found. The assistant uses your Claude "
                          "subscription through it: install it from "
                          "https://claude.com/claude-code, then sign in. If it is "
                          "installed somewhere unusual, set CLAUDE_CODE_PATH."}

    if not subscription_mode():
        return {**base, "available": True, "reason": "", "detail": "", "cli": cli,
                "has_api_key": bool(os.environ.get("ANTHROPIC_API_KEY"))}

    who = account(cli, refresh=refresh)
    if not who["signed_in"]:
        return {**base, "available": False, "reason": "login", "cli": cli,
                "login_command": login_command(cli),
                "detail": "Claude Code is not signed in. Sign in with your Claude "
                          "subscription to use the assistant."
                          + (f" ({who['error']})" if who["error"] else "")}
    return {**base, "available": True, "reason": "", "detail": "", "cli": cli,
            "account": who, "login_command": login_command(cli),
            "masked_api_key": bool(os.environ.get("ANTHROPIC_API_KEY"))}


# ---------------------------------------------------------------- asking

def ask(prompt: str, cwd: str = "", model: str = "") -> dict:
    """Put one question to the agent. Returns the answer, or an error.

    Synchronous by design: the SDK is asyncio and the server is a thread per
    request, so the event loop lives and dies inside this call rather than
    being something the rest of the module has to know about.
    """
    import asyncio

    prompt = (prompt or "").strip()
    if not prompt:
        return {"ok": False, "error": "Ask a question first."}
    if len(prompt) > MAX_PROMPT:
        return {"ok": False, "error": f"That question is longer than "
                                      f"{MAX_PROMPT} characters."}

    ready = state()
    if not ready["available"]:
        return {"ok": False, "error": ready["detail"], "reason": ready["reason"]}

    try:
        return asyncio.run(_ask(prompt, cwd, model, ready.get("cli", "")))
    except Exception as e:
        # Includes the SDK's own CLINotFoundError, ProcessError and the
        # authentication failures, all of which are things to show the user
        # rather than a stack trace in a log nobody is reading.
        return {"ok": False, "error": f"{e.__class__.__name__}: {e}"}


async def _ask(prompt: str, cwd: str, model: str, cli: str = "") -> dict:
    from claude_agent_sdk import (AssistantMessage, ClaudeAgentOptions,
                                  ResultMessage, TextBlock, query)
    import asyncio

    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        # No tools, and no permission to use any. See the module docstring:
        # this answers questions about commands, it does not run them.
        tools=[],
        allowed_tools=[],
        permission_mode="dontAsk",
        max_turns=1,
        # The operator's own CLAUDE.md and settings are not loaded. They belong
        # to whatever project directory the pane happens to be sitting in, and
        # silently folding them into a terminal's help box would make the same
        # question give different answers depending on the cwd.
        setting_sources=None,
        cwd=cwd or None,
        model=model or None,
        # The operator's own Claude Code and its sign-in, never a copy bundled
        # into this app; and in subscription mode, no API key to outrank it.
        cli_path=cli or None,
        env=cli_env(),
    )

    chunks, result = [], None
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    chunks.append(block.text)
        elif isinstance(message, ResultMessage):
            result = message

    text = "".join(chunks).strip()
    if result is not None and result.is_error and not text:
        return {"ok": False,
                "error": "; ".join(result.errors or []) or "The agent returned an error.",
                "usage": _usage_of(result)}
    if not text:
        return {"ok": False, "error": "The agent returned nothing."}

    usage = _usage_of(result)
    if usage and subscription_mode():
        # The CLI still reports what the ask would have cost at API rates. On a
        # subscription that is not a bill, and the panel must say so.
        usage["subscription"] = True
    return {"ok": True, "text": text, "commands": commands_in(text), "usage": usage}


def _usage_of(result) -> dict:
    """One ask's cost, flattened into something a browser can render.

    `total_cost_usd` is what the SDK actually billed and is preferred whenever
    it is there. The per-model estimate is the fallback, and `estimated` says
    which of the two the number came from -- a cost panel that cannot tell a
    measurement from a guess is worse than no cost panel.
    """
    if result is None:
        return {}

    models = []
    for name, usage in (result.model_usage or {}).items():
        billed = usage.get("costUSD")
        models.append({
            "model": _canonical(name),
            "input": usage.get("inputTokens", 0),
            "output": usage.get("outputTokens", 0),
            "cache_read": usage.get("cacheReadInputTokens", 0),
            "cache_write": usage.get("cacheCreationInputTokens", 0),
            "cost": billed if billed is not None else estimate_cost(name, usage),
            "estimated": billed is None,
        })

    total = result.total_cost_usd
    estimated = total is None
    if estimated:
        parts = [m["cost"] for m in models if m["cost"] is not None]
        total = sum(parts) if parts else None

    return {
        "cost": total,
        "estimated": estimated,
        "turns": result.num_turns,
        "duration_ms": result.duration_ms,
        "api_ms": result.duration_api_ms,
        "session": result.session_id,
        "models": models,
        "input": sum(m["input"] for m in models),
        "output": sum(m["output"] for m in models),
        "cache_read": sum(m["cache_read"] for m in models),
        "cache_write": sum(m["cache_write"] for m in models),
    }


# ----------------------------------------------------------------- the ledger

def _models_of(row: dict) -> list:
    """One ask's models, whichever shape the row was written in.

    Rows written before the per-model cost was kept hold bare strings. They are
    still counted -- an ask is an ask -- but they contribute no cost, because
    the split they would need was never recorded and inventing one would make
    the oldest rows the least trustworthy without saying so.
    """
    out = []
    for entry in row.get("models") or []:
        if isinstance(entry, dict):
            out.append({"model": entry.get("model") or "unknown",
                        "cost": entry.get("cost")})
        else:
            out.append({"model": str(entry), "cost": None})
    return out or [{"model": "unknown", "cost": row.get("cost")}]


class Ledger:
    """What every ask cost, on disk, so the total survives a restart.

    Same bargain as History: one JSON file in the data directory, written whole
    under a lock. A few hundred rows of small objects is not a database problem,
    and a terminal should not acquire one.

    The question is stored; the answer is not. What the panel needs is "which
    ask cost that much", and keeping the full text of every answer would turn a
    cost ledger into a transcript nobody asked it to keep.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._data = {"version": 1, "asks": []}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("asks"), list):
                with self._lock:
                    self._data = {"version": 1, "asks": data["asks"][:MAX_LEDGER]}
        except (OSError, ValueError):
            # No file yet, or one that will not parse. Either way the ledger
            # starts empty rather than stopping the module from loading.
            pass

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def record(self, prompt: str, usage: dict, ok: bool = True) -> None:
        row = {
            "at": time.time(),
            "prompt": (prompt or "")[:200],
            "ok": bool(ok),
            "cost": usage.get("cost"),
            "estimated": bool(usage.get("estimated")),
            "subscription": bool(usage.get("subscription")),
            "input": usage.get("input", 0),
            "output": usage.get("output", 0),
            "cache_read": usage.get("cache_read", 0),
            "cache_write": usage.get("cache_write", 0),
            "duration_ms": usage.get("duration_ms"),
            # Per model, with its own cost. Keeping only the names would make
            # the per-model breakdown a guess: one ask routinely spends across
            # two models, and the expensive one is not the one listed first.
            "models": [{"model": m["model"], "cost": m.get("cost")}
                       for m in usage.get("models", [])],
        }
        with self._lock:
            self._data["asks"].insert(0, row)
            del self._data["asks"][MAX_LEDGER:]
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._data = {"version": 1, "asks": []}
            self._save()

    def analysis(self, recent: int = 25) -> dict:
        """The cost panel: totals, a per-day series, per-model, and the tail."""
        with self._lock:
            asks = list(self._data["asks"])

        priced = [a for a in asks if a.get("cost") is not None]
        total = sum(a["cost"] for a in priced)
        tokens = {k: sum(a.get(k, 0) or 0 for a in asks)
                  for k in ("input", "output", "cache_read", "cache_write")}

        by_day, by_model = {}, {}
        for a in asks:
            day = time.strftime("%Y-%m-%d", time.localtime(a["at"]))
            slot = by_day.setdefault(day, {"day": day, "asks": 0, "cost": 0.0})
            slot["asks"] += 1
            slot["cost"] += a.get("cost") or 0.0
            for entry in _models_of(a):
                m = by_model.setdefault(entry["model"],
                                        {"model": entry["model"], "asks": 0, "cost": 0.0})
                m["asks"] += 1
                m["cost"] += entry.get("cost") or 0.0

        return {
            "asks": len(asks),
            "priced": len(priced),
            # True when at least one row's cost came from the price table rather
            # than from the SDK, so the panel can mark the total as approximate.
            "estimated": any(a.get("estimated") for a in priced),
            "subscription": any(a.get("subscription") for a in asks),
            "total": total,
            "average": (total / len(priced)) if priced else 0.0,
            "tokens": tokens,
            "by_day": sorted(by_day.values(), key=lambda d: d["day"])[-30:],
            "by_model": sorted(by_model.values(), key=lambda m: -m["cost"]),
            "recent": asks[:recent],
        }
