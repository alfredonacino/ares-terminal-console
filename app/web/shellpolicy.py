"""What a web user's terminal may run, and the ssh options that keep users apart.

In the web edition every terminal runs as the one service account on the server. Two rules
follow from that:

* **Who may open a shell on this server** is the ``local_shell`` policy (default: administrators).
  Everyone else may open only ``ssh <destination>``, validated here and pinned to their own ssh
  config, known_hosts and identity file, with no agent, no forwarding, no escape commands, and no
  option that runs a local command (``-o ProxyCommand``, ``-F``, ``-J``, ``-I``, …). They reach
  only what they can log in to with their own credentials.
* **Connection sharing is per user.** The console multiplexes ssh (ControlMaster) so the server
  tools ride on a pane's login. The socket directory is per user, so one user's authenticated
  connection is never reused by another's ``ssh`` to the same host.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

# ssh flags that take an argument (OpenSSH 9.x).
_WITH_ARG = set("BbcDEeFIiJLlmOoPpQRSWw")
# Allowed for users without a local shell. Everything else is refused.
_ALLOWED_ARG = set("BbclmpPQ")
_ALLOWED_FLAG = set("46aACgkKqstTvVxXyY")


class PolicyError(ValueError):
    pass


def validate_ssh(command: str) -> list[str]:
    """The argv of a plain ``ssh [safe options] destination [remote command]``, or PolicyError."""
    try:
        argv = shlex.split(command or "")
    except ValueError:
        raise PolicyError("The command could not be read (unbalanced quotes).")
    if not argv or argv[0] != "ssh":
        raise PolicyError("Your administrator allows only ssh connections here: ssh user@host")
    i, dest = 1, None
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        j = 1
        while j < len(a):
            c = a[j]
            if c in _WITH_ARG:
                if c not in _ALLOWED_ARG:
                    raise PolicyError(f"The ssh option -{c} is not allowed here.")
                if j + 1 >= len(a):
                    i += 1
                    if i >= len(argv):
                        raise PolicyError(f"The ssh option -{c} needs a value.")
                break
            if c not in _ALLOWED_FLAG:
                raise PolicyError(f"The ssh option -{c} is not allowed here.")
            j += 1
        i += 1
    if i < len(argv):
        dest = argv[i]
    if not dest or dest.startswith("-"):
        raise PolicyError("Name the server to connect to: ssh user@host")
    return argv


def control_dir(base: str, uid: int) -> str:
    """The user's own ControlMaster socket directory (short: a socket path is limited to ~104 bytes)."""
    path = os.path.join(base, f"u{int(uid)}")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def user_home(data_dir: str | Path, uid: int) -> str:
    home = Path(data_dir) / "users" / str(int(uid)) / "home"
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    for p in (home.parent, home, home / ".ssh"):
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    cfg = home / ".ssh" / "config"
    if not cfg.exists():
        cfg.touch(mode=0o600)
    return str(home)


def _multiplex(cdir: str) -> list[str]:
    return ["-o", "ControlMaster=auto", "-o", f"ControlPath={os.path.join(cdir, '%C')}",
            "-o", "ControlPersist=60"]


def harden(argv: list[str], home: str, cdir: str) -> str:
    """The command a restricted user's ssh runs. Options given first win in ssh, and the user
    can no longer pass any of these themselves (validate_ssh refuses them)."""
    ssh = os.path.join(home, ".ssh")
    forced = ["-F", os.path.join(ssh, "config"), "-e", "none",
              "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
              "-o", f"IdentityFile={os.path.join(ssh, 'id_ed25519')}",
              "-o", f"UserKnownHostsFile={os.path.join(ssh, 'known_hosts')}",
              "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes",
              "-o", "ForwardAgent=no", "-o", "ForwardX11=no"]
    return shlex.join([argv[0], *forced, *_multiplex(cdir), *argv[1:]])


def with_own_multiplexing(command: str, cdir: str) -> str:
    """An ssh command with the user's own ControlPath (a shell user's ssh pane), else unchanged."""
    try:
        argv = shlex.split(command or "")
    except ValueError:
        return command
    if not argv or os.path.basename(argv[0]) != "ssh":
        return command
    joined = " ".join(argv).lower()
    if "controlmaster" in joined or "controlpath" in joined or any(a.startswith("-S") for a in argv[1:]):
        return command
    return shlex.join([argv[0], *_multiplex(cdir), *argv[1:]])


_SECRET_ARG = re.compile(r"(?i)(--?[\w.-]*(?:pass(?:word|wd|phrase)?|secret|token|api[-_]?key|auth)[\w.-]*)(=|\s+)(\"[^\"]*\"|'[^']*'|\S+)")
_URL_CRED = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+):[^@\s/]+@")
_USER_PASS = re.compile(r"(\s(?:-u|--user)(?:=|\s+))([^:\s]+):\S+")
_ENV_SECRET = re.compile(r"(?i)\b([A-Z0-9_]*(?:PASS(?:WORD)?|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*)=(\S+)")


def redact(command: str) -> str:
    """A command line fit for the audit log: values of password / secret / token arguments,
    credentials in URLs and secret-looking environment assignments replaced by ****."""
    out = _SECRET_ARG.sub(lambda m: f"{m.group(1)}{m.group(2)}****", command or "")
    out = _URL_CRED.sub(r"\1:****@", out)
    out = _USER_PASS.sub(r"\1\2:****", out)
    out = _ENV_SECRET.sub(r"\1=****", out)
    return out[:1000]
