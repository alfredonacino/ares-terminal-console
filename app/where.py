"""
Where a pane is: the host, its address, and the directory its shell is in.

Shown in each pane's title bar, so it has to be cheap, never block a pane,
and never need anything set up in somebody's shell.

LOCAL PANES

The host and address are this machine's. The directory is the working
directory of the terminal's *foreground* process group -- the shell while it
waits for a command, the program while one runs -- read from /proc on Linux
and from lsof on macOS. If that foreground process is `ssh`, the pane is a
local shell that has hopped somewhere else, and the destination is reported
instead of a local directory that no longer means anything.

SSH PANES

Asked of the server, over the pane's own multiplexed connection (see
remote.py), by REMOTE_SCRIPT. On a multiplexed connection one sshd process
serves every channel, so the probe walks up to that sshd and looks at its
other children: the one holding a terminal is the pane's shell, and the
terminal's foreground group gives the directory. Two panes to one server share
a master, and then the terminal typed into most recently is taken. A probe that
had to connect on its own (no master) finds no such shell and reports host and
address only -- which is the honest answer.

A shell that reports its directory itself (OSC 7) is believed first by the UI;
this is the fallback that works with a stock shell.
"""

import os
import socket
import subprocess
import sys

REMOTE_SCRIPT = r"""
h=$(hostname 2>/dev/null || uname -n 2>/dev/null)
ip=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$ip" ] || ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/,"",$4); print $4; exit}')
[ -n "$ip" ] || ip=$(ifconfig 2>/dev/null | awk '/inet /{a=$2; sub("addr:","",a); if (a!="127.0.0.1") {print a; exit}}')
echo "host=$h"
echo "ip=$ip"
echo "user=$(id -un 2>/dev/null)"
[ -r /proc/$$/stat ] || exit 0
p=$$; sshd=
while [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null; do
  case "$(cat /proc/$p/comm 2>/dev/null)" in sshd*) sshd=$p; break;; esac
  p=$(sed 's/.*) //' /proc/$p/stat 2>/dev/null | awk '{print $2}')
done
[ -n "$sshd" ] || exit 0
best=; bt=-1; fg=
for line in $(awk -v s="$sshd" '{f=FILENAME; sub(/^\/proc\//,"",f); sub(/\/stat$/,"",f);
                                   sub(/.*\) /,""); if ($2==s && $5!=0) print f ":" $6}' /proc/[0-9]*/stat 2>/dev/null); do
  pid=${line%%:*}; grp=${line#*:}
  t=$(readlink /proc/$pid/fd/0 2>/dev/null)
  m=$(stat -c %Y "$t" 2>/dev/null || echo 0)
  if [ "$m" -gt "$bt" ]; then best=$pid; bt=$m; fg=$grp; fi
done
[ -n "$best" ] || exit 0
cwd=$(readlink /proc/$fg/cwd 2>/dev/null)
[ -n "$cwd" ] || cwd=$(readlink /proc/$best/cwd 2>/dev/null)
echo "cwd=$cwd"
"""

_local_ip = None


def local_host() -> str:
    try:
        return socket.gethostname().split(".")[0]
    except OSError:
        return ""


def local_ip() -> str:
    """The address this machine would use to reach the outside. Connecting a
    UDP socket sends nothing; it only asks the routing table."""
    global _local_ip
    if _local_ip is None:
        _local_ip = ""
        for probe in ("192.0.2.1", "10.255.255.255"):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((probe, 9))
                    _local_ip = s.getsockname()[0]
                    break
            except OSError:
                continue
    return _local_ip


def _foreground(session) -> int:
    fd = getattr(session, "fd", None)
    if fd is None or os.name == "nt":
        return session.pid or 0
    try:
        return os.tcgetpgrp(fd)
    except OSError:
        return session.pid or 0


def _cwd_of(pid: int) -> str:
    if not pid:
        return ""
    if sys.platform.startswith("linux"):
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return ""
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                                 capture_output=True, text=True, timeout=3).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        for line in out.splitlines():
            if line.startswith("n"):
                return line[1:]
    return ""


def _argv_of(pid: int) -> list:
    if not pid:
        return []
    if sys.platform.startswith("linux"):
        try:
            raw = open(f"/proc/{pid}/cmdline", "rb").read()
        except OSError:
            return []
        return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                                 capture_output=True, text=True, timeout=3).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        return out.split()
    return []


def hop_command(session, fg: int = 0) -> str:
    """The `ssh ...` a local pane's shell is running in the foreground, as a
    command line, or "" when it is not running one. This is what the server
    tools follow: type `ssh host` in a local pane and they work on that host."""
    from app import remote
    argv = _argv_of(fg or _foreground(session))
    if not argv or os.path.basename(argv[0]).lower() not in ("ssh", "ssh.exe"):
        return ""
    import shlex
    command = " ".join(shlex.quote(a) for a in remote.strip_ours(argv))
    return command if remote.parse(command) else ""


def local(session) -> dict:
    """Where a pane running on this machine is."""
    from app import remote
    out = {"host": local_host(), "ip": local_ip(), "cwd": "", "remote": False,
           "user": os.environ.get("USER") or os.environ.get("USERNAME") or ""}
    fg = _foreground(session)
    hop = hop_command(session, fg)
    if hop:
        target = remote.parse(hop)
        if target:
            # The shell has hopped: the local directory is beside the point.
            dest = remote.label(target)
            user, _, host = dest.rpartition("@")
            out.update(host=host.split(":")[0], ip="", user=user, hop=dest, remote=True)
            return out
    out["cwd"] = _cwd_of(fg) or _cwd_of(session.pid) or getattr(session, "cwd", "")
    return out


def parse_remote(text: str) -> dict:
    out = {"host": "", "ip": "", "cwd": "", "user": "", "remote": True}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in out:
            out[key] = value.strip()
    return out
