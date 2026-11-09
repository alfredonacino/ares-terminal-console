"""
Running a read-only script on the server an SSH pane is connected to.

THE PROBLEM

The analysis tools (health, performance, logs, packages, vulnerabilities) each
run a script on the far side. They need a channel to that server, and the
obvious one -- a second `ssh` login -- is the wrong answer for exactly the
servers people use this on: one behind a password, a one-time code or a
hardware key would ask again, from a process with no terminal to ask in.

THE ANSWER: SHARE THE PANE'S CONNECTION

OpenSSH multiplexes. A pane started with `ssh ...` is given

    -o ControlMaster=auto -o ControlPath=~/.ssh/ares-tc/%C -o ControlPersist=60

so the login typed into the pane becomes a master connection with a socket
beside it, and every probe is one more channel over that socket: no second
login, no second prompt, and nothing the pane's own session sees. `%C` is a
hash of the local host, the remote host, the port and the user, so two panes
to one server share a master, and two servers never do.

What is not changed: a command that already names ControlMaster, ControlPath
or -S keeps its own choice, and on Windows -- whose OpenSSH has no
multiplexing -- nothing is added at all. There, and whenever no master is up,
a probe connects on its own with BatchMode, which works with keys and an agent
and fails cleanly (rather than hanging on a prompt) without them.

The socket directory is under ~/.ssh rather than the data folder because a
Unix socket path is limited to about 104 bytes, and "~/Library/Application
Support/ARES Terminal Console/" has already spent most of them.
"""

import os
import shlex
import subprocess
import sys
import threading
import time

# ssh options that take an argument (OpenSSH 9.x `ssh -h`). Needed to find
# where the options end and the destination begins.
_WITH_ARG = set("BbcDEeFIiJLlmOoPpQRSWw")

PROBE_TIMEOUT = 240          # a whole inventory of a big server can take a while
CONNECT_TIMEOUT = 15


def multiplexing() -> bool:
    return os.name != "nt"


def control_dir() -> str:
    path = os.path.join(os.path.expanduser("~"), ".ssh", "ares-tc")
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def control_path() -> str:
    return os.path.join(control_dir(), "%C")


def _split(command: str) -> list:
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return []


def parse(command: str):
    """The SSH target of a pane's command, or None when it is not `ssh ...`.

    Returns {"options": [...], "destination": "user@host", "port": "",
    "remote": [...]} -- options exactly as given, so a probe connects the way
    the pane did (same -i, -J, -p, -o, config).
    """
    argv = _split(command)
    if not argv:
        return None
    if os.path.basename(argv[0]).lower() not in ("ssh", "ssh.exe"):
        return None
    options, i, port, user = [], 1, "", ""
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        options.append(a)
        flag = a[1:]
        # -p2222 and -p 2222 both occur; so do combined flags like -tt or -vA.
        for j, ch in enumerate(flag):
            if ch in _WITH_ARG:
                value = flag[j + 1:]
                if not value:
                    i += 1
                    if i >= len(argv):
                        return None
                    value = argv[i]
                    options.append(value)
                if ch == "p":
                    port = value
                elif ch == "l":
                    user = value
                break
        i += 1
    if i >= len(argv):
        return None                     # `ssh -V`, `ssh -G` and the like
    destination = argv[i]
    return {"options": options, "destination": destination, "port": port,
            "user": user, "remote": argv[i + 1:], "ssh": argv[0]}


def _has_own_multiplexing(options: list) -> bool:
    joined = " ".join(options).lower()
    return ("controlmaster" in joined or "controlpath" in joined
            or any(o == "-S" or o.startswith("-S") for o in options))


def pane_argv(command: str):
    """The argv a pane should run for this command, or None to leave it alone.

    Only an `ssh` command is touched, and only to add multiplexing.
    """
    target = parse(command)
    if not target or not multiplexing() or _has_own_multiplexing(target["options"]):
        return None
    argv = _split(command)
    return [argv[0], "-o", "ControlMaster=auto", "-o", f"ControlPath={control_path()}",
            "-o", "ControlPersist=60"] + argv[1:]


def strip_ours(argv: list) -> list:
    """argv without the multiplexing options this app adds (pane_argv, and the
    ssh wrapper on a local pane's PATH), so a probe built from a running ssh
    is the plain command the user typed: Runner adds ControlMaster=no itself."""
    ours = {"ControlMaster=auto", f"ControlPath={control_path()}", "ControlPersist=60"}
    out, i = [], 0
    while i < len(argv):
        if argv[i] == "-o" and i + 1 < len(argv) and argv[i + 1] in ours:
            i += 2
            continue
        out.append(argv[i])
        i += 1
    return out


def label(target: dict) -> str:
    dest = target["destination"]
    if target.get("user") and "@" not in dest:
        dest = f"{target['user']}@{dest}"
    return dest + (f":{target['port']}" if target.get("port") else "")


class Runner:
    """`run_input` and `stream_input` for the probes, over one SSH target."""

    def __init__(self, target: dict):
        self.target = target

    def argv(self, remote_command: str) -> list:
        base = [self.target.get("ssh") or "ssh", "-T",
                "-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
                "-o", "LogLevel=ERROR"]
        opts = [o for o in self.target["options"] if o not in ("-t", "-tt")]
        if multiplexing() and not _has_own_multiplexing(opts):
            # ControlMaster=no: use the pane's master if it is up, otherwise
            # connect alone. Never become a master here -- a probe that did
            # would hold the connection open after the pane closed.
            base += ["-o", "ControlMaster=no", "-o", f"ControlPath={control_path()}"]
        return base + opts + [self.target["destination"], remote_command]

    def _popen(self, remote_command: str):
        flags = 0x08000000 if os.name == "nt" else 0          # CREATE_NO_WINDOW
        return subprocess.Popen(self.argv(remote_command), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=flags)

    def run_input(self, command: str, stdin: str, timeout: float = PROBE_TIMEOUT):
        """(status, stdout, stderr) of `command` with `stdin` fed to it."""
        proc = self._popen(command)
        try:
            out, err = proc.communicate((stdin or "").encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            err += b"\n(timed out after %d s)" % timeout
        return proc.returncode, out.decode("utf-8", "replace"), _clean(err)

    def stream_input(self, command: str, stdin: str, on_output, cancel: threading.Event,
                     timeout: float):
        """Like run_input, but output arrives as it is produced -- the long
        performance check reports progress -- and `cancel` stops it."""
        proc = self._popen(command)
        try:
            proc.stdin.write((stdin or "").encode())
            proc.stdin.close()
        except OSError:
            pass
        err_chunks = []
        threading.Thread(target=lambda: err_chunks.append(proc.stderr.read()),
                         daemon=True).start()
        deadline = time.monotonic() + timeout
        stopper = threading.Thread(target=self._watch, args=(proc, cancel, deadline), daemon=True)
        stopper.start()
        while True:
            chunk = proc.stdout.read1(65536) if hasattr(proc.stdout, "read1") else proc.stdout.read(4096)
            if not chunk:
                break
            on_output(chunk.decode("utf-8", "replace"))
        proc.wait()
        code = -1 if cancel.is_set() else proc.returncode
        return code, _clean(b"".join(c for c in err_chunks if c))

    @staticmethod
    def _watch(proc, cancel, deadline):
        while proc.poll() is None:
            if cancel.is_set() or time.monotonic() > deadline:
                proc.terminate()
                return
            time.sleep(0.3)


class LocalRunner(Runner):
    """The same probes on this computer, for a pane that is not `ssh ...`.

    A probe is a command line plus a script on stdin, so the only difference
    is who runs it: the local shell instead of the far side of an SSH
    channel. On Windows that shell is cmd.exe, where `sh -s` fails and the
    probes fall back to their PowerShell form exactly as on a Windows server.
    """

    def __init__(self):
        super().__init__({"options": [], "destination": "localhost"})

    def argv(self, remote_command: str):
        return remote_command

    def _popen(self, remote_command: str):
        flags = 0x08000000 if os.name == "nt" else 0          # CREATE_NO_WINDOW
        return subprocess.Popen(remote_command, shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=flags)


HOST_KEY_SCRIPT = r"""
for k in ed25519 ecdsa rsa; do
  f=/etc/ssh/ssh_host_${k}_key.pub
  if [ -r "$f" ]; then cat "$f"; exit 0; fi
done
"""


def host_key_fingerprint(runner: "Runner") -> str:
    """The server's SSH host key as `SHA256:...`, the way ssh-keygen -l
    prints it. Read from the public key file, which every user may read, so
    a machine that will say nothing else about itself still has an identity."""
    import base64
    import hashlib
    try:
        code, out, _ = runner.run_input("sh -s", HOST_KEY_SCRIPT)
    except OSError:
        return ""
    parts = out.split()
    if len(parts) < 2:
        return ""
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        return ""
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _clean(err: bytes) -> str:
    text = err.decode("utf-8", "replace")
    lines = [l for l in text.splitlines() if l.strip()
             and "post-quantum" not in l and "store now, decrypt later" not in l
             and "openssh.com/pq.html" not in l]
    return "\n".join(lines)


def explain(error: str) -> str:
    """A probe failure in words that say what to do about it."""
    low = (error or "").lower()
    if "permission denied" in low or "batchmode" in low or "authentication" in low:
        how = ("open it in a pane first and log in there -- the tools reuse that login"
               if multiplexing() else
               "use a key or an agent: on Windows the tools cannot reuse a pane's login")
        return f"The tools could not log in to the server on their own: {how}."
    if "could not resolve" in low or "connection refused" in low or "timed out" in low:
        return f"The server could not be reached: {error.strip()[:200]}"
    return error.strip()[:300] or "The server did not answer."
