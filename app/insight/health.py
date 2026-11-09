"""Health & processes: a live reading of a server, the way ARES Server Guardian
shows the machine it runs on.

Server Guardian is an agent: it runs on the server and asks psutil every ten
seconds. ARES is not on the server, so the same numbers are read from /proc
over a channel of the session's own connection, one probe per sample, and
everything psutil would have worked out - a CPU percentage, a process's share
of a core, bytes per second - is worked out here from the difference between
two probes. The thresholds, the overall status, the sustained-for-30-seconds
rule and the per-process limits are Guardian's own defaults (its
``config.py``), so a server reads the same in both.

What the sample holds, and where it comes from:

=================  =========================================================
CPU %              ``/proc/stat``'s first line, busy = total - idle - iowait,
                   over the time since the previous sample
Memory             ``/proc/meminfo``, used = MemTotal - MemAvailable
Swap               ``/proc/meminfo``, SwapTotal - SwapFree
Load               ``/proc/loadavg``
Uptime             ``/proc/uptime``
Network            ``/proc/net/dev``, every physical interface summed. Guardian
                   sums psutil's counters, which include ``lo``; loopback and
                   bridges are left out here because they count the same
                   packet twice
Disks              ``df -Pk``, without the pseudo filesystems Guardian skips
Processes          ``/proc/[pid]/stat`` - state, CPU ticks, threads, RSS and
                   start time, so a reused pid is a new process - with the
                   owner from ``ps``
Connections        ``/proc/net/tcp`` and ``tcp6``: inbound connections are the
                   established and half-open ones on a port this host listens on
=================  =========================================================

Read-only. The one thing that is not, :func:`stop_command`, is run only after
the operator has confirmed it, exactly as Guardian's Stop button.
"""
from __future__ import annotations

import ipaddress
import time
from collections import Counter
from dataclasses import dataclass, field

from .metrics import LOOPBACK, PSEUDO, PSEUDO_MOUNTS, human

#: Server Guardian's defaults, from its ``config.py`` ``[health]`` table.
DEFAULTS = {
    "interval_seconds": 10,
    "cpu_warn": 85.0,
    "mem_warn": 90.0,
    "disk_warn": 90.0,
    "load_warn_per_core": 2.0,
    "process_cpu_warn": 80.0,          # % of one core
    "process_mem_warn": 25.0,          # % of RAM
    "process_sustain_samples": 3,
}
SWAP_WARN = 80.0
DISK_CRITICAL = 97.0
ZOMBIE_WARN = 20
DEDUP_SECONDS = 1800
DEDUP_SECONDS_LONG = 3600
TOP_N = 15
#: Twenty-four hours at the default interval; the charts' memory.
HISTORY_POINTS = 8640

#: Guardian's `_PSEUDO_FS`: filesystems that are not storage.
PSEUDO_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "efivarfs",
             "devpts", "cgroup2", "fuse.portal", "fuse.gvfsd-fuse", "ramfs", "iso9660"}

#: Interfaces that carry another interface's packets a second time.
VIRTUAL_IF = ("veth", "docker", "br-", "virbr", "cni", "flannel", "vxlan", "kube")

# The awk that turns `cat /proc/[0-9]*/stat` into one short line a process.
# comm is in parentheses and may hold spaces and ")", so the line is split on
# the LAST ") " - the same reading as the performance check's sampler.
_PROC_AWK = r"""
{
  n = split($0, parts, ") ")
  if (n < 2) next
  rest = parts[n]
  head = substr($0, 1, length($0) - length(rest) - 2)
  i = index(head, " (")
  if (i == 0) next
  pid = substr(head, 1, i - 1)
  comm = substr(head, i + 2)
  m = split(rest, f, " ")
  if (m < 22) next
  if (pid == self || f[2] == self) next
  gsub(/[^ -~]/, "?", comm); gsub(/\|/, "/", comm)
  printf "%s|%s|%s|%.0f|%s|%s|%s|%s\n", pid, f[2], f[1], f[12] + f[13], f[18], f[22], f[20], comm
}
"""

PROBE = r"""[ -r /proc/stat ] || { echo '@@noproc'; uname -s 2>/dev/null; echo '@@end'; exit 0; }
SELF=$$
echo '@@clock'; cut -d' ' -f1 /proc/uptime; getconf CLK_TCK 2>/dev/null || echo 100
getconf PAGESIZE 2>/dev/null || echo 4096; grep -c '^processor' /proc/cpuinfo 2>/dev/null
echo '@@hostname'; hostname 2>/dev/null
echo '@@loadavg'; cat /proc/loadavg
echo '@@cpu'; head -n 1 /proc/stat
echo '@@meminfo'; cat /proc/meminfo
echo '@@netdev'; cat /proc/net/dev 2>/dev/null
echo '@@df'; df -Pk 2>/dev/null
echo '@@mounts'; cat /proc/mounts 2>/dev/null
echo '@@tcp'; cat /proc/net/tcp /proc/net/tcp6 2>/dev/null
echo '@@procs'; cat /proc/[0-9]*/stat 2>/dev/null | awk -v self="$SELF" '""" + _PROC_AWK + r"""'
echo '@@users'; ps -eo pid=,user= 2>/dev/null || ps -o pid,user 2>/dev/null
echo '@@end'
"""
assert "'" not in _PROC_AWK


class HealthError(Exception):
    pass


def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = ""
    for line in (text or "").splitlines():
        if line.startswith("@@"):
            current = line[2:].strip()
            out.setdefault(current, [])
        elif current:
            out[current].append(line.rstrip("\r"))
    return out


def _int(text, default: int = 0) -> int:
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ reading --

@dataclass
class Reading:
    """One probe, as the server printed it, before any rate is worked out."""

    uptime: float = 0.0
    clk: int = 100
    page: int = 4096
    ncpu: int = 1
    hostname: str = ""
    load: tuple[float, float, float] = (0.0, 0.0, 0.0)
    cpu: list[int] = field(default_factory=list)
    mem: dict[str, int] = field(default_factory=dict)        # kB
    net: dict[str, tuple[int, int]] = field(default_factory=dict)
    disks: list[dict] = field(default_factory=list)
    connections: dict = field(default_factory=dict)
    # pid -> (ppid, state, ticks, threads, rss pages, start time, comm)
    procs: dict[str, tuple] = field(default_factory=dict)
    users: dict[str, str] = field(default_factory=dict)
    monotonic: float = 0.0


def parse(text: str) -> Reading:
    """A probe's output. Raises HealthError on a server without /proc."""
    s = _sections(text)
    if "noproc" in s:
        system = next((l.strip() for l in s["noproc"] if l.strip()), "this system")
        raise HealthError(f"Health & processes reads /proc, which {system} does not have. "
                          "Server Guardian is Linux-only for the same reason.")
    if "clock" not in s:
        raise HealthError("the server did not answer the health probe")
    r = Reading(monotonic=time.monotonic())
    clock = [l.strip() for l in s.get("clock", [])] + ["", "", "", ""]
    try:
        r.uptime = float(clock[0])
    except ValueError:
        r.uptime = 0.0
    r.clk = _int(clock[1], 100) or 100
    r.page = _int(clock[2], 4096) or 4096
    r.ncpu = _int(clock[3], 1) or 1
    r.hostname = next((l.strip() for l in s.get("hostname", []) if l.strip()), "")
    load = (s.get("loadavg") or [""])[0].split()
    if len(load) >= 3:
        try:
            r.load = (float(load[0]), float(load[1]), float(load[2]))
        except ValueError:
            pass
    cpu = (s.get("cpu") or [""])[0].split()
    if cpu and cpu[0] == "cpu":
        r.cpu = [_int(v) for v in cpu[1:]]
    for line in s.get("meminfo", []):
        name, _, rest = line.partition(":")
        value = rest.split()
        if value and value[0].isdigit():
            r.mem[name.strip()] = int(value[0])
    for line in s.get("netdev", []):
        name, sep, rest = line.partition(":")
        values = rest.split()
        if sep and len(values) >= 9:
            r.net[name.strip()] = (_int(values[0]), _int(values[8]))
    r.disks = _disks(s.get("df", []), s.get("mounts", []))
    r.connections = parse_tcp(s.get("tcp", []))
    for line in s.get("procs", []):
        f = line.split("|", 7)
        if len(f) == 8 and f[0].isdigit():
            r.procs[f[0]] = (f[1], f[2], _int(f[3]), _int(f[4]), _int(f[5]), f[6], f[7])
    for line in s.get("users", []):
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            r.users[parts[0]] = parts[1]
    return r


def _disks(df: list[str], mounts: list[str]) -> list[dict]:
    """Every real filesystem once, as Guardian's `disk_usage` lists them."""
    fstype = {}
    for line in mounts:
        parts = line.split()
        if len(parts) >= 3:
            fstype[parts[1].replace("\\040", " ")] = parts[2]
    out, devices = [], set()
    for line in df[1:]:
        parts = line.split()
        if len(parts) < 6 or not parts[1].isdigit() or not parts[2].isdigit() \
                or not parts[3].isdigit():
            continue
        device, mount = parts[0], " ".join(parts[5:])
        kind = fstype.get(mount, "")
        if kind in PSEUDO_FS or device in PSEUDO or device.split("/")[-1] in PSEUDO:
            continue
        if LOOPBACK.match(device) or any(mount == p or mount.startswith(p + "/")
                                         for p in PSEUDO_MOUNTS):
            continue
        if mount.startswith("/etc/"):        # a container's bind-mounted file
            continue
        total, used, avail = int(parts[1]) * 1024, int(parts[2]) * 1024, int(parts[3]) * 1024
        if total <= 0 or device in devices:
            continue
        devices.add(device)
        # psutil's percent, which is df's: used over what a user could have.
        percent = round(100.0 * used / (used + avail), 1) if used + avail else 0.0
        out.append({"mount": mount, "device": device, "fstype": kind, "total": total,
                    "used": used, "percent": percent})
    out.sort(key=lambda d: (d["mount"] != "/", d["mount"]))
    return out


# -------------------------------------------------------------- connections --

_TCP_STATES = {"01": "established", "03": "syn_recv", "0A": "listen", "06": "time_wait"}


def _hex_address(text: str) -> tuple[str, int]:
    """`0100007F:1F90` -> ("127.0.0.1", 8080), IPv4 or IPv6, as /proc prints them."""
    address, _, port = text.partition(":")
    try:
        number = int(port, 16)
        raw = bytes.fromhex(address)
    except ValueError:
        return "", 0
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1])), number
    if len(raw) == 16:
        # Four 32-bit words, each in the host's (little-endian) order.
        words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        ip = ipaddress.IPv6Address(words)
        return str(ip.ipv4_mapped or ip), number
    return "", 0


def parse_tcp(lines: list[str]) -> dict:
    """Guardian's ConnectionMonitor summary, from /proc/net/tcp and tcp6."""
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or not parts[0].endswith(":") or parts[1] == "local_address":
            continue
        rows.append((_hex_address(parts[1]), _hex_address(parts[2]),
                     _TCP_STATES.get(parts[3].upper(), "")))
    listening = sorted({local[1] for local, _, state in rows if state == "listen"})
    ports = set(listening)
    established = syn_recv = 0
    by_ip: Counter = Counter()
    by_port: Counter = Counter()
    for local, remote, state in rows:
        if local[1] not in ports or state not in ("established", "syn_recv"):
            continue
        if state == "established":
            established += 1
        else:
            syn_recv += 1
        by_ip[remote[0]] += 1
        by_port[local[1]] += 1
    return {"established": established, "syn_recv": syn_recv, "unique_ips": len(by_ip),
            "listening_ports": listening, "top_ips": by_ip.most_common(10),
            "by_port": by_port.most_common(10), "measured": bool(lines)}


# ------------------------------------------------------------------- sample --

@dataclass
class Alert:
    key: str
    severity: str              # critical | high | medium | low
    title: str
    message: str
    ts: float


@dataclass
class Sample:
    """One reading, with every rate worked out against the one before."""

    ts: float
    hostname: str
    uptime: float
    ncpu: int
    cpu: float
    mem: float
    mem_total: int
    mem_used: int
    swap: float
    swap_total: int
    swap_used: int
    load: tuple[float, float, float]
    disks: list[dict]
    disk: float
    net_rx: float              # bytes per second
    net_tx: float
    proc_count: int
    zombies: int
    top_cpu: list[dict]
    top_mem: list[dict]
    connections: dict
    status: str = "unknown"
    alerts: list[Alert] = field(default_factory=list)


def _is_virtual(name: str) -> bool:
    return name == "lo" or name.startswith(VIRTUAL_IF)


def _cpu_percent(a: list[int], b: list[int]) -> float:
    if not a or not b:
        return 0.0
    a, b = a + [0] * 10, b + [0] * 10
    d = [max(0, b[k] - a[k]) for k in range(8)]
    total = sum(d)
    return round(100.0 * (total - d[3] - d[4]) / total, 1) if total else 0.0


def status(sample: Sample | None, cfg: dict | None = None) -> str:
    """Guardian's `health_status`: healthy, degraded or unknown."""
    cfg = cfg or DEFAULTS
    if sample is None:
        return "unknown"
    if sample.cpu >= cfg["cpu_warn"] or sample.mem >= cfg["mem_warn"] \
            or sample.disk >= cfg["disk_warn"]:
        return "degraded"
    return "healthy"


def level(value: float, warn: float, bad: float) -> str:
    """Guardian's `level()`: the colour of a meter, ok, warn or bad."""
    return "bad" if value >= bad else "warn" if value >= warn else "ok"


#: Each meter's (warn, bad), as Guardian's health page draws them.
def meter_levels(cfg: dict | None = None) -> dict[str, tuple[float, float]]:
    cfg = cfg or DEFAULTS
    return {"cpu": (cfg["cpu_warn"] - 15, cfg["cpu_warn"]),
            "mem": (cfg["mem_warn"] - 15, cfg["mem_warn"]),
            "swap": (50.0, SWAP_WARN),
            "disk": (cfg["disk_warn"] - 10, cfg["disk_warn"])}


class HealthMonitor:
    """Guardian's HealthMonitor, fed by probes instead of psutil.

    `step(reading)` turns a reading into a :class:`Sample` against the one
    before it, raises the sustained alerts, and keeps the history the charts
    draw. The first reading only primes it - a rate needs two - and returns
    None.
    """

    def __init__(self, cfg: dict | None = None):
        self.cfg = dict(DEFAULTS, **(cfg or {}))
        self.previous: Reading | None = None
        self.latest: Sample | None = None
        self.history: list[dict] = []
        self.alerts: list[Alert] = []
        self._counters: dict[str, int] = {}
        self._proc_counters: dict[tuple[str, str], int] = {}
        self._raised: dict[str, float] = {}

    def step(self, reading: Reading, now: float | None = None) -> Sample | None:
        now = time.time() if now is None else now
        before, self.previous = self.previous, reading
        if before is None:
            return None
        elapsed = reading.uptime - before.uptime
        if elapsed <= 0:
            elapsed = max(0.001, reading.monotonic - before.monotonic)
        mem = reading.mem
        total = mem.get("MemTotal", 0)
        available = mem.get("MemAvailable", mem.get("MemFree", 0) + mem.get("Cached", 0))
        swap_total = mem.get("SwapTotal", 0)
        swap_used = swap_total - mem.get("SwapFree", 0)
        rx = tx = 0.0
        for name, (r_now, t_now) in reading.net.items():
            if _is_virtual(name) or name not in before.net:
                continue
            r_was, t_was = before.net[name]
            if r_now >= r_was and t_now >= t_was:
                rx += (r_now - r_was) / elapsed
                tx += (t_now - t_was) / elapsed
        rows = self._processes(before, reading, elapsed, total * 1024)
        sample = Sample(
            ts=now, hostname=reading.hostname, uptime=reading.uptime, ncpu=reading.ncpu,
            cpu=_cpu_percent(before.cpu, reading.cpu),
            mem=round(100.0 * (total - available) / total, 1) if total else 0.0,
            mem_total=total * 1024, mem_used=(total - available) * 1024,
            swap=round(100.0 * swap_used / swap_total, 1) if swap_total else 0.0,
            swap_total=swap_total * 1024, swap_used=swap_used * 1024,
            load=reading.load, disks=reading.disks,
            disk=max((d["percent"] for d in reading.disks), default=0.0),
            net_rx=rx, net_tx=tx, proc_count=len(reading.procs),
            zombies=sum(1 for p in reading.procs.values() if p[1] == "Z"),
            top_cpu=sorted(rows, key=lambda r: -r["cpu"])[:TOP_N],
            top_mem=sorted(rows, key=lambda r: -r["mem"])[:TOP_N],
            connections=reading.connections)
        sample.status = status(sample, self.cfg)
        sample.alerts = self._check_system(sample) + self._check_processes(sample)
        self.alerts = (sample.alerts + self.alerts)[:50]
        self.latest = sample
        self.history.append({"ts": now, "cpu": sample.cpu, "mem": sample.mem,
                             "swap": sample.swap, "disk": sample.disk,
                             "load1": sample.load[0], "net_rx": rx, "net_tx": tx,
                             "conns": sample.connections.get("established", 0),
                             "syn_recv": sample.connections.get("syn_recv", 0),
                             "procs": sample.proc_count})
        del self.history[:-HISTORY_POINTS]
        return sample

    def _processes(self, before: Reading, now: Reading, elapsed: float,
                   mem_total: int) -> list[dict]:
        """psutil's process rows: CPU as a share of ONE core, so 200% is two."""
        rows = []
        for pid, (ppid, state, ticks, threads, rss, start, comm) in now.procs.items():
            was = before.procs.get(pid)
            cpu = 0.0
            if was is not None and was[5] == start:          # same process, not a reused pid
                cpu = 100.0 * max(0, ticks - was[2]) / (now.clk * elapsed)
            rss_bytes = rss * now.page
            rows.append({"pid": int(pid), "ppid": _int(ppid), "name": comm,
                         "user": now.users.get(pid, ""), "cpu": round(cpu, 1),
                         "cpu_total": round(cpu / max(now.ncpu, 1), 1),
                         "mem": round(100.0 * rss_bytes / mem_total, 2) if mem_total else 0.0,
                         "rss": rss_bytes, "status": _STATES.get(state, state),
                         "threads": threads})
        return rows

    # ------------------------------------------------------------ alerts --
    def _raise(self, key: str, severity: str, title: str, message: str,
               dedup: float, now: float) -> list[Alert]:
        if now - self._raised.get(key, -1e18) < dedup:
            return []
        self._raised[key] = now
        return [Alert(key, severity, title, message, now)]

    def _sustained(self, key: str, bad: bool) -> bool:
        if not bad:
            self._counters[key] = 0
            return False
        self._counters[key] = self._counters.get(key, 0) + 1
        return self._counters[key] >= self.cfg["process_sustain_samples"]

    def _check_system(self, s: Sample) -> list[Alert]:
        """Guardian's `_check_system`: each must hold for three samples."""
        cfg, out = self.cfg, []
        top = ", ".join(f"{p['name']}({p['pid']}) {p['cpu']:.0f}%" for p in s.top_cpu[:3])
        tail = f" Top CPU processes: {top}." if top else ""
        checks = [
            ("cpu", s.cpu >= cfg["cpu_warn"], "high", "CPU",
             f"CPU at {s.cpu:.0f}% (threshold {cfg['cpu_warn']:.0f}%)."),
            ("mem", s.mem >= cfg["mem_warn"], "high", "memory",
             f"Memory at {s.mem:.0f}% (threshold {cfg['mem_warn']:.0f}%)."),
            ("load", s.load[0] >= cfg["load_warn_per_core"] * s.ncpu, "medium", "load",
             f"Load {s.load[0]:.2f} on {s.ncpu} core(s)."),
            ("swap", s.swap >= SWAP_WARN, "medium", "swap", f"Swap at {s.swap:.0f}%."),
        ]
        for d in s.disks:
            checks.append((f"disk:{d['mount']}", d["percent"] >= cfg["disk_warn"],
                           "critical" if d["percent"] >= DISK_CRITICAL else "high",
                           f"disk {d['mount']}", f"{d['mount']} is {d['percent']:.0f}% full."))
        for key, bad, severity, metric, message in checks:
            if self._sustained(key, bad):
                out += self._raise(key, severity, f"Server overload: {metric}",
                                   message + tail, DEDUP_SECONDS, s.ts)
        if s.zombies > ZOMBIE_WARN:
            out += self._raise("zombies", "low", "Server overload: zombies",
                               f"{s.zombies} zombie processes.", DEDUP_SECONDS_LONG, s.ts)
        return out

    def _check_processes(self, s: Sample) -> list[Alert]:
        """Guardian's `_check_processes`: a process hot for three samples running."""
        cfg, out, hot = self.cfg, [], set()
        rows = {r["pid"]: r for r in s.top_cpu + s.top_mem}
        for pid, r in rows.items():
            for metric, value, limit, unit in (
                    ("cpu", r["cpu"], cfg["process_cpu_warn"], "of one core"),
                    ("mem", r["mem"], cfg["process_mem_warn"], "of RAM")):
                if value < limit:
                    continue
                key = (str(pid), metric)
                hot.add(key)
                self._proc_counters[key] = self._proc_counters.get(key, 0) + 1
                if self._proc_counters[key] == cfg["process_sustain_samples"]:
                    seconds = cfg["process_sustain_samples"] * cfg["interval_seconds"]
                    out += self._raise(
                        f"proc:{pid}:{metric}", "medium",
                        f"Overloading process: {r['name']} (PID {pid})",
                        f"{r['name']} (PID {pid}, user {r['user'] or '?'}) is using "
                        f"{value:.0f}% {unit} for {seconds}s+.", DEDUP_SECONDS_LONG, s.ts)
        for key in list(self._proc_counters):
            if key not in hot:
                del self._proc_counters[key]
        return out


#: /proc's one-letter states, in the words psutil uses.
_STATES = {"R": "running", "S": "sleeping", "D": "disk-sleep", "Z": "zombie",
           "T": "stopped", "t": "tracing-stop", "I": "idle", "X": "dead", "W": "paging",
           "P": "parked", "K": "wakekill"}


def stop_command(pid: int, force: bool = False) -> str:
    """Guardian's `terminate_process`, as a command line: SIGTERM, or SIGKILL.

    Refuses pid 1 and below, as Guardian does. The pid is an int, so nothing
    else can reach the command line.
    """
    pid = int(pid)
    if pid <= 1:
        raise HealthError("refusing to signal this process")
    return f"kill -{'KILL' if force else 'TERM'} {pid}"


def uptime_text(seconds: float) -> str:
    seconds = int(seconds or 0)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def rate_text(bytes_per_second: float) -> str:
    return f"{human(bytes_per_second)}/s"


def probe(run_input) -> Reading:
    """One reading over `run_input(command, stdin)`."""
    status_code, out, err = run_input("sh -s", PROBE)
    if "@@" not in out:
        detail = (err or out or f"exit status {status_code}").strip().splitlines()
        raise HealthError("Health & processes reads /proc through a POSIX shell, and this "
                          "server ran neither - a Windows server, say. It said: "
                          + (detail[0][:200] if detail else "nothing"))
    return parse(out)
