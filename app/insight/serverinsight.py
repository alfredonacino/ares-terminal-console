"""Who a server is, how it is coping, and what its logs are complaining about.

Three probes, each one round trip over a connection that is already open, and
each parsed here rather than on the far side - nothing is installed on a
server to be studied, and every parser can be tested against canned output.

Identity
--------
A server is not its address. An IP is reused, re-leased, NAT-ed and changed
on a migration, and the same machine reached through a tunnel and directly has
two of them. What stays with a machine is an identifier it keeps about itself,
so that is what the history is keyed on. In order of preference:

``machine-id``  ``/etc/machine-id`` (or dbus's copy). Written once per install
                and readable by every user, which matters: an identifier only
                root can read would give the same server two identities
                depending on who logged in.
``ioplatform``  macOS's ``IOPlatformUUID``.
``windows``     ``HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid``.
``hostuuid``    FreeBSD's ``kern.hostuuid``.
``dmi``         ``/sys/class/dmi/id/product_uuid`` - the firmware's own UUID,
                usually root-only, so it is a fallback rather than first.
``hostkey``     The SHA256 fingerprint of the SSH host key, when the machine
                will tell us nothing else (a switch, a busybox appliance).

The address, the hostname and the host key are kept beside the identity as
facts about it, not as what it is.

Performance and logs
--------------------
Both are read-only: ``cat`` of ``/proc``, ``ps``, ``df``, ``journalctl`` and
``grep`` over ``/var/log``. They see what the logged-in user can see, and say
so when files were out of reach rather than reporting a quiet server.

The scripts are sent on standard input to ``sh -s``. The login shell on the far
side might be fish or csh, and a script written for one shell and handed to
another as an argument fails in ways that look like a broken server.
"""
from __future__ import annotations

import base64
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from .metrics import LOOPBACK, PSEUDO, PSEUDO_MOUNTS, human, parse_df, parse_meminfo

#: ``(status, stdout, stderr)`` from a command with a script on its stdin.
RunInput = Callable[[str, str], tuple[int, str, str]]

SEVERITY_ORDER = {"ok": 0, "info": 1, "warn": 2, "crit": 3}


def worst(severities) -> str:
    """The most serious of a set of severities, ``ok`` for none."""
    best = "ok"
    for s in severities:
        if SEVERITY_ORDER.get(s, 0) > SEVERITY_ORDER[best]:
            best = s
    return best


def _sections(text: str) -> dict[str, list[str]]:
    """Split ``@@name`` labelled output into its parts."""
    out: dict[str, list[str]] = {}
    current = ""
    for line in (text or "").splitlines():
        if line.startswith("@@"):
            current = line[2:].strip()
            out.setdefault(current, [])
        elif current:
            out[current].append(line.rstrip("\r"))
    return out


def _first(lines: list[str] | None) -> str:
    for line in lines or []:
        if line.strip():
            return line.strip()
    return ""


def powershell(script: str) -> str:
    """A PowerShell command line that survives cmd.exe as the login shell.

    ``-EncodedCommand`` takes UTF-16LE base64, which has no quote or caret in
    it for cmd to reinterpret.
    """
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"


def run_script(run_input: RunInput, posix: str, windows: str = "",
               timeout_hint: str = "") -> tuple[str, str]:
    """Run the POSIX script, falling back to PowerShell on a Windows server.

    Returns ``(platform, output)`` where platform is ``posix`` or ``windows``.
    Raises ``RuntimeError`` with the far side's own words when neither ran.
    """
    status, out, err = run_input("sh -s", posix)
    if "@@" in out:
        return "posix", out
    if windows:
        status_w, out_w, err_w = run_input(powershell(windows), "")
        if "@@" in out_w:
            return "windows", out_w
        err = err or err_w
    detail = (err or out or f"exit status {status}").strip().splitlines()
    raise RuntimeError(
        f"the server did not run the probe{timeout_hint}: "
        f"{detail[0][:200] if detail else 'no output'}")


# ================================================================ identity ==

IDENTITY_POSIX = r"""
echo '@@machine_id'; cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null
echo '@@ioplatform'; ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}'
echo '@@hostuuid'; sysctl -n kern.hostuuid 2>/dev/null
echo '@@dmi'; cat /sys/class/dmi/id/product_uuid 2>/dev/null
echo '@@container'
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then echo yes
elif grep -qaE 'container=' /proc/1/environ 2>/dev/null; then echo yes
elif grep -qaE '/(docker|lxc|kubepods|containerd|libpod)' /proc/1/cgroup 2>/dev/null; then echo yes; fi
echo '@@hostname'; hostname -f 2>/dev/null || hostname 2>/dev/null || uname -n
echo '@@os'; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || sw_vers -productName 2>/dev/null || uname -s
echo '@@kernel'; uname -srm 2>/dev/null
echo '@@addresses'
if command -v ip >/dev/null 2>&1; then ip -o addr show scope global 2>/dev/null | awk '{print $4}'
elif command -v ifconfig >/dev/null 2>&1; then ifconfig 2>/dev/null | awk '/inet /{print $2}'
else hostname -I 2>/dev/null | tr ' ' '\n'; fi
echo '@@end'
"""

IDENTITY_WINDOWS = r"""
'@@windows'; (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
'@@dmi'; (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).UUID
'@@hostname'; [System.Net.Dns]::GetHostEntry('').HostName
'@@os'; (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
'@@kernel'; [System.Environment]::OSVersion.VersionString
'@@addresses'; (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress
'@@end'
"""

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

#: UUIDs firmware vendors ship un-set. Every machine with one of these would
#: be the same server.
_PLACEHOLDER_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
    "00020003-0004-0005-0006-000700080009",
}

#: Preference order, and why each is where it is, is in the module docstring.
ID_SOURCES = ("machine-id", "ioplatform", "windows", "hostuuid", "dmi", "hostkey")

ID_SOURCE_LABELS = {
    "machine-id": "machine-id",
    "ioplatform": "macOS platform UUID",
    "windows": "Windows MachineGuid",
    "hostuuid": "FreeBSD host UUID",
    "dmi": "firmware (DMI) UUID",
    "hostkey": "SSH host key",
}


@dataclass
class ServerIdentity:
    """What a server says about itself. ``uid`` is the key everything uses."""

    uid: str = ""
    source: str = ""
    hostname: str = ""
    os_name: str = ""
    kernel: str = ""
    addresses: list[str] = field(default_factory=list)
    host_key: str = ""                 # SHA256 fingerprint, when known
    platform: str = ""                 # posix | windows | ""
    container: bool = False
    error: str = ""

    @property
    def short(self) -> str:
        """A readable handle for the identity: its source and first 12 chars."""
        if not self.uid:
            return ""
        source, _, value = self.uid.partition(":")
        value = value.replace("SHA256:", "")
        return f"{source}:{value[:12]}"


def _clean_id(source: str, value: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        return ""
    if source == "machine-id":
        return value if _HEX32.match(value) and set(value) != {"0"} else ""
    if source in ("ioplatform", "windows", "hostuuid", "dmi"):
        if not _UUID.match(value) or value in _PLACEHOLDER_UUIDS:
            return ""
        return value
    return value


def hostkey_uid(fingerprint: str) -> str:
    return f"hostkey:{fingerprint}" if fingerprint else ""


def parse_identity(text: str, *, host_key: str = "", platform: str = "") -> ServerIdentity:
    """Choose the identity from the probe's output, best source first."""
    s = _sections(text)
    candidates = {
        "machine-id": _first(s.get("machine_id")),
        "ioplatform": _first(s.get("ioplatform")),
        "windows": _first(s.get("windows")),
        "hostuuid": _first(s.get("hostuuid")),
        "dmi": _first(s.get("dmi")),
    }
    ident = ServerIdentity(
        hostname=_first(s.get("hostname"))[:255],
        os_name=_first(s.get("os"))[:255],
        kernel=_first(s.get("kernel"))[:255],
        host_key=host_key, platform=platform)
    addresses: list[str] = []
    for line in s.get("addresses", []):
        for part in line.split():
            part = part.split("/")[0].strip()
            if part and part not in ("127.0.0.1", "::1") and part not in addresses:
                addresses.append(part)
    ident.addresses = addresses[:32]
    ident.container = _first(s.get("container")) == "yes"
    for source in ID_SOURCES[:-1]:
        if ident.container and source in ("machine-id", "dmi"):
            # A container sees its host's firmware UUID, and often a
            # machine-id baked into the image it was started from: every
            # container on one host, or from one image, would be one server.
            # Its own SSH host key is generated when it first starts.
            continue
        value = _clean_id(source, candidates.get(source, ""))
        if value:
            ident.uid, ident.source = f"{source}:{value}", source
            return ident
    if host_key:
        ident.uid, ident.source = hostkey_uid(host_key), "hostkey"
    return ident


def identify(run_input: RunInput, *, host_key: str = "") -> ServerIdentity:
    """Ask the server who it is. Never raises: falls back to the host key."""
    try:
        platform, out = run_script(run_input, IDENTITY_POSIX, IDENTITY_WINDOWS)
    except Exception as exc:
        ident = ServerIdentity(host_key=host_key, error=str(exc))
        if host_key:
            ident.uid, ident.source = hostkey_uid(host_key), "hostkey"
        return ident
    return parse_identity(out, host_key=host_key, platform=platform)


# ============================================================= performance ==

PERF_POSIX = r"""
echo '@@uptime'; cat /proc/uptime 2>/dev/null
echo '@@boottime'; [ -r /proc/uptime ] || sysctl -n kern.boottime 2>/dev/null
echo '@@now'; date +%s
echo '@@loadavg'; cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg 2>/dev/null
echo '@@nproc'; nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null
echo '@@meminfo'; cat /proc/meminfo 2>/dev/null
if [ ! -r /proc/meminfo ]; then
  echo '@@memsize'; sysctl -n hw.memsize hw.physmem 2>/dev/null | head -n 1
  echo '@@vmstat'; vm_stat 2>/dev/null
  echo '@@swapusage'; sysctl -n vm.swapusage 2>/dev/null
fi
echo '@@stat1'; head -n 1 /proc/stat 2>/dev/null
sleep 1
echo '@@stat2'; head -n 1 /proc/stat 2>/dev/null
if [ ! -r /proc/stat ]; then
  echo '@@cpuusage'; top -l 2 -n 0 -s 1 2>/dev/null | grep 'CPU usage' | tail -n 1
fi
echo '@@psi'; for f in cpu memory io; do [ -r /proc/pressure/$f ] && printf '%s %s\n' "$f" "$(head -n 1 /proc/pressure/$f)"; done
echo '@@df'; df -Pk 2>/dev/null
echo '@@dfi'; df -Pi 2>/dev/null
if ps -eo pid= --sort=-pcpu >/dev/null 2>&1; then
  echo '@@pscpu'; ps -eo pid=,user=,pcpu=,pmem=,rss=,comm= --sort=-pcpu 2>/dev/null | head -n 8
  echo '@@psmem'; ps -eo pid=,user=,pcpu=,pmem=,rss=,comm= --sort=-rss 2>/dev/null | head -n 8
elif ps -A -o pid= -r >/dev/null 2>&1; then
  echo '@@pscpu'; ps -A -o pid=,user=,pcpu=,pmem=,rss=,comm= -r 2>/dev/null | head -n 8
  echo '@@psmem'; ps -A -o pid=,user=,pcpu=,pmem=,rss=,comm= -m 2>/dev/null | head -n 8
else
  echo '@@top'; top -b -n 1 2>/dev/null | head -n 14
fi
echo '@@states'; ps -eo stat= 2>/dev/null | cut -c1 | sort | uniq -c
echo '@@failed'; systemctl --failed --no-legend --plain 2>/dev/null | head -n 30
echo '@@oom'; (journalctl -k -b --no-pager -q 2>/dev/null || dmesg 2>/dev/null) | grep -iE 'out of memory|oom-kill|killed process' | tail -n 5
echo '@@end'
"""

PERF_WINDOWS = r"""
$os = Get-CimInstance Win32_OperatingSystem
'@@uptime'; [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
'@@nproc'; [System.Environment]::ProcessorCount
'@@wincpu'; (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
'@@winmem'; "$($os.TotalVisibleMemorySize) $($os.FreePhysicalMemory)"
'@@windisk'; Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID) $($_.Size) $($_.FreeSpace)" }
'@@winproc'; Get-Process | Sort-Object CPU -Descending | Select-Object -First 7 | ForEach-Object { "$($_.Id) $([int]$_.CPU) $($_.WorkingSet64) $($_.ProcessName)" }
'@@failed'; Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | Where-Object { $_.ExitCode -ne 0 } | ForEach-Object { "$($_.Name) exit $($_.ExitCode)" }
'@@end'
"""


@dataclass
class Finding:
    severity: str          # ok | info | warn | crit
    title: str
    detail: str = ""


@dataclass
class PerfReport:
    platform: str = ""
    uptime_s: float | None = None
    cpus: int | None = None
    load: tuple[float, float, float] | None = None
    cpu_busy: float | None = None
    iowait: float | None = None
    steal: float | None = None
    mem_used: int | None = None
    mem_total: int | None = None
    swap_used: int | None = None
    swap_total: int | None = None
    disks: list[tuple[str, float, str]] = field(default_factory=list)  # mount, %, detail
    top_cpu: list[str] = field(default_factory=list)
    top_mem: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return worst(f.severity for f in self.findings)

    def headline(self) -> str:
        bad = [f for f in self.findings if f.severity in ("warn", "crit")]
        if not bad:
            return "Performance: healthy"
        return f"Performance: {len(bad)} issue(s) - " + "; ".join(f.title for f in bad[:3])

    def to_text(self) -> str:
        lines = [self.headline(), ""]
        facts = []
        if self.uptime_s is not None:
            facts.append(f"up {_duration(self.uptime_s)}")
        if self.cpus:
            facts.append(f"{self.cpus} CPU(s)")
        if self.load:
            facts.append("load " + " ".join(f"{v:.2f}" for v in self.load))
        if self.cpu_busy is not None:
            facts.append(f"CPU {self.cpu_busy:.0f}% busy")
        if self.mem_total:
            facts.append(f"memory {human(self.mem_used or 0)} / {human(self.mem_total)}")
        if facts:
            lines.append(" · ".join(facts))
            lines.append("")
        for f in self.findings:
            mark = {"crit": "[CRITICAL]", "warn": "[WARNING]", "info": "[info]",
                    "ok": "[ok]"}.get(f.severity, "")
            lines.append(f"{mark} {f.title}")
            if f.detail:
                lines.extend("    " + d for d in f.detail.splitlines())
        if self.disks:
            lines += ["", "Filesystems:"]
            lines += [f"    {m:<24} {p:5.1f}%  {d}" for m, p, d in self.disks]
        if self.top_cpu:
            lines += ["", {"windows": "Busiest processes (pid, CPU time, memory, name):"}.get(
                self.platform, "Busiest processes (pid user cpu% mem% rss command):"
                if self.top_mem else "Busiest processes:")]
            lines += ["    " + p for p in self.top_cpu]
        if self.top_mem:
            lines += ["", "Largest processes by memory:"]
            lines += ["    " + p for p in self.top_mem]
        return "\n".join(lines).rstrip() + "\n"


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _cpu_fields(line: str) -> list[int] | None:
    parts = line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        return None
    try:
        return [int(v) for v in parts[1:]]
    except ValueError:
        return None


def _swap(lines: list[str]) -> tuple[int | None, int | None]:
    values = {}
    for line in lines:
        name, _, rest = line.partition(":")
        number = rest.strip().split(" ")[0]
        if number.isdigit():
            values[name.strip()] = int(number) * 1024
    total = values.get("SwapTotal")
    if not total:
        return None, total
    return total - values.get("SwapFree", 0), total


def _float(text: str) -> float | None:
    try:
        return float(text.replace(",", "."))
    except (TypeError, ValueError):
        return None


def parse_performance(text: str, platform: str = "posix") -> PerfReport:
    """Turn the probe's output into numbers, then numbers into findings."""
    s = _sections(text)
    r = PerfReport(platform=platform)
    up = _first(s.get("uptime")).split()
    if up:
        r.uptime_s = _float(up[0])
    boot = re.search(r"sec\s*=\s*(\d+)", _first(s.get("boottime")))
    now = _first(s.get("now"))
    if r.uptime_s is None and boot and now.isdigit():
        r.uptime_s = float(int(now) - int(boot.group(1)))
    n = _first(s.get("nproc"))
    if n.isdigit():
        r.cpus = int(n)
    load = re.findall(r"[0-9]+[.,][0-9]+", _first(s.get("loadavg")))
    if len(load) >= 3:
        r.load = tuple(float(v.replace(",", ".")) for v in load[:3])  # type: ignore

    if platform == "windows":
        _parse_windows_perf(s, r)
    else:
        a, b = _cpu_fields(_first(s.get("stat1"))), _cpu_fields(_first(s.get("stat2")))
        if a and b and len(a) == len(b):
            delta = [y - x for x, y in zip(a, b)]
            total = sum(delta[:8]) or 0
            if total > 0:
                idle = delta[3]
                iowait = delta[4] if len(delta) > 4 else 0
                steal = delta[7] if len(delta) > 7 else 0
                r.cpu_busy = 100.0 * (total - idle - iowait - steal) / total
                r.iowait = 100.0 * iowait / total
                r.steal = 100.0 * steal / total
        used, total_mem = parse_meminfo(s.get("meminfo", []))
        r.mem_used, r.mem_total = used, total_mem
        r.swap_used, r.swap_total = _swap(s.get("meminfo", []))
        if r.mem_total is None:
            _parse_bsd_memory(s, r)
        if r.cpu_busy is None:
            usage = _first(s.get("cpuusage"))
            idle = re.search(r"([0-9.]+)%\s*idle", usage)
            if idle:
                r.cpu_busy = max(0.0, 100.0 - float(idle.group(1)))
        for disk in parse_df(s.get("df", [])):
            if disk.mount.startswith("/etc/"):       # a container's bind-mounted file
                continue
            r.disks.append((disk.mount, disk.percent,
                            f"{human(disk.used)} / {human(disk.total)}"))
        r.top_cpu = _processes(s.get("pscpu", []))
        r.top_mem = _processes(s.get("psmem", []))
        if not r.top_cpu and s.get("top"):
            r.top_cpu = [l.rstrip() for l in s["top"] if l.strip()][:14]

    _judge(r, s)
    return r


def _parse_bsd_memory(s: dict[str, list[str]], r: PerfReport) -> None:
    """macOS: `vm_stat` pages, the way Activity Monitor counts "used"."""
    size = _first(s.get("memsize"))
    if not size.isdigit():
        return
    r.mem_total = int(size)
    page = 4096
    pages: dict[str, int] = {}
    for line in s.get("vmstat", []):
        found = re.search(r"page size of (\d+) bytes", line)
        if found:
            page = int(found.group(1))
            continue
        name, _, value = line.partition(":")
        value = value.strip().rstrip(".")
        if value.isdigit():
            pages[name.strip()] = int(value)
    used = sum(pages.get(k, 0) for k in ("Pages active", "Pages wired down",
                                          "Pages occupied by compressor"))
    if used:
        r.mem_used = used * page
    swap = re.findall(r"(total|used)\s*=\s*([0-9.]+)([KMG])", _first(s.get("swapusage")))
    scale = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    values = {k: float(v) * scale[u] for k, v, u in swap}
    if values.get("total"):
        r.swap_total, r.swap_used = int(values["total"]), int(values.get("used", 0))


def _parse_windows_perf(s: dict[str, list[str]], r: PerfReport) -> None:
    cpu = _float(_first(s.get("wincpu")))
    if cpu is not None:
        r.cpu_busy = cpu
    mem = _first(s.get("winmem")).split()
    if len(mem) == 2 and all(m.isdigit() for m in mem):
        total, free = int(mem[0]) * 1024, int(mem[1]) * 1024
        r.mem_total, r.mem_used = total, total - free
    for line in s.get("windisk", []):
        parts = line.split()
        if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit() and int(parts[1]):
            size, free = int(parts[1]), int(parts[2])
            r.disks.append((parts[0], 100.0 * (size - free) / size,
                            f"{human(size - free)} / {human(size)}"))
    for line in s.get("winproc", []):
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[2].isdigit():
            r.top_cpu.append(f"{parts[0]:>6}  cpu {parts[1]:>6}s  "
                             f"{human(int(parts[2])):>7}  {parts[3]}")
    r.top_cpu = r.top_cpu[:7]


def _inode_use(lines: list[str]) -> list[tuple[str, str, int]]:
    """(mount, device, percent) from `df -Pi`, GNU or BSD.

    GNU prints "IUse%" as the fifth column; macOS prints the space columns
    first and "%iused" eighth. The header says which, and the mount point -
    which may contain spaces - is everything after the last numeric column.
    """
    if not lines:
        return []
    header = lines[0].split()
    column = next((i for i, h in enumerate(header) if h.lower() in ("iuse%", "%iused")), -1)
    if column < 0:
        return []
    mount_at = len(header) - 2 if header[-2:] == ["Mounted", "on"] else len(header) - 1
    out = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) <= mount_at or not parts[column].endswith("%"):
            continue
        number = parts[column][:-1]
        if number.isdigit():
            out.append((" ".join(parts[mount_at:]), parts[0], int(number)))
    return out


def _real_filesystem(device: str, mount: str) -> bool:
    """Storage, not a read-only image or memory. A snap's squashfs is always
    100% full of inodes, by construction, and is nothing to warn about."""
    if device in PSEUDO or device.split("/")[-1] in PSEUDO or LOOPBACK.match(device):
        return False
    return not any(mount == p or mount.startswith(p + "/") for p in PSEUDO_MOUNTS)


def _processes(lines: list[str]) -> list[str]:
    """`ps` rows, without the `ps` that took the reading."""
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        command = " ".join(parts[5:]).rsplit("/", 1)[-1]      # macOS gives the path
        if command in ("ps", "sh"):
            continue
        rows.append(" ".join(parts[:5] + [command]))
    return rows[:7]


def _judge(r: PerfReport, s: dict[str, list[str]]) -> None:
    """The thresholds a person would apply reading the same numbers."""
    add = r.findings.append
    if r.load and r.cpus:
        per_core = r.load[0] / r.cpus
        if per_core >= 2:
            add(Finding("crit", f"Load {r.load[0]:.2f} on {r.cpus} CPU(s)",
                        "More than twice as many runnable tasks as cores - work is queuing."))
        elif per_core >= 1:
            add(Finding("warn", f"Load {r.load[0]:.2f} on {r.cpus} CPU(s)",
                        "Every core is spoken for; anything new waits."))
    if r.cpu_busy is not None:
        if r.cpu_busy >= 90:
            add(Finding("crit", f"CPU {r.cpu_busy:.0f}% busy"))
        elif r.cpu_busy >= 75:
            add(Finding("warn", f"CPU {r.cpu_busy:.0f}% busy"))
    if r.iowait is not None and r.iowait >= 20:
        add(Finding("warn", f"I/O wait {r.iowait:.0f}%",
                    "The CPUs are waiting on storage. Check disk latency (iostat -x 1)."))
    if r.steal is not None and r.steal >= 10:
        add(Finding("warn", f"CPU steal {r.steal:.0f}%",
                    "The hypervisor is giving this VM's time to others."))
    if r.mem_total:
        pct = 100.0 * (r.mem_used or 0) / r.mem_total
        if pct >= 95:
            add(Finding("crit", f"Memory {pct:.0f}% used",
                        f"{human(r.mem_used or 0)} of {human(r.mem_total)} - close to OOM."))
        elif pct >= 85:
            add(Finding("warn", f"Memory {pct:.0f}% used",
                        f"{human(r.mem_used or 0)} of {human(r.mem_total)}."))
    if r.swap_total and r.swap_used is not None:
        pct = 100.0 * r.swap_used / r.swap_total
        if pct >= 50:
            add(Finding("warn", f"Swap {pct:.0f}% used",
                        "Heavy swapping slows everything; memory is short."))
    for mount, pct, detail in r.disks:
        if pct >= 95:
            add(Finding("crit", f"Filesystem {mount} {pct:.0f}% full", detail))
        elif pct >= 85:
            add(Finding("warn", f"Filesystem {mount} {pct:.0f}% full", detail))
    for mount, device, used in _inode_use(s.get("dfi", [])):
        if used >= 90 and _real_filesystem(device, mount):
            add(Finding("warn", f"Inodes on {mount} {used}% used",
                        "New files will fail even with free space left."))
    states = {}
    for line in s.get("states", []):
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            states[parts[1]] = int(parts[0])
    if states.get("Z", 0):
        add(Finding("crit" if states["Z"] > 20 else "warn",
                    f"{states['Z']} zombie process(es)",
                    "A parent is not reaping its children."))
    if states.get("D", 0) > 2:
        add(Finding("warn", f"{states['D']} process(es) in uninterruptible sleep",
                    "Usually stuck on storage or NFS."))
    for line in s.get("psi", []):
        found = re.match(r"(\w+)\s+some avg10=([0-9.]+)", line)
        if found and float(found.group(2)) >= 20:
            add(Finding("warn", f"{found.group(1)} pressure {found.group(2)}%",
                        "Tasks spent this share of the last 10s stalled on it."))
    failed = [l.split()[0] for l in s.get("failed", []) if l.strip()]
    if failed:
        add(Finding("warn", f"{len(failed)} failed service(s)",
                    "\n".join(failed[:15])))
    oom = [l.strip() for l in s.get("oom", []) if l.strip()]
    if oom:
        add(Finding("crit", "The kernel killed processes for memory this boot",
                    "\n".join(oom[-3:])))
    if r.uptime_s is not None and r.uptime_s < 600:
        add(Finding("info", f"Rebooted {_duration(r.uptime_s)} ago"))
    if not r.findings:
        add(Finding("ok", "No resource problems found"))


def performance(run_input: RunInput) -> PerfReport:
    platform, out = run_script(run_input, PERF_POSIX, PERF_WINDOWS)
    return parse_performance(out, platform)


# ==================================================================== logs ==

#: What counts as an error line. Broad on purpose: a summary groups and ranks
#: what it finds, so a few false positives cost a line each, while a narrow
#: pattern costs the one error nobody spelled "error".
ERROR_PATTERN = (r"error|fail(ed|ure)?|fatal|crit(ical)?|panic|segfault|denied|"
                 r"exception|traceback|out of memory|oom|timed? ?out|refused|unreachable")

#: How much of each file is read. A 40 GB access log is someone else's
#: problem; the last 20 MB of it is what happened recently.
TAIL_BYTES = 20_000_000

LOGS_POSIX = r"""
PAT='""" + ERROR_PATTERN + r"""'
echo '@@journal_count'
if command -v journalctl >/dev/null 2>&1; then
  journalctl -p err --since -24h --no-pager -q -o cat 2>/dev/null | wc -l
fi
echo '@@journal'
if command -v journalctl >/dev/null 2>&1; then
  journalctl -p err --since -24h --no-pager -q -o short-iso 2>/dev/null | tail -n 300 | cut -c1-400
fi
LIST=$(find /var/log -xdev -type f \( -name '*.log' -o -name syslog -o -name messages -o -name secure -o -name kern.log -o -name error_log -o -name '*.err' -o -name 'catalina.out' \) -mtime -7 -size -2000000k 2>/dev/null | head -n 300)
echo '@@unreadable'
echo "$LIST" | while IFS= read -r f; do [ -n "$f" ] && [ ! -r "$f" ] && echo "$f"; done | head -n 50
echo '@@files'
echo "$LIST" | while IFS= read -r f; do
  [ -n "$f" ] && [ -r "$f" ] || continue
  n=$(tail -c """ + str(TAIL_BYTES) + r""" "$f" 2>/dev/null | grep -aciE "$PAT" 2>/dev/null)
  [ "${n:-0}" -gt 0 ] 2>/dev/null && printf '%s\t%s\n' "$n" "$f"
done | sort -rn | head -n 40 > "${TMPDIR:-/tmp}/.ares-logs.$$"
cat "${TMPDIR:-/tmp}/.ares-logs.$$"
head -n 15 "${TMPDIR:-/tmp}/.ares-logs.$$" | while IFS="$(printf '\t')" read -r n f; do
  echo "@@sample $f"
  tail -c """ + str(TAIL_BYTES) + r""" "$f" 2>/dev/null | grep -aiE "$PAT" 2>/dev/null | tail -n 60 | cut -c1-400
done
rm -f "${TMPDIR:-/tmp}/.ares-logs.$$"
echo '@@end'
"""

LOGS_WINDOWS = r"""
$since = (Get-Date).AddDays(-1)
$events = @(Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$since} -MaxEvents 400 -ErrorAction SilentlyContinue)
'@@journal_count'; $events.Count
'@@journal'
$events | ForEach-Object { "$($_.TimeCreated.ToString('s')) $($_.LogName)/$($_.ProviderName)[$($_.Id)]: " + (($_.Message -split "`n")[0]).Trim() }
'@@end'
"""


@dataclass
class Signature:
    """One kind of error: the line with its particulars taken out."""

    pattern: str
    count: int
    example: str
    sources: list[str] = field(default_factory=list)
    category: str = "other"


@dataclass
class LogReport:
    platform: str = ""
    journal_count: int = 0
    journal_lines: list[str] = field(default_factory=list)
    files: list[tuple[int, str]] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    samples: dict[str, list[str]] = field(default_factory=dict)
    signatures: list[Signature] = field(default_factory=list)
    categories: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return self.journal_count + sum(n for n, _ in self.files)

    @property
    def severity(self) -> str:
        if not self.total:
            return "ok"
        serious = sum(self.categories.get(c, 0) for c in ("kernel", "disk", "memory"))
        if serious or self.total >= 1000:
            return "crit"
        return "warn"

    def headline(self) -> str:
        if not self.total:
            return "Logs: no error lines found"
        where = []
        if self.journal_count:
            log = "the Windows event log" if self.platform == "windows" else "the journal"
            where.append(f"{self.journal_count} in {log} (24h)")
        if self.files:
            where.append(f"{sum(n for n, _ in self.files)} in {len(self.files)} file(s)")
        return "Logs: " + ", ".join(where)

    def summary(self) -> str:
        """The plain-language summary of the errors, made on this machine."""
        if not self.total:
            text = "No error lines in the system journal for the last 24 hours, " \
                   "or in log files changed in the last 7 days."
            if self.unreadable:
                text += (f" {len(self.unreadable)} log file(s) could not be read as "
                         "this user, so this is not the whole picture.")
            return text
        parts = [self.headline() + "."]
        if self.categories:
            ranked = sorted(self.categories.items(), key=lambda kv: -kv[1])
            parts.append("By kind: " + ", ".join(
                f"{CATEGORY_LABELS.get(k, k)} {v}" for k, v in ranked) + ".")
        if self.signatures:
            top = self.signatures[0]
            parts.append(f"Most frequent ({top.count}x): {top.example[:160]}")
        if self.files:
            parts.append("Noisiest file: " + f"{self.files[0][1]} ({self.files[0][0]} lines).")
        for category, advice in CATEGORY_ADVICE.items():
            if self.categories.get(category):
                if self.platform == "windows":
                    advice = WINDOWS_ADVICE.get(category, advice)
                parts.append(advice)
        if self.unreadable:
            parts.append(f"{len(self.unreadable)} log file(s) were not readable as this "
                         "user; connect as a user in the adm or systemd-journal group "
                         "for the full picture.")
        return "\n".join(parts)

    def to_text(self) -> str:
        lines = [self.headline(), "", self.summary(), ""]
        if self.signatures:
            lines.append("Recurring errors (count, kind, example):")
            for sig in self.signatures[:20]:
                lines.append(f"  {sig.count:>5}  [{CATEGORY_LABELS.get(sig.category, sig.category)}]"
                             f"  {sig.example[:240]}")
                if sig.sources:
                    lines.append(f"         in {', '.join(sig.sources[:3])}")
            lines.append("")
        if self.files:
            lines.append("Log files with errors (lines matched, last 20 MB of each):")
            lines += [f"  {n:>7}  {path}" for n, path in self.files]
            lines.append("")
        if self.unreadable:
            lines.append("Not readable as this user:")
            lines += [f"  {p}" for p in self.unreadable[:20]]
        return "\n".join(lines).rstrip() + "\n"

    def excerpt(self, limit: int) -> str:
        """The part of this report worth an AI's time, redacted, within ``limit``.

        Grouped errors first - they are the most information per character -
        then the newest raw lines from the journal and the noisiest files.
        """
        out = [self.headline(), ""]
        if self.signatures:
            out.append("Recurring error patterns (count | category | example line):")
            for sig in self.signatures[:25]:
                out.append(f"{sig.count} | {sig.category} | {redact_log_line(sig.example)[:300]}")
            out.append("")
        if self.journal_lines:
            out.append("Newest journal error lines:")
            out += [redact_log_line(l)[:300] for l in self.journal_lines[-60:]]
            out.append("")
        for path, lines in list(self.samples.items())[:8]:
            out.append(f"Newest error lines from {path}:")
            out += [redact_log_line(l)[:300] for l in lines[-25:]]
            out.append("")
        text = "\n".join(out)
        if len(text) > limit:
            text = text[:limit].rsplit("\n", 1)[0] + "\n[... cut to fit]"
        return text


CATEGORY_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("kernel", re.compile(r"kernel panic|segfault|call trace|\bBUG:|general protection|"
                          r"\bwatchdog\b|hung_task|\bmce\b|machine check", re.I)),
    ("disk", re.compile(r"i/o error|no space left|read-only file system|ext4-fs error|"
                        r"\bxfs\b.*(error|corrupt)|blk_update_request|\bsmartd?\b|"
                        r"\bbad sector|filesystem.*(error|full)|disk quota", re.I)),
    ("memory", re.compile(r"out of memory|oom|cannot allocate memory|killed process", re.I)),
    ("auth", re.compile(r"authentication failure|failed password|invalid user|"
                        r"permission denied|access denied|unauthori[sz]ed|pam_unix|sudo:", re.I)),
    ("network", re.compile(r"connection refused|unreachable|timed? ?out|connection reset|"
                           r"name resolution|\bdns\b|no route to host|\bssl\b|\btls\b|"
                           r"certificate|\bocsp\b", re.I)),
    ("service", re.compile(r"systemd|failed to start|main process exited|"
                           r"start request repeated|unit .* failed|exited with|"
                           r"\bservice\b.*\bfail|\bfail.*\bservice\b", re.I)),
    ("application", re.compile(r"exception|traceback|stack ?trace|fatal|panic|"
                               r"undefined|null ?pointer", re.I)),
)

CATEGORY_LABELS = {"kernel": "kernel", "disk": "disk/filesystem", "memory": "memory",
                   "auth": "authentication", "network": "network",
                   "service": "services", "application": "application",
                   "other": "other"}

CATEGORY_ADVICE = {
    "kernel": "Kernel-level faults appeared - check dmesg and hardware health before anything else.",
    "disk": "Storage errors appeared - check free space, SMART health and whether a filesystem went read-only.",
    "memory": "Memory exhaustion appeared - see which process the OOM killer chose and whether limits are right.",
    "auth": "Authentication failures appeared - check for brute-force attempts (lastb, fail2ban) and expired credentials.",
    "service": "Services failed - systemctl --failed and journalctl -u <unit> show why.",
}


WINDOWS_ADVICE = {
    "kernel": "Kernel-level faults appeared - check the System log for bugchecks and hardware (WHEA) events first.",
    "auth": "Authentication failures appeared - check the Security log for event 4625 and locked-out accounts.",
    "service": "Services failed - Get-Service and the System log's Service Control Manager events show which and why.",
}


def categorise(line: str) -> str:
    for name, rule in CATEGORY_RULES:
        if rule.search(line):
            return name
    return "other"


_TS_PREFIXES = (
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ][\d:.,]+(?:Z|[+-]\d{2}:?\d{2})?\s*"),
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"),
    re.compile(r"^\[[^\]]{8,40}\]\s*"),
)
_NORMALISE = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"'[^']{1,80}'|\"[^\"]{1,80}\""), "<q>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\[\d+\]"), "[<pid>]"),
    (re.compile(r"\d+"), "<n>"),
    (re.compile(r"\s+"), " "),
)


def _strip_timestamp(line: str) -> str:
    text = line.strip()
    for rule in _TS_PREFIXES:
        text = rule.sub("", text, count=1)
    return text


def normalise(line: str) -> str:
    """The shape of an error line, so repeats of it group together."""
    text = _strip_timestamp(line)
    # A syslog line carries the host before the program: "web01 nginx[12]: ...".
    text = re.sub(r"^[\w.-]+\s+(?=[\w./-]+(?:\[\d+\])?:)", "", text)
    for rule, replacement in _NORMALISE:
        text = rule.sub(replacement, text)
    return text.strip()[:240]


def _signatures(lines_by_source: dict[str, list[str]]) -> tuple[list[Signature], dict[str, int]]:
    counts: Counter = Counter()
    examples: dict[str, str] = {}
    sources: dict[str, list[str]] = {}
    categories: Counter = Counter()
    for source, lines in lines_by_source.items():
        for line in lines:
            if not line.strip():
                continue
            key = normalise(line)
            if not key:
                continue
            counts[key] += 1
            # Newest example wins. Redacted here, so the summary kept in the
            # history never holds a password a log line happened to print.
            examples[key] = redact_log_line(_strip_timestamp(line))
            if source not in sources.setdefault(key, []):
                sources[key].append(source)
            categories[categorise(line)] += 1
    sigs = [Signature(pattern=k, count=n, example=examples[k], sources=sources[k],
                      category=categorise(examples[k]))
            for k, n in counts.most_common(40)]
    return sigs, dict(categories)


def parse_logs(text: str, platform: str = "posix") -> LogReport:
    s = _sections(text)
    r = LogReport(platform=platform)
    count = _first(s.get("journal_count"))
    r.journal_count = int(count) if count.isdigit() else 0
    r.journal_lines = [l for l in s.get("journal", []) if l.strip()]
    for line in s.get("files", []):
        n, _, path = line.partition("\t")
        if n.strip().isdigit() and path.strip():
            r.files.append((int(n), path.strip()))
    r.unreadable = [l.strip() for l in s.get("unreadable", []) if l.strip()]
    for name, lines in s.items():
        if name.startswith("sample "):
            r.samples[name[len("sample "):].strip()] = [l for l in lines if l.strip()]
    journal = "event log" if platform == "windows" else "journal"
    sources = {journal: r.journal_lines, **r.samples}
    r.signatures, r.categories = _signatures(sources)
    return r


def logs(run_input: RunInput) -> LogReport:
    platform, out = run_script(run_input, LOGS_POSIX, LOGS_WINDOWS)
    return parse_logs(out, platform)


# =============================================================== redaction ==

_REDACT = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "<private key removed>"),
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*\S+(\s+\S+)?"), r"\1: ***"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer ***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key|"
                r"access[_-]?key|client[_-]?secret|session[_-]?id|cookie)\b(\"?\s*[:=]\s*\"?)[^\s\"',;&]+"),
     r"\1\2***"),
    (re.compile(r"(?i)([?&](?:token|key|sig|signature|password|secret|auth)=)[^&\s\"']+"), r"\1***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<aws key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "<token>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "<token>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "<jwt>"),
    (re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+@"), r"\1***@"),
    # Command lines, which the performance pack carries: `--password hunter2`
    # with a space, and the MySQL family's glued `-pSecret`.
    (re.compile(r"(?i)(--?(?:password|passwd|pass|pwd|token|secret|api[_-]?key)\s+)"
                r"(?!-)[^\s\"']+"), r"\1***"),
    (re.compile(r"(?i)(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]*?\s-p)"
                r"(?!\s)[^\s\"']+"), r"\1***"),
)


def redact_log_line(line: str) -> str:
    """A log line with anything that looks like a credential blanked out.

    Applied to everything that leaves this machine for AI analysis. It is a
    net, not a guarantee, which is why the operator is shown the exact text
    before it is sent.
    """
    text = line or ""
    for rule, replacement in _REDACT:
        text = rule.sub(replacement, text)
    return text


# ============================================================ (de)serialise ==

def to_json(obj) -> str:
    """A report as JSON for the sealed history body."""
    from dataclasses import asdict
    return json.dumps(asdict(obj), ensure_ascii=False)


__all__ = [
    "CATEGORY_LABELS", "ERROR_PATTERN", "Finding", "ID_SOURCES", "ID_SOURCE_LABELS",
    "LogReport", "PerfReport", "ServerIdentity", "Signature", "categorise",
    "hostkey_uid", "identify", "logs", "normalise", "parse_identity", "parse_logs",
    "parse_performance", "performance", "powershell", "redact_log_line",
    "run_script", "to_json", "worst",
]
