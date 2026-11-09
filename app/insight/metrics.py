"""What a server is doing with itself: CPU, memory and disks.

One command per sample, parsed here rather than on the far side, so nothing has
to be installed on a server to be watched. Linux answers from ``/proc``; the
BSDs and macOS answer what they can through ``sysctl`` and ``df``, and whatever
cannot be had is left blank rather than guessed at.

The sampler is handed a ``run`` callable - anything that takes a command and
returns ``(status, stdout, stderr)`` - so it works over an SSH session without
knowing what one is, and can be tested against canned output.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger("ares.metrics")

#: Asked in one round trip. Sections are labelled so a shell that lacks one
#: command simply contributes nothing to that part.
COMMAND = (
    "echo '#stat'; head -n 1 /proc/stat 2>/dev/null; "
    "echo '#mem'; head -n 5 /proc/meminfo 2>/dev/null; "
    "echo '#swap'; grep -E '^Swap(Total|Free)' /proc/meminfo 2>/dev/null; "
    "echo '#load'; uptime 2>/dev/null; "
    "echo '#sysctl'; sysctl -n hw.physmem hw.ncpu 2>/dev/null; "
    "echo '#df'; df -Pk 2>/dev/null"
)

#: Filesystems that are memory, not storage.
PSEUDO = {"tmpfs", "devtmpfs", "devfs", "udev", "none", "overlay", "squashfs",
          "proc", "sysfs", "cgroup", "cgroup2", "ramfs", "efivarfs", "fdescfs",
          "procfs", "map", "run"}
PSEUDO_MOUNTS = ("/dev", "/proc", "/sys", "/run", "/snap", "/var/lib/snapd/snap",
                 "/System/Volumes/VM")
#: Loopback images - every snap package mounts one, permanently 100% full.
LOOPBACK = re.compile(r"^/dev/(loop|ram)\d+$")


@dataclass
class Disk:
    mount: str
    used: int = 0
    total: int = 0
    filesystem: str = ""

    @property
    def percent(self) -> float:
        return (self.used / self.total * 100) if self.total else 0.0


@dataclass
class Snapshot:
    """One reading. Anything unknown stays None, and the gauge omits it."""

    cpu: float | None = None
    load: float | None = None
    cores: int | None = None
    mem_used: int | None = None
    mem_total: int | None = None
    swap_used: int | None = None
    swap_total: int | None = None
    disks: list[Disk] = field(default_factory=list)
    error: str = ""

    @property
    def mem_percent(self) -> float:
        if not self.mem_total or self.mem_used is None:
            return 0.0
        return self.mem_used / self.mem_total * 100

    @property
    def swap_percent(self) -> float:
        if not self.swap_total or self.swap_used is None:
            return 0.0
        return self.swap_used / self.swap_total * 100

    @property
    def empty(self) -> bool:
        return (self.cpu is None and self.mem_total is None and not self.disks
                and self.load is None)


def human(size: float) -> str:
    """Bytes as a person would write them."""
    for unit in ("B", "K", "M", "G", "T", "P"):
        if abs(size) < 1024 or unit == "P":
            return f"{size:.0f}{unit}" if unit in ("B", "K") else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}P"


def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        if line.startswith("#") and not line.startswith("#!"):
            current = line[1:].strip()
            out[current] = []
        elif current:
            out[current].append(line)
    return out


def parse_cpu_times(line: str) -> tuple[int, int] | None:
    """``/proc/stat``'s first line as (busy + idle, idle)."""
    parts = line.split()
    if len(parts) < 5 or not parts[0].startswith("cpu"):
        return None
    try:
        values = [int(v) for v in parts[1:11] if v.isdigit()]
    except ValueError:
        return None
    if len(values) < 4:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)     # idle + iowait
    return sum(values), idle


def parse_meminfo(lines: list[str]) -> tuple[int | None, int | None]:
    """(used, total) in bytes, preferring MemAvailable as the kernel means it."""
    values: dict[str, int] = {}
    for line in lines:
        name, _, rest = line.partition(":")
        number = rest.strip().split(" ")[0]
        if number.isdigit():
            values[name.strip()] = int(number) * 1024
    total = values.get("MemTotal")
    if not total:
        return None, None
    if "MemAvailable" in values:
        return total - values["MemAvailable"], total
    free = values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
    return total - free, total


def parse_df(lines: list[str]) -> list[Disk]:
    disks: list[Disk] = []
    seen: set[str] = set()
    for line in lines[1:]:                       # the header names the columns
        parts = line.split()
        if len(parts) < 6:
            continue
        filesystem, blocks, used = parts[0], parts[1], parts[2]
        mount = " ".join(parts[5:])
        if not blocks.isdigit() or not used.isdigit():
            continue
        if filesystem in PSEUDO or filesystem.split("/")[-1] in PSEUDO:
            continue
        if any(mount == p or mount.startswith(p + "/") for p in PSEUDO_MOUNTS):
            continue
        if LOOPBACK.match(filesystem) or mount in seen or int(blocks) <= 0:
            continue
        seen.add(mount)
        disks.append(Disk(mount=mount, used=int(used) * 1024,
                          total=int(blocks) * 1024, filesystem=filesystem))
    # One row per device: a btrfs subvolume or a bind mount is the same space
    # seen twice, and listing "/" seven times says nothing seven times. Root
    # sorts first, then the shortest path, so the row kept is the one a person
    # would name.
    disks.sort(key=lambda d: (d.mount != "/", len(d.mount), d.mount))
    unique: list[Disk] = []
    devices: set[tuple[str, int]] = set()
    for disk in disks:
        key = (disk.filesystem, disk.total)
        if key in devices:
            continue
        devices.add(key)
        unique.append(disk)
    return unique


_LOAD = re.compile(r"load averages?:\s*([0-9]+[.,][0-9]+)", re.IGNORECASE)


def parse_load(lines: list[str]) -> float | None:
    for line in lines:
        found = _LOAD.search(line)
        if found:
            try:
                return float(found.group(1).replace(",", "."))
            except ValueError:
                return None
    return None


class MetricsSampler:
    """Repeated readings from one server, with CPU measured between them."""

    def __init__(self, run: Callable[[str], tuple[int, str, str]], *,
                 max_failures: int = 3):
        self.run = run
        self.max_failures = max_failures
        self.failures = 0
        self._previous: tuple[int, int] | None = None

    @property
    def giving_up(self) -> bool:
        return self.failures >= self.max_failures

    def sample(self) -> Snapshot:
        try:
            status, out, err = self.run(COMMAND)
        except Exception as exc:
            self.failures += 1
            return Snapshot(error=f"{type(exc).__name__}: {exc}")
        if status not in (0, None) and not out.strip():
            self.failures += 1
            return Snapshot(error=(err or "the server returned nothing").strip()[:200])
        snapshot = self.parse(out)
        if snapshot.empty:
            self.failures += 1
            snapshot.error = snapshot.error or "nothing to read on this server"
        else:
            self.failures = 0
        return snapshot

    def parse(self, text: str) -> Snapshot:
        sections = _sections(text)
        snapshot = Snapshot()

        stat = sections.get("stat") or []
        times = parse_cpu_times(stat[0]) if stat else None
        if times:
            if self._previous:
                total_delta = times[0] - self._previous[0]
                idle_delta = times[1] - self._previous[1]
                if total_delta > 0:
                    snapshot.cpu = max(0.0, min(100.0,
                                                (1 - idle_delta / total_delta) * 100))
            self._previous = times

        snapshot.mem_used, snapshot.mem_total = parse_meminfo(sections.get("mem", []))
        swap_values: dict[str, int] = {}
        for line in sections.get("swap", []):
            name, _, rest = line.partition(":")
            number = rest.strip().split(" ")[0]
            if number.isdigit():
                swap_values[name.strip()] = int(number) * 1024
        if swap_values.get("SwapTotal"):
            snapshot.swap_total = swap_values["SwapTotal"]
            snapshot.swap_used = snapshot.swap_total - swap_values.get("SwapFree", 0)

        snapshot.load = parse_load(sections.get("load", []))
        sysctl = [line.strip() for line in sections.get("sysctl", []) if line.strip()]
        if sysctl and sysctl[0].isdigit() and not snapshot.mem_total:
            snapshot.mem_total = int(sysctl[0])          # BSD: total only
        if len(sysctl) > 1 and sysctl[1].isdigit():
            snapshot.cores = int(sysctl[1])
        snapshot.disks = parse_df(sections.get("df", []))
        return snapshot


__all__ = ["COMMAND", "Disk", "MetricsSampler", "Snapshot", "human", "parse_cpu_times",
           "parse_df", "parse_load", "parse_meminfo"]
