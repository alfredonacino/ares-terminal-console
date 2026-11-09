"""Performance check: what is behind high CPU, high load and high memory on a
server - sampled, attributed to processes, judged, and packaged for later
analysis by a person or by an AI model.

A port of TractorBeam's performance check (``tractorbeam/perf.py``), kept
deliberately close to it: the same sampler, the same record tags, the same
rules and thresholds, the same report. The two parsers read each other's
output. What differs is only the transport and the wording - TractorBeam's
targets are USM sensors reached through a PTY, ARES's are any Linux server,
reached on an SSH channel of the check's own:

  * the sampler is sent on standard input to ``sh -s``, so it needs neither
    the base64 wrapping a PTY forced on TractorBeam nor a muted terminal;
  * a long run (minutes to hours) stays on that channel and is streamed back
    as it goes, rather than left behind as a ``nohup`` job in /tmp. Closing the
    tab, or Stop, ends it; nothing is left running on the server.

**This module never touches a server.** It composes the sampler (a POSIX
shell script) and parses what that script printed; the channel is the
caller's.

Why sampling, and not `top -bn1` or `ps`:

- **`ps %CPU` is a lifetime average**, so a process that has been idle for a
  week and is pegging a core right now reads as 0.3%. CPU here is always the
  DELTA of `utime+stime` between two samples over the time between them.
- **One `top` frame is one moment.** Load and memory pressure are trends; a
  report that cannot say "rising" or "every 30 s" cannot explain a load
  average, which is itself a 1/5/15-minute decay.
- **Short-lived processes are invisible to both.** A cron script or a monit
  check that forks two hundred `grep`s a minute never appears in any frame,
  yet it is the CPU. Their time lands in the PARENT's `cutime+cstime` when
  they are reaped, so the sampler records that too ("child CPU"), and the
  report compares the CPU the kernel says was used with the CPU it can
  attribute to a process - the gap is churn.

The sampler sends **only what changed** per process (new, updated, exited),
keeping its previous view in a temp dir. An idle server has ~250 processes,
most of them kernel threads that never move; resending all of them every
sample is what would make an hour-long run large.

Read-only: it reads /proc, /etc/passwd and (with `sudo -n`, never prompting)
the kernel ring buffer for OOM kills and the owners of sockets. Its only
write is its own temp directory, removed on exit.

Linux only, like TractorBeam's: it is /proc from end to end. A server without
/proc answers ``TBPNOPROC`` and the caller falls back to the one-shot
analysis in :mod:`ares.protocols.serverinsight`.
"""

from __future__ import annotations

PERF_LABEL = "perf-check"

#: (samples, interval in seconds) for the two short runs: ~10 s and ~30 s.
PRESETS = {"quick": (6, 2), "standard": (11, 3)}
#: A long run: how long, and how often. TractorBeam's background choices.
LONG_DURATIONS = (5 * 60, 10 * 60, 30 * 60, 60 * 60, 120 * 60)
LONG_INTERVALS = (5, 10, 15, 30, 60)
LONG_MIN_S, LONG_MAX_S = 60, 2 * 3600
MODE_LABELS = {"quick": "quick", "standard": "standard", "long": "long"}
#: What a server without /proc prints instead of a header.
NO_PROC = "TBPNOPROC"

TOP_N = 15

# The awk that turns `cat /proc/[0-9]*/stat` into deltas. POSIX, and no
# single quote (it is spliced into one -- asserted in sampler_script).
#
# comm is in parentheses and may itself contain spaces and ")", so the record
# is split on the LAST ") ": everything after it is the fixed-format tail.
# Field numbers below are 1-based into that tail, i.e. proc(5) field N-2.
#
# The signature includes the start time, so a pid reused inside the window is
# reported as a new process rather than as the old one suddenly using an hour
# of CPU.
_PROC_AWK = r"""
BEGIN {
  while ((getline l < prev) > 0) { split(l, a, " "); P[a[1]] = a[2] }
  close(prev)
}
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
  st = f[1]; ppid = f[2]
  if (pid == self || ppid == self || ppid == pself) next
  tk = f[12] + f[13]; ct = f[14] + f[15]; th = f[18]; stt = f[20]; rss = f[22]
  sig = stt ":" st ":" tk ":" ct ":" rss ":" th
  print pid " " sig > cur
  seen[pid] = 1
  isnew = !(pid in P)
  if (!isnew) { split(P[pid], q, ":"); if (q[1] != stt) isnew = 1 }
  if (isnew) {
    gsub(/[^ -~]/, "?", comm); gsub(/\|/, "/", comm)
    printf "TBPP|%s|%s|%s|%.0f|%.0f|%s|%s|%s|%s\n", pid, ppid, st, tk, ct, th, rss, stt, comm
    print pid > newf
  } else if (P[pid] != sig) {
    printf "TBPU|%s|%s|%.0f|%.0f|%s|%s\n", pid, st, tk, ct, th, rss
  }
}
END {
  for (p in P) if (!(p in seen)) print "TBPX|" p
}
"""


# The awk that turns `ss -tanp` / `ss -uanp` (or `netstat -tunap`) into a
# connection snapshot: listening sockets, and established ones aggregated by
# direction, service port, remote host and owning process. POSIX, no single
# quote, same as _PROC_AWK.
#
# Every input line is prefixed with its protocol ("tcp " / "udp ") by the
# sampler, because ss prints no Netid column when asked for one protocol.
#
# A connection is INBOUND when its local port is one this host listens on
# for that protocol. That is the definition a person means by "who is
# connected to us": a syslog source on 6514, an SSH session on 22. Everything
# else is outbound, keyed by the REMOTE port (the service we are using).
#
# Aggregated on the server so a collector with thousands of sources sends a
# few hundred lines, not thousands; past CONN_KEYS distinct keys the remote
# host is folded into "(other)" so a scan cannot make the snapshot grow with
# the internet.
#
# The IPv6 brackets are stripped by slicing, not by a bracket expression:
# `/[\[\]]/` is read three different ways by gawk, mawk and busybox awk.
_CONN_AWK = r"""
function port(a,  i) { i = match(a, /:[^:]*$/); return i ? substr(a, i + 1) : "" }
function host(a,  h) {
  h = substr(a, 1, length(a) - length(port(a)) - 1)
  if (substr(h, 1, 1) == "[") h = substr(h, 2, length(h) - 2)
  sub(/^::ffff:/, "", h); sub(/%.*$/, "", h)
  return h
}
function owner(s,  p, q) {
  if (match(s, /\(\("[^"]*",pid=[0-9]+/)) {
    p = substr(s, RSTART + 3, RLENGTH - 3)
    q = index(p, "\",pid=")
    return substr(p, 1, q - 1) "/" substr(p, q + 6)
  }
  if (match(s, /^[0-9]+\/./)) {
    q = index(s, "/"); p = substr(s, q + 1); sub(/:$/, "", p)
    return p "/" substr(s, 1, q - 1)
  }
  return ""
}
{
  pr = $1
  if (src == "ss") {
    if (NF < 6) next
    st = $2; la = $5; ra = $6; ow = ""
    for (j = 7; j <= NF; j++) ow = ow $j
  } else {
    if ($2 !~ /^(tcp|udp)/) next
    la = $5; ra = $6
    if (pr == "udp") { st = ($7 ~ /^[A-Z]/) ? $7 : "UNCONN"; ow = ($7 ~ /^[A-Z]/) ? $8 : $7 }
    else { st = $7; ow = $8 }
  }
  if (st == "State" || st == "") next
  if (st == "ESTABLISHED") st = "ESTAB"
  gsub(/_/, "-", st)
  ow = owner(ow); gsub(/\|/, "/", ow)
  lp = port(la)
  if (st == "LISTEN" || (pr == "udp" && st == "UNCONN")) {
    k = pr "/" lp
    if (!(k in L)) { L[k] = 1; LA[k] = host(la); LO[k] = ow; nl++ }
    else if (LO[k] == "" && ow != "") LO[k] = ow
    next
  }
  ST[pr "/" st]++
  n++; CP[n] = pr; CS[n] = st; CL[n] = lp; CR[n] = port(ra); CH[n] = host(ra); CO[n] = ow
}
END {
  for (k in L) { split(k, a, "/"); print "TBPA|" a[1] "|" a[2] "|" LA[k] "|" LO[k] }
  for (k in ST) { split(k, a, "/"); print "TBPY|" a[1] "|" a[2] "|" ST[k] }
  nk = 0
  for (i = 1; i <= n; i++) {
    d = ((CP[i] "/" CL[i]) in L) ? "in" : "out"
    sp = (d == "in") ? CL[i] : CR[i]
    key = d "|" CP[i] "|" sp "|" CH[i] "|" CO[i]
    if (!(key in K)) {
      if (nk >= maxk) key = d "|" CP[i] "|" sp "|(other)|" CO[i]
      if (!(key in K)) nk++
    }
    K[key]++
    if (CS[i] == "ESTAB") E[key]++
  }
  for (key in K) print "TBPO|" key "|" K[key] "|" (E[key] + 0)
  print "TBPT|" src "|" n "|" nl
}
"""

CONN_KEYS = 300


class PerfError(Exception):
    pass


def long_params(duration: str | int, interval: str | int) -> tuple[int, int]:
    """(samples, interval) for a long run. Raises PerfError."""
    try:
        d, i = int(str(duration).strip()), int(str(interval).strip())
    except ValueError:
        raise PerfError("duration and interval must be whole numbers of seconds")
    if not (LONG_MIN_S <= d <= LONG_MAX_S):
        raise PerfError(f"duration must be between {LONG_MIN_S // 60} min and "
                        f"{LONG_MAX_S // 3600} h")
    if i not in LONG_INTERVALS:
        raise PerfError(f"interval must be one of {', '.join(map(str, LONG_INTERVALS))} s")
    if d // i < 2:
        raise PerfError("the window must hold at least two samples")
    return d // i + 1, i


def params(mode: str, duration: int = 0, interval: int = 0) -> tuple[int, int]:
    """(samples, interval) for a mode: ``quick``, ``standard`` or ``long``."""
    if mode in PRESETS:
        return PRESETS[mode]
    if mode == "long":
        return long_params(duration, interval)
    raise PerfError(f"unknown mode {mode!r}")


def sampler_script(samples: int, interval: int) -> str:
    """The sampler, as a shell script. `samples` x `interval` are trusted ints."""
    samples, interval = int(samples), int(interval)
    assert 2 <= samples <= 2000 and 1 <= interval <= 600
    assert "'" not in _PROC_AWK and "'" not in _CONN_AWK
    # A connection snapshot on the first sample, the last, and about every
    # five minutes between: ss is cheap, but a collector with thousands of
    # sockets makes each snapshot a few KB, and an hour at 5 s would be 720.
    every = max(1, 300 // interval)
    return f"""[ -r /proc/stat ] || {{ echo "{NO_PROC}|$(uname -s 2>/dev/null)"; exit 0; }}
S=""; [ "$(id -u)" -eq 0 ] || S="sudo -n"
W=$(mktemp -d /tmp/ares-perf.XXXXXX 2>/dev/null) || {{ W=/tmp/ares-perf.$$; mkdir -p "$W"; }}
trap 'rm -rf "$W"' EXIT
trap 'rm -rf "$W"; exit 143' TERM INT HUP PIPE
N={samples}; I={interval}
CLK=$(getconf CLK_TCK 2>/dev/null || echo 100)
PG=$(getconf PAGESIZE 2>/dev/null || echo 4096)
NC=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
MODEL=$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' | tr '|' '/')
echo "TBPH|$(date +%s)|$N|$I|$CLK|$PG|$NC|$(hostname 2>/dev/null | tr '|' '/')|$(uname -r)|$MODEL"
awk -F: '{{print "TBPW|" $3 "|" $1}}' /etc/passwd 2>/dev/null
SELF=$$; PSELF=$PPID
: > "$W/prev"
k=1
while [ "$k" -le "$N" ]; do
  echo "TBPS|$k|$(date +%s)|$(cut -d' ' -f1 /proc/uptime)"
  echo "TBPL|$(cat /proc/loadavg)"
  awk '/^cpu /{{$1=""; print "TBPC|" substr($0, 2)}} /^(procs_running|procs_blocked|processes|ctxt) /{{print "TBPQ|" $1 "|" $2}}' /proc/stat
  awk '/^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree|Shmem|SReclaimable|Dirty|Committed_AS|CommitLimit):/{{sub(":", "", $1); print "TBPM|" $1 "|" $2}}' /proc/meminfo
  awk '/^(pswpin|pswpout|pgmajfault|oom_kill) /{{print "TBPV|" $1 "|" $2}}' /proc/vmstat 2>/dev/null
  for r in cpu memory io; do [ -r /proc/pressure/$r ] && sed "s/^/TBPI|$r|/" /proc/pressure/$r; done
  awk 'NR > 2 {{ i = index($0, ":"); n = substr($0, 1, i - 1); gsub(/ /, "", n); m = split(substr($0, i + 1), v, " "); if (m >= 12) print "TBPD|" n "|" v[1] "|" v[2] "|" v[3] + v[4] "|" v[9] "|" v[10] "|" v[11] + v[12] }}' /proc/net/dev 2>/dev/null
  if [ "$k" -eq 1 ] || [ "$k" -eq "$N" ] || [ $((k % {every})) -eq 0 ]; then
    if command -v ss >/dev/null 2>&1; then
      {{ {{ $S ss -tanp 2>/dev/null || ss -tanp 2>/dev/null || ss -tan 2>/dev/null; }} | sed 's/^/tcp /'
        {{ $S ss -uanp 2>/dev/null || ss -uanp 2>/dev/null || ss -uan 2>/dev/null; }} | sed 's/^/udp /'; }} \
        | awk -v src=ss -v maxk={CONN_KEYS} '{_CONN_AWK}'
    elif command -v netstat >/dev/null 2>&1; then
      {{ $S netstat -tunap 2>/dev/null || netstat -tunap 2>/dev/null || netstat -tuna 2>/dev/null; }} \
        | awk '{{ p = ($1 ~ /^udp/) ? "udp" : "tcp"; print p " " $0 }}' \
        | awk -v src=netstat -v maxk={CONN_KEYS} '{_CONN_AWK}'
    else
      echo "TBPT|none|0|0"
    fi
  fi
  : > "$W/cur"; : > "$W/new"
  cat /proc/[0-9]*/stat 2>/dev/null | awk -v self="$SELF" -v pself="$PSELF" -v prev="$W/prev" -v cur="$W/cur" -v newf="$W/new" '{_PROC_AWK}'
  mv "$W/cur" "$W/prev"
  while read p; do
    u=$(awk '/^Uid:/{{print $2; exit}}' /proc/$p/status 2>/dev/null)
    c=$(tr '\\000' ' ' < /proc/$p/cmdline 2>/dev/null | head -c 300 | tr -c '[:print:]' '?' | tr '|' '/')
    echo "TBPN|$p|$u|$c"
  done < "$W/new"
  echo "TBPZ|$k"
  k=$((k + 1))
  [ "$k" -le "$N" ] && sleep "$I"
done
{{ $S dmesg -T 2>/dev/null || $S dmesg 2>/dev/null; }} | grep -iE 'out of memory|oom-kill|killed process|oom_reaper' | tail -n 20 | tr '|' '/' | sed 's/^/TBPK|/'
echo "TBPE|$(date +%s)"
"""


def no_proc(text: str) -> str:
    """The server's own name for its system when it has no /proc, else ""."""
    for line in (text or "").splitlines():
        if line.startswith(NO_PROC):
            return line.partition("|")[2].strip() or "this system"
    return ""


# =============================================================================
# Parsing
# =============================================================================

def _i(s, d=0):
    try:
        return int(float(s))
    except (TypeError, ValueError):
        return d


def _f(s, d=0.0):
    try:
        return float(s)
    except (TypeError, ValueError):
        return d


def parse(text: str) -> dict:
    """Replay the record stream into samples. Only COMPLETE samples (closed by
    TBPZ) are kept: a long run stopped mid-sample, or a read that ended
    mid-sample, must not contribute half a sample's deltas."""
    out = {"start": 0, "n": 0, "interval": 0, "clk": 100, "page": 4096, "ncpu": 0,
           "host": "", "kernel": "", "model": "", "users": {}, "cmd": {},
           "samples": [], "oom": [], "end": 0, "conn": None}
    procs: dict[str, dict] = {}
    pending: list[tuple[str, list[str]]] = []
    cur: dict | None = None

    def apply(tag, f):
        if tag == "TBPP" and len(f) >= 9:
            procs[f[0]] = {"ppid": f[1], "st": f[2], "tk": _i(f[3]), "ct": _i(f[4]),
                           "th": _i(f[5]), "rss": _i(f[6]), "stt": f[7],
                           "comm": "|".join(f[8:])}
        elif tag == "TBPU" and len(f) >= 6 and f[0] in procs:
            p = procs[f[0]]
            p["st"], p["tk"], p["ct"], p["th"], p["rss"] = f[1], _i(f[2]), _i(f[3]), _i(f[4]), _i(f[5])
        elif tag == "TBPX" and f:
            procs.pop(f[0], None)
        elif tag == "TBPN" and len(f) >= 2:
            out["cmd"][f[0]] = (f[1], "|".join(f[2:]).strip())

    for raw in text.splitlines():
        line = raw.strip()
        if len(line) < 5 or not line.startswith("TBP") or line[4] != "|":
            continue
        tag, _, rest = line.partition("|")
        f = rest.split("|")
        if tag == "TBPH" and len(f) >= 9:
            out.update(start=_i(f[0]), n=_i(f[1]), interval=_i(f[2]), clk=_i(f[3], 100) or 100,
                       page=_i(f[4], 4096) or 4096, ncpu=_i(f[5]), host=f[6], kernel=f[7],
                       model="|".join(f[8:]))
        elif tag == "TBPW" and len(f) >= 2:
            out["users"][f[0]] = f[1]
        elif tag == "TBPS" and len(f) >= 3:
            cur = {"seq": _i(f[0]), "t": _i(f[1]), "up": _f(f[2]), "load": [], "run": "",
                   "cpu": [], "q": {}, "mem": {}, "vm": {}, "psi": {}, "net": {}, "conn": None}
            pending = []
        elif cur is None:
            if tag == "TBPK":
                out["oom"].append(rest.strip())
            elif tag == "TBPE":
                out["end"] = _i(f[0])
            continue
        elif tag == "TBPL":
            parts = rest.split()
            cur["load"] = [_f(x) for x in parts[:3]]
            cur["run"] = parts[3] if len(parts) > 3 else ""
        elif tag == "TBPC":
            cur["cpu"] = [_i(x) for x in rest.split()]
        elif tag == "TBPQ" and len(f) >= 2:
            cur["q"][f[0]] = _i(f[1])
        elif tag == "TBPM" and len(f) >= 2:
            cur["mem"][f[0]] = _i(f[1])
        elif tag == "TBPV" and len(f) >= 2:
            cur["vm"][f[0]] = _i(f[1])
        elif tag == "TBPI" and len(f) >= 2:
            kind = f[1].split()[0] if f[1].split() else ""
            vals = dict(kv.split("=", 1) for kv in f[1].split()[1:] if "=" in kv)
            cur["psi"].setdefault(f[0], {})[kind] = _f(vals.get("avg10"))
        elif tag == "TBPD" and len(f) >= 7:
            # iface -> rx bytes, rx packets, rx errs+drops, tx bytes, tx packets, tx errs+drops
            cur["net"][f[0]] = tuple(_i(x) for x in f[1:7])
        elif tag in ("TBPA", "TBPO", "TBPY", "TBPT"):
            c = cur["conn"]
            if c is None:
                c = cur["conn"] = {"source": "", "listen": [], "flows": [], "states": {},
                                   "total": 0, "t": cur["t"]}
            if tag == "TBPA" and len(f) >= 4:
                c["listen"].append({"proto": f[0], "port": _i(f[1]), "addr": f[2],
                                    "owner": "|".join(f[3:])})
            elif tag == "TBPO" and len(f) >= 7:
                c["flows"].append({"dir": f[0], "proto": f[1], "port": _i(f[2]), "host": f[3],
                                   "owner": f[4], "count": _i(f[5]), "estab": _i(f[6])})
            elif tag == "TBPY" and len(f) >= 3:
                c["states"][f"{f[0]}/{f[1]}"] = _i(f[2])
            elif tag == "TBPT" and len(f) >= 1:
                c["source"] = f[0]
                c["total"] = _i(f[1]) if len(f) > 1 else 0
        elif tag in ("TBPP", "TBPU", "TBPX", "TBPN"):
            pending.append((tag, f))
        elif tag == "TBPZ":
            for t, ff in pending:
                apply(t, ff)
            pending = []
            cur["procs"] = {pid: (p["stt"], p["st"], p["tk"], p["ct"], p["rss"], p["th"])
                            for pid, p in procs.items()}
            out["samples"].append(cur)
            # The newest COMPLETE snapshot wins: a half-printed one from a
            # sample that never closed would undercount every port.
            if cur["conn"] is not None and cur["conn"]["source"]:
                out["conn"] = cur["conn"]
            cur = None
        elif tag == "TBPK":
            out["oom"].append(rest.strip())
        elif tag == "TBPE":
            out["end"] = _i(f[0])
    out["procinfo"] = {pid: {"ppid": p["ppid"], "comm": p["comm"]} for pid, p in procs.items()}
    # Processes that exited still need a name in the tables; keep the last
    # one seen. Rebuilt cheaply from the TBPP lines.
    for raw in text.splitlines():
        if raw.startswith("TBPP|"):
            f = raw.strip().split("|")[1:]
            if len(f) >= 9 and f[0] not in out["procinfo"]:
                out["procinfo"][f[0]] = {"ppid": f[1], "comm": "|".join(f[8:])}
    return out


# =============================================================================
# Analysis
# =============================================================================

def _mib(kb: float) -> float:
    return kb / 1024.0


# Interfaces that carry another interface's traffic a second time. A bridge
# and each of its veths count the same packet twice, so a total that included
# them would report a container's download as double the link.
_VIRTUAL_IF = ("lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "vxlan", "kube")


def _is_virtual(name: str) -> bool:
    return name == "lo" or name.startswith(_VIRTUAL_IF[1:])


def _network(S: list, dt, window: float) -> dict:
    """Per-interface throughput from /proc/net/dev deltas, and the series.

    Rates are bits per second over the WINDOW (quiet intervals count), the
    same reading traffic.py gives an average. A counter that went backwards
    is an interface that was re-created; that interval is skipped for it
    rather than reported as negative traffic."""
    per: dict[str, dict] = {}
    srx, stx = [], []
    for i in range(1, len(S)):
        a, b = S[i - 1]["net"], S[i]["net"]
        d = dt(S[i - 1], S[i])
        trx = ttx = 0.0
        seen = False
        for name, vb in b.items():
            va = a.get(name)
            if va is None:
                continue
            dl = [vb[k] - va[k] for k in range(6)]
            if dl[0] < 0 or dl[3] < 0:
                continue
            g = per.setdefault(name, {"name": name, "rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0,
                                      "tx_packets": 0, "rx_err_drop": 0, "tx_err_drop": 0,
                                      "rx_peak_mbps": 0.0, "tx_peak_mbps": 0.0,
                                      "virtual": _is_virtual(name)})
            g["rx_bytes"] += dl[0]; g["rx_packets"] += max(0, dl[1]); g["rx_err_drop"] += max(0, dl[2])
            g["tx_bytes"] += dl[3]; g["tx_packets"] += max(0, dl[4]); g["tx_err_drop"] += max(0, dl[5])
            rx, tx = dl[0] * 8 / d / 1e6, dl[3] * 8 / d / 1e6
            g["rx_peak_mbps"] = max(g["rx_peak_mbps"], rx)
            g["tx_peak_mbps"] = max(g["tx_peak_mbps"], tx)
            if not g["virtual"]:
                trx += rx; ttx += tx; seen = True
        srx.append(round(trx, 3) if seen else None)
        stx.append(round(ttx, 3) if seen else None)
    ifaces = []
    for g in per.values():
        g["rx_mbps"] = round(g["rx_bytes"] * 8 / window / 1e6, 3)
        g["tx_mbps"] = round(g["tx_bytes"] * 8 / window / 1e6, 3)
        g["rx_peak_mbps"] = round(g["rx_peak_mbps"], 3)
        g["tx_peak_mbps"] = round(g["tx_peak_mbps"], 3)
        if g["name"] != "lo":
            ifaces.append(g)
    ifaces.sort(key=lambda g: (g["virtual"], -(g["rx_bytes"] + g["tx_bytes"])))
    phys = [g for g in ifaces if not g["virtual"]]
    # Interfaces that moved nothing are named, not tabled: a server with a
    # dozen idle bridges would otherwise bury the two that matter.
    idle = [g["name"] for g in ifaces if not (g["rx_bytes"] or g["tx_bytes"]
                                              or g["rx_err_drop"] or g["tx_err_drop"])]
    ifaces = [g for g in ifaces if g["name"] not in idle]
    vals = lambda xs: [x for x in xs if x is not None]
    return {"ifaces": ifaces, "idle": idle, "series_rx": srx, "series_tx": stx,
            "rx_mbps": round(sum(g["rx_mbps"] for g in phys), 3),
            "tx_mbps": round(sum(g["tx_mbps"] for g in phys), 3),
            "rx_peak_mbps": max(vals(srx), default=0.0),
            "tx_peak_mbps": max(vals(stx), default=0.0),
            "rx_bytes": sum(g["rx_bytes"] for g in phys),
            "tx_bytes": sum(g["tx_bytes"] for g in phys)}


def _loopback(h: str) -> bool:
    return h.startswith("127.") or h in ("::1", "localhost")


def _split_owner(o: str) -> tuple[str, int]:
    name, _, pid = o.rpartition("/")
    return (name, int(pid)) if pid.isdigit() and name else (o, 0)


def _connections(c: dict | None, procs_by_pid: dict) -> dict:
    """The newest connection snapshot, shaped for reading.

    INBOUND = the local port is one this host listens on (see _CONN_AWK).
    Loopback traffic is counted separately as `local`: a server's own
    services talk to each other over 127.0.0.1 all day, and folding that into
    "inbound" would make rabbitmq the busiest remote peer on every server."""
    empty = {"measured": False, "source": "", "t": 0, "listen": [], "inbound": [], "outbound": [],
             "processes": [], "states": {}, "inbound_total": 0, "inbound_hosts": 0,
             "outbound_total": 0, "local_total": 0, "owners_known": False, "total": 0}
    if not c or c.get("source") in ("", "none"):
        return empty
    inb: dict[tuple, dict] = {}
    outb: dict[tuple, dict] = {}
    owners: dict[str, dict] = {}
    hosts_in: set[str] = set()
    local = 0

    def owner_row(o: str) -> dict:
        name, pid = _split_owner(o)
        r = owners.setdefault(o, {"owner": o, "name": name or "(unknown)", "pid": pid,
                                  "inbound": 0, "outbound": 0, "local": 0, "listen": []})
        return r

    for f in c["flows"]:
        o = f["owner"]
        if _loopback(f["host"]):
            local += f["count"]
            owner_row(o)["local"] += f["count"]
            continue
        if f["dir"] == "in":
            k = (f["proto"], f["port"])
            g = inb.setdefault(k, {"proto": f["proto"], "port": f["port"], "owners": set(),
                                   "count": 0, "estab": 0, "peers": {}})
            g["count"] += f["count"]; g["estab"] += f["estab"]
            if o:
                g["owners"].add(_split_owner(o)[0])
            g["peers"][f["host"]] = g["peers"].get(f["host"], 0) + f["count"]
            if f["host"] != "(other)":
                hosts_in.add(f["host"])
            owner_row(o)["inbound"] += f["count"]
        else:
            k = (f["proto"], f["port"], f["host"])
            g = outb.setdefault(k, {"proto": f["proto"], "port": f["port"], "host": f["host"],
                                    "owners": set(), "count": 0, "estab": 0})
            g["count"] += f["count"]; g["estab"] += f["estab"]
            if o:
                g["owners"].add(_split_owner(o)[0])
            owner_row(o)["outbound"] += f["count"]
    for l in c["listen"]:
        if l["owner"]:
            owner_row(l["owner"])["listen"].append(f"{l['proto']}/{l['port']}")

    inbound = []
    for g in sorted(inb.values(), key=lambda g: -g["count"]):
        peers = sorted(g["peers"].items(), key=lambda kv: -kv[1])
        inbound.append({"proto": g["proto"], "port": g["port"], "owner": ", ".join(sorted(g["owners"])),
                        "count": g["count"], "estab": g["estab"],
                        "peers": len([h for h in g["peers"] if h != "(other)"]),
                        "top_peers": [{"host": h, "count": n} for h, n in peers[:5]]})
    outbound = [{**{k: v for k, v in g.items() if k != "owners"},
                 "owner": ", ".join(sorted(g["owners"]))}
                for g in sorted(outb.values(), key=lambda g: -g["count"])]
    procs = []
    for r in owners.values():
        if not r["owner"]:
            continue
        pr = procs_by_pid.get(r["pid"], {})
        procs.append({**r, "listen": sorted(set(r["listen"]), key=lambda x: int(x.split("/")[1])),
                      "total": r["inbound"] + r["outbound"] + r["local"],
                      "cpu_avg": round(pr.get("cpu_avg", 0.0), 1), "rss_mib": round(pr.get("rss_mib", 0.0), 1),
                      "user": pr.get("user", ""), "cmd": pr.get("cmd", "")})
    procs.sort(key=lambda r: (-(r["inbound"] + r["outbound"]), -r["local"], -len(r["listen"])))
    listen = sorted(c["listen"], key=lambda l: (l["proto"], l["port"]))
    for l in listen:
        l["exposed"] = not _loopback(l["addr"])
    return {"measured": True, "source": c["source"], "t": c["t"], "total": c["total"],
            "listen": listen, "inbound": inbound[:TOP_N * 2], "outbound": outbound[:TOP_N * 2],
            "processes": procs[:TOP_N * 2], "states": c["states"],
            "inbound_total": sum(g["count"] for g in inbound),
            "inbound_hosts": len(hosts_in),
            "outbound_total": sum(g["count"] for g in outbound), "local_total": local,
            "owners_known": any(f["owner"] for f in c["flows"]) or any(l["owner"] for l in c["listen"])}


def report(text: str, status: str = "finished", mode: str = "standard") -> dict:
    p = parse(text)
    S = p["samples"]
    clk, page, ncpu = p["clk"], p["page"], p["ncpu"] or 1
    live = status == "running"
    base = {"mode": mode, "live": live, "host": p["host"], "kernel": p["kernel"],
            "model": p["model"], "ncpu": ncpu, "samples": len(S),
            "requested_samples": p["n"], "interval": p["interval"],
            "start": S[0]["t"] if S else p["start"]}
    if len(S) < 2:
        base.update(state="running" if live else "incomplete", verdict="info",
                    findings=[] if live else [{"status": "warn", "title": "Not enough samples",
                              "detail": "At least two complete samples are needed to measure a rate."}],
                    window_s=0, ai_pack="")
        return base

    def dt(a, b):
        d = b["up"] - a["up"]
        return d if d > 0 else max(1, b["t"] - a["t"])

    window = sum(dt(S[i - 1], S[i]) for i in range(1, len(S)))

    # ---- system CPU, per interval --------------------------------------------
    rows = []
    for i in range(1, len(S)):
        a, b = S[i - 1], S[i]
        ca, cb = a["cpu"] + [0] * 10, b["cpu"] + [0] * 10
        d = [max(0, cb[k] - ca[k]) for k in range(8)]  # user nice sys idle iow irq sirq steal
        tot = sum(d) or 1
        idle, iow, steal = d[3], d[4], d[7]
        rows.append({
            "t": b["t"], "dt": dt(a, b),
            "busy": 100.0 * (tot - idle - iow) / tot,
            "user": 100.0 * (d[0] + d[1]) / tot, "system": 100.0 * d[2] / tot,
            "iowait": 100.0 * iow / tot, "irq": 100.0 * (d[5] + d[6]) / tot,
            "steal": 100.0 * steal / tot,
            "busy_jiffies": d[0] + d[1] + d[2],
            "load1": b["load"][0] if b["load"] else 0.0,
            "load5": b["load"][1] if len(b["load"]) > 1 else 0.0,
            "load15": b["load"][2] if len(b["load"]) > 2 else 0.0,
            "running": b["q"].get("procs_running", 0), "blocked": b["q"].get("procs_blocked", 0),
        })
    mean = lambda k: sum(r[k] for r in rows) / len(rows)
    cpu = {k: round(mean(k), 1) for k in ("busy", "user", "system", "iowait", "irq", "steal")}
    cpu["busy_peak"] = round(max(r["busy"] for r in rows), 1)

    # ---- load ----------------------------------------------------------------
    last = S[-1]
    l1s = [s["load"][0] for s in S if s["load"]]
    load = {"last": last["load"], "max1": max(l1s) if l1s else 0.0,
            "per_cpu": round((last["load"][0] if last["load"] else 0) / ncpu, 2),
            "running_avg": round(mean("running"), 1), "blocked_avg": round(mean("blocked"), 1),
            "blocked_max": max(r["blocked"] for r in rows)}

    # ---- memory --------------------------------------------------------------
    def memrow(s):
        m = s["mem"]
        tot = m.get("MemTotal", 0) or 1
        av = m.get("MemAvailable", m.get("MemFree", 0) + m.get("Cached", 0))
        st, sf = m.get("SwapTotal", 0), m.get("SwapFree", 0)
        return {"used_pct": 100.0 * (tot - av) / tot, "avail_mib": _mib(av),
                "total_mib": _mib(tot), "swap_used_mib": _mib(st - sf),
                "swap_total_mib": _mib(st),
                "commit_pct": 100.0 * m.get("Committed_AS", 0) / (m.get("CommitLimit", 0) or 1)}
    mrows = [memrow(s) for s in S]
    first_vm, last_vm = S[0]["vm"], last["vm"]
    vmd = {k: max(0, last_vm.get(k, 0) - first_vm.get(k, 0)) for k in
           ("pswpin", "pswpout", "pgmajfault", "oom_kill")}
    mem = {**{k: round(v, 1) for k, v in mrows[-1].items()},
           "used_pct_max": round(max(r["used_pct"] for r in mrows), 1),
           "swap_in_per_s": round(vmd["pswpin"] / window, 1),
           "swap_out_per_s": round(vmd["pswpout"] / window, 1),
           "majfault_per_s": round(vmd["pgmajfault"] / window, 1),
           "oom_kills_in_window": vmd["oom_kill"]}
    psi = last["psi"]

    # ---- uptime --------------------------------------------------------------
    # /proc/uptime of the last sample. The boot time is derived from the
    # SERVER's clock (its own `date +%s` minus its own uptime), never from
    # this workstation's, so a skewed laptop does not move the reboot.
    uptime_s = int(last["up"])
    boot_t = last["t"] - uptime_s if uptime_s else 0

    # ---- network throughput --------------------------------------------------
    net = _network(S, dt, window)

    forks_per_s = round(max(0, last["q"].get("processes", 0) - S[0]["q"].get("processes", 0)) / window, 1)

    # ---- per process ---------------------------------------------------------
    agg: dict[str, dict] = {}
    for i in range(1, len(S)):
        a, b = S[i - 1]["procs"], S[i]["procs"]
        d = dt(S[i - 1], S[i])
        for pid, pb in b.items():
            pa = a.get(pid)
            g = agg.setdefault(pid, {"tk": 0, "ct": 0, "peak": 0.0, "series": {},
                                     "rss": [], "dstates": 0, "present": 0, "th": 0})
            g["rss"].append(pb[4])
            g["th"] = pb[5]
            g["present"] += 1
            if pb[1] == "D":
                g["dstates"] += 1
            if pa is None or pa[0] != pb[0]:
                continue
            dtk, dct = max(0, pb[2] - pa[2]), max(0, pb[3] - pa[3])
            g["tk"] += dtk
            g["ct"] += dct
            pct = 100.0 * dtk / (clk * d)
            g["peak"] = max(g["peak"], pct)
            g["series"][i] = pct
    # The first sample's RSS too, so growth is measured over the whole window.
    for pid, pv in S[0]["procs"].items():
        if pid in agg:
            agg[pid]["rss"].insert(0, pv[4])

    users, cmds, info = p["users"], p["cmd"], p["procinfo"]

    def ident(pid):
        uid, cmd = cmds.get(pid, ("", ""))
        inf = info.get(pid, {})
        return {"pid": int(pid), "ppid": _i(inf.get("ppid")), "user": users.get(uid, uid),
                "comm": inf.get("comm", "?"), "cmd": cmd or f"[{inf.get('comm', '?')}]"}

    procs = []
    for pid, g in agg.items():
        r = g["rss"] or [0]
        procs.append({**ident(pid),
                      "cpu_avg": 100.0 * g["tk"] / (clk * window),
                      "cpu_peak": g["peak"],
                      "child_cpu": 100.0 * g["ct"] / (clk * window),
                      "threads": g["th"],
                      "rss_mib": r[-1] * page / 1048576, "rss_first_mib": r[0] * page / 1048576,
                      "rss_max_mib": max(r) * page / 1048576,
                      "rss_growth_mib": (r[-1] - r[0]) * page / 1048576,
                      "dstate_samples": g["dstates"], "present": g["present"],
                      "full_window": g["present"] == len(S) - 1,
                      "_series": g["series"]})

    def clean(rows_):
        return [{k: (round(v, 1) if isinstance(v, float) else v) for k, v in r.items()
                 if not k.startswith("_")} for r in rows_]

    by_cpu = sorted(procs, key=lambda r: -r["cpu_avg"])
    by_mem = sorted(procs, key=lambda r: -r["rss_mib"])
    growth = sorted([r for r in procs if r["full_window"] and r["rss_growth_mib"] >= 20
                     and r["rss_growth_mib"] >= 0.05 * max(r["rss_first_mib"], 1)],
                    key=lambda r: -r["rss_growth_mib"])
    parents = sorted([r for r in procs if r["child_cpu"] >= 1.0], key=lambda r: -r["child_cpu"])
    dproc = sorted([r for r in procs if r["dstate_samples"]], key=lambda r: -r["dstate_samples"])
    groups: dict[str, dict] = {}
    for r in procs:
        g = groups.setdefault(r["comm"], {"comm": r["comm"], "count": 0, "cpu_avg": 0.0,
                                          "rss_mib": 0.0, "child_cpu": 0.0})
        g["count"] += 1
        g["cpu_avg"] += r["cpu_avg"]
        g["rss_mib"] += r["rss_mib"]
        g["child_cpu"] += r["child_cpu"]
    groups_l = sorted(groups.values(), key=lambda g: -(g["cpu_avg"] + g["child_cpu"]))
    zombies = [ident(pid) for pid, pv in last["procs"].items() if pv[1] == "Z"]
    conns = _connections(p["conn"], {r["pid"]: r for r in procs})

    # CPU the kernel counted vs CPU attributable to a process (own + reaped
    # children). The gap is processes that lived and died between samples
    # without being reaped by anyone we sampled -- or irq time charged to
    # nobody -- and on a server it is almost always script churn.
    busy_j = sum(r["busy_jiffies"] for r in rows)
    attr_j = sum(g["tk"] + g["ct"] for g in agg.values())
    unattributed = max(0.0, 100.0 * (busy_j - attr_j) / busy_j) if busy_j else 0.0
    machine_pct = lambda core_pct: core_pct / ncpu   # % of one core -> % of machine

    # ---- findings ------------------------------------------------------------
    F = []

    def add(status, title, detail, action=""):
        F.append({"status": status, "title": title, "detail": detail, "action": action})

    def names(rows_, key, n=3, unit="% of a core"):
        return ", ".join(f"{r['comm']} (pid {r['pid']}, {r[key]:.0f}{unit})" for r in rows_[:n])

    top = [r for r in by_cpu if r["cpu_avg"] >= 1.0]
    if oom := p["oom"]:
        add("fail", f"The kernel has killed processes for memory ({len(oom)} line(s) in the ring buffer)",
            "Out-of-memory kills happened on this server (not necessarily during this window). "
            "Most recent: " + oom[-1][:220],
            "Compare the victims with the memory table; a service the kernel killed restarts "
            "and drops whatever it was holding.")
    if cpu["busy"] >= 90:
        add("fail", f"CPU is saturated: {cpu['busy']:.0f}% busy on average",
            f"Across {ncpu} CPU(s). Biggest consumers: {names(top, 'cpu_avg')}.")
    elif cpu["busy"] >= 75:
        add("warn", f"CPU is busy: {cpu['busy']:.0f}% on average (peak {cpu['busy_peak']:.0f}%)",
            f"Biggest consumers: {names(top, 'cpu_avg')}.")
    if top and top[0]["cpu_avg"] >= 80:
        t0 = top[0]
        add("warn" if cpu["busy"] < 75 else "fail",
            f"{t0['comm']} (pid {t0['pid']}) is using {t0['cpu_avg'] / 100:.1f} core(s) on average",
            f"{machine_pct(t0['cpu_avg']):.0f}% of the whole machine, {t0['threads']} thread(s). "
            f"Command: {t0['cmd'][:160]}",
            f"`top -H -p {t0['pid']}` names the hot threads"
            + (" - for a JVM, match them to `jstack` by the hex thread id."
               if "java" in (t0["comm"] + t0["cmd"]).lower() else "."))
    if cpu["steal"] >= 10:
        add("warn" if cpu["steal"] < 25 else "fail",
            f"CPU steal is {cpu['steal']:.0f}% -- the hypervisor is withholding CPU",
            "Time this VM was ready to run but the host ran something else. On AWS this is "
            "usually a burstable instance (t2/t3) out of CPU credits, or a noisy neighbour. "
            "No process on the server can fix it.",
            "Check the instance type, and on AWS its CPUCreditBalance in CloudWatch.")
    if cpu["iowait"] >= 20:
        add("warn", f"I/O wait is {cpu['iowait']:.0f}% -- CPUs idle waiting for disk",
            "The bottleneck is storage, not CPU. "
            + (f"Processes seen in uninterruptible (D) state: {names(dproc, 'dstate_samples', unit=' samples')}."
               if dproc else ""))
    lpc = load["per_cpu"]
    if lpc >= 1.0:
        why = ("mostly runnable processes competing for CPU" if cpu["busy"] >= 70
               else "mostly processes BLOCKED on I/O (D state), not CPU -- load counts those too"
               if load["blocked_max"] or dproc else
               "while the CPUs were not saturated during this window -- the 1-minute average "
               "is still decaying from something earlier, or bursts are shorter than the interval")
        add("fail" if lpc >= 2 else "warn",
            f"Load average {last['load'][0]:.2f} on {ncpu} CPU(s) ({lpc:.2f} per CPU)",
            f"Load is the number of processes running or waiting to run, {why}. "
            f"Runnable on average: {load['running_avg']}, blocked: {load['blocked_avg']} (max {load['blocked_max']}).")
    if unattributed >= 15 and cpu["busy"] >= 20:
        add("warn", f"{unattributed:.0f}% of the CPU used was by processes too short-lived to sample",
            f"Forks: {forks_per_s}/s. Parents whose reaped children used the most CPU: "
            + (names(parents, "child_cpu") if parents else "none identified (their parents were not sampled either)")
            + ". This is script or check churn -- invisible in top.",
            "Look at what that parent runs (cron jobs, monit checks, a restart loop).")
    elif parents and parents[0]["child_cpu"] >= 10:
        add("warn", f"{parents[0]['comm']} (pid {parents[0]['pid']}) spawns children that use "
            f"{parents[0]['child_cpu']:.0f}% of a core", f"Forks: {forks_per_s}/s. Command: {parents[0]['cmd'][:160]}")
    if mem["used_pct"] >= 95:
        add("fail", f"Memory is {mem['used_pct']:.0f}% used ({mem['avail_mib']:.0f} MiB available)",
            f"Largest: {names(by_mem, 'rss_mib', unit=' MiB')}.")
    elif mem["used_pct"] >= 85:
        add("warn", f"Memory is {mem['used_pct']:.0f}% used ({mem['avail_mib']:.0f} MiB available)",
            f"Largest: {names(by_mem, 'rss_mib', unit=' MiB')}.")
    if mem["swap_in_per_s"] + mem["swap_out_per_s"] >= 10:
        add("fail" if mem["swap_in_per_s"] >= 50 else "warn",
            f"The server is swapping: {mem['swap_in_per_s']}/s in, {mem['swap_out_per_s']}/s out (pages)",
            "Active swapping makes everything slow and drives load up through I/O wait. "
            "Swap merely being USED is not this; pages moving now is.")
    for g in growth[:3]:
        add("warn", f"{g['comm']} (pid {g['pid']}) grew {g['rss_growth_mib']:.0f} MiB in {window / 60:.1f} min",
            f"{g['rss_first_mib']:.0f} -> {g['rss_mib']:.0f} MiB resident. A steady climb over a "
            "longer window is a leak; one step is often a cache filling or a JVM heap expanding.",
            "Run a longer check to tell a climb from a step.")
    kswapd = sum(r["cpu_avg"] for r in procs if r["comm"].startswith("kswapd"))
    if kswapd >= 5:
        add("warn", f"kswapd is using {kswapd:.0f}% of a core -- the kernel is reclaiming memory hard",
            "Memory pressure, even if 'used' does not look extreme.")
    for res, lim in (("memory", 10), ("io", 20), ("cpu", 50)):
        v = psi.get(res, {}).get("some", 0.0)
        if v >= lim:
            add("warn", f"{res.upper()} pressure: tasks stalled {v:.0f}% of the last 10 s",
                "Pressure Stall Information -- the kernel's own measure of time lost waiting for "
                f"{res}.")
    if len(zombies) >= 5:
        add("warn", f"{len(zombies)} zombie processes",
            "Exited but never reaped by their parent. Harmless in CPU terms; a growing count is a parent bug. "
            "Parents: " + ", ".join(sorted({str(z['ppid']) for z in zombies})[:6]))
    for ifc in net["ifaces"]:
        bad = ifc["rx_err_drop"] + ifc["tx_err_drop"]
        pk = ifc["rx_packets"] + ifc["tx_packets"]
        if bad and (bad / window >= 100 or (pk and bad >= 0.01 * pk)):
            add("warn", f"{ifc['name']} is dropping or erroring packets: {bad / window:.0f}/s "
                f"({100.0 * bad / max(pk, 1):.1f}% of packets)",
                f"{ifc['rx_err_drop']} received and {ifc['tx_err_drop']} sent packets were dropped or "
                "in error during the window. On a capture port this is the NIC or the kernel not "
                "keeping up; on the management interface it is usually the link or the driver.",
                "Compare with `ethtool -S` on that interface for the specific counter.")
    if conns["measured"]:
        cw = conns["states"].get("tcp/CLOSE-WAIT", 0)
        if cw >= 100:
            add("warn", f"{cw} TCP sockets are stuck in CLOSE-WAIT",
                "The other side closed and this host never did: a process is leaking sockets. "
                "They hold file descriptors until the process closes them or exits.",
                "The connections table shows which process owns the most sockets.")
        sr = conns["states"].get("tcp/SYN-RECV", 0)
        if sr >= 50:
            add("warn", f"{sr} half-open inbound TCP connections (SYN-RECV)",
                "Connections are arriving faster than the listener accepts them, or something is "
                "sending SYNs it never completes.")
        if conns["inbound_total"] and not conns["owners_known"]:
            add("info", "Connection owners are not shown",
                "Naming the process behind a socket needs root; this login has neither root nor "
                "passwordless sudo, so only counts and ports are reported.")
    else:
        add("info", "Connections were not measured",
            "Neither ss nor netstat is available on this server, or no snapshot completed yet.")
    if uptime_s and uptime_s < 3600:
        add("info", f"The server started {uptime_s // 60} min ago",
            "A recent boot explains a high load average on its own: services start and caches "
            "fill. Judge load again once it has been up for an hour.")
    if len(info) < 30:
        add("info", "Few processes were visible",
            "/proc may be mounted with hidepid, so other users' processes are hidden from this login.")
    if not F:
        add("ok", "Nothing stands out",
            f"CPU {cpu['busy']:.0f}% busy, load {last['load'][0]:.2f} on {ncpu} CPU(s), "
            f"memory {mem['used_pct']:.0f}% used, no swapping"
            + (" during this window. A problem that comes and goes needs a longer check." if mode != "long" else "."))
    order = {"fail": 0, "warn": 1, "info": 2, "ok": 3}
    F.sort(key=lambda f: order.get(f["status"], 9))
    verdict = "fail" if any(f["status"] == "fail" for f in F) else \
              "warn" if any(f["status"] == "warn" for f in F) else "ok"

    # ---- series --------------------------------------------------------------
    top3 = [r for r in by_cpu[:3] if r["cpu_avg"] > 0]
    series = {
        "t": [r["t"] for r in rows],
        "busy": [round(r["busy"], 1) for r in rows],
        "iowait": [round(r["iowait"], 1) for r in rows],
        "steal": [round(r["steal"], 1) for r in rows],
        "load1": [r["load1"] for r in rows],
        "load5": [r["load5"] for r in rows],
        "load15": [r["load15"] for r in rows],
        "net_rx_mbps": net["series_rx"],
        "net_tx_mbps": net["series_tx"],
        "running": [r["running"] for r in rows],
        "blocked": [r["blocked"] for r in rows],
        "mem_used": [round(m["used_pct"], 1) for m in mrows[1:]],
        "swap_used": [round(m["swap_used_mib"], 1) for m in mrows[1:]],
        "top": [{"name": f"{r['comm']} ({r['pid']})",
                 "values": [round(r["_series"][i], 1) if i in r["_series"] else None
                            for i in range(1, len(S))]} for r in top3],
    }

    rep = {**base,
           "state": "running" if live else "finished",
           "verdict": "info" if live else verdict,
           "end": last["t"], "window_s": round(window, 1),
           "cpu": cpu, "load": load, "mem": mem, "psi": psi,
           "uptime_s": uptime_s, "boot_t": boot_t, "net": net, "conns": conns,
           "forks_per_s": forks_per_s, "unattributed_pct": round(unattributed, 1),
           "process_count": len(last["procs"]),
           "findings": F,
           "top_cpu": clean(by_cpu[:TOP_N]), "top_mem": clean(by_mem[:TOP_N]),
           "growth": clean(growth[:TOP_N]), "parents": clean(parents[:TOP_N]),
           "dstate": clean(dproc[:TOP_N]), "groups": clean(groups_l[:TOP_N]),
           "zombies": zombies[:TOP_N], "oom": p["oom"], "series": series}
    rep["ai_pack"] = ai_pack(rep)
    return rep


# =============================================================================
# The AI analysis pack
# =============================================================================

def _table(rows, cols):
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(h for h, _ in cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        cells = []
        for _, k in cols:
            v = r.get(k, "")
            v = f"{v:.1f}" if isinstance(v, float) else str(v)
            cells.append(v.replace("|", "/")[:160])
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def _blank(v):
    return "" if v is None else v


def fmt_uptime(sec: int) -> str:
    if not sec:
        return "unknown"
    d, rem = divmod(int(sec), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d} d {h} h" if d else f"{h} h {m} min" if h else f"{m} min"


def ai_pack(r: dict, server_label: str = "") -> str:
    """Everything an analyst -- a person or a model -- needs to reason about
    this server's CPU, load and memory without access to it, as one Markdown
    document. Self-describing on purpose: the reader of a pack saved today may
    be a model next month that has never heard of this console, so the units,
    the definitions and the environment are written into it rather than
    assumed. Contains process command lines from the server -- treat
    it like any other ticket attachment.
    """
    from datetime import datetime, timezone

    def ts(t):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if t else "?"

    c, ld, m = r["cpu"], r["load"], r["mem"]
    L = []
    L.append(f"# Server performance analysis pack — {server_label or r['host']}")
    L.append("")
    L.append("## Context")
    L.append("- Environment: a Linux server, reached over SSH as an ordinary login; "
             "what it runs is in the process tables below.")
    L.append(f"- Host: `{r['host']}` · kernel `{r['kernel']}` · {r['ncpu']} CPU(s) · {r['model']}")
    L.append(f"- Collected by ARES Ultimate Console, **{r['mode']}** check: {r['samples']} samples every "
             f"{r['interval']} s, {ts(r['start'])} → {ts(r['end'])} ({r['window_s']:.0f} s).")
    L.append("- CPU % per process = (utime+stime delta) / elapsed, **100% = one full core**. "
             "System CPU % = share of all CPUs. Memory = resident set size (RSS), MiB. "
             "Child CPU = CPU of a process's reaped children (short-lived subprocesses).")
    L.append("")
    L.append("## Summary")
    L.append(f"- CPU: {c['busy']}% busy (peak interval {c['busy_peak']}%), user {c['user']}%, "
             f"system {c['system']}%, iowait {c['iowait']}%, irq {c['irq']}%, steal {c['steal']}%")
    L.append(f"- Load: {', '.join(f'{x:.2f}' for x in ld['last'])} (1/5/15 min) on {r['ncpu']} CPUs "
             f"= {ld['per_cpu']} per CPU; max 1-min in window {ld['max1']:.2f}; runnable avg "
             f"{ld['running_avg']}, blocked avg {ld['blocked_avg']} (max {ld['blocked_max']})")
    L.append(f"- Memory: {m['used_pct']}% used ({m['avail_mib']:.0f} MiB available of "
             f"{m['total_mib']:.0f}); swap used {m['swap_used_mib']:.0f}/{m['swap_total_mib']:.0f} MiB; "
             f"swap in/out {m['swap_in_per_s']}/{m['swap_out_per_s']} pages/s; major faults "
             f"{m['majfault_per_s']}/s; commit {m['commit_pct']:.0f}% of limit")
    L.append(f"- Uptime: {fmt_uptime(r.get('uptime_s', 0))} (booted {ts(r.get('boot_t', 0))}, "
             "by the server's own clock)")
    nt = r.get("net") or {}
    if nt.get("ifaces"):
        L.append(f"- Network (physical interfaces, average over the window): received "
                 f"{nt['rx_mbps']} Mbit/s (peak {nt['rx_peak_mbps']}), sent {nt['tx_mbps']} Mbit/s "
                 f"(peak {nt['tx_peak_mbps']})")
    cn = r.get("conns") or {}
    if cn.get("measured"):
        L.append(f"- Connections (snapshot {ts(cn['t'])}, via {cn['source']}): {cn['inbound_total']} inbound "
                 f"from {cn['inbound_hosts']} remote hosts, {cn['outbound_total']} outbound, "
                 f"{cn['local_total']} over loopback; TCP states "
                 + ", ".join(f"{k.split('/')[1]} {v}" for k, v in sorted(cn["states"].items())
                             if k.startswith("tcp/")))
    L.append(f"- Processes: {r['process_count']}; forks {r['forks_per_s']}/s; CPU not attributable "
             f"to any sampled process {r['unattributed_pct']}%")
    if r["psi"]:
        L.append("- Pressure (PSI avg10, % of time some task stalled): " + ", ".join(
            f"{k} {v.get('some', 0):.1f}" for k, v in r["psi"].items()))
    L.append("")
    L.append("## Automated findings (rule-based, worst first)")
    for f in r["findings"]:
        L.append(f"- **[{f['status']}] {f['title']}** — {f['detail']}"
                 + (f" _Suggested: {f['action']}_" if f.get("action") else ""))
    L.append("")
    proc_cols = [("pid", "pid"), ("user", "user"), ("comm", "comm"), ("CPU avg %", "cpu_avg"),
                 ("CPU peak %", "cpu_peak"), ("child CPU %", "child_cpu"), ("threads", "threads"),
                 ("RSS MiB", "rss_mib"), ("command", "cmd")]
    L.append("## Top processes by CPU")
    L.append(_table(r["top_cpu"], proc_cols))
    L.append("## Top processes by memory")
    L.append(_table(r["top_mem"], [("pid", "pid"), ("user", "user"), ("comm", "comm"),
                                   ("RSS MiB", "rss_mib"), ("first MiB", "rss_first_mib"),
                                   ("max MiB", "rss_max_mib"), ("growth MiB", "rss_growth_mib"),
                                   ("CPU avg %", "cpu_avg"), ("command", "cmd")]))
    L.append("## Memory growing during the window")
    L.append(_table(r["growth"], [("pid", "pid"), ("comm", "comm"), ("first MiB", "rss_first_mib"),
                                  ("last MiB", "rss_mib"), ("growth MiB", "rss_growth_mib"),
                                  ("command", "cmd")]))
    L.append("## By command name (all instances summed)")
    L.append(_table(r["groups"], [("comm", "comm"), ("count", "count"), ("CPU avg %", "cpu_avg"),
                                  ("child CPU %", "child_cpu"), ("RSS MiB", "rss_mib")]))
    L.append("## Parents of CPU-heavy short-lived children")
    L.append(_table(r["parents"], [("pid", "pid"), ("comm", "comm"), ("child CPU %", "child_cpu"),
                                   ("command", "cmd")]))
    L.append("## Processes seen in uninterruptible sleep (D state)")
    L.append(_table(r["dstate"], [("pid", "pid"), ("comm", "comm"), ("samples in D", "dstate_samples"),
                                  ("command", "cmd")]))
    if r["zombies"]:
        L.append(f"## Zombies: {len(r['zombies'])} (parents: "
                 + ", ".join(sorted({str(z['ppid']) for z in r['zombies']})) + ")\n")
    if nt.get("ifaces"):
        L.append("## Network interfaces (bits per second averaged over the window)")
        L.append(_table(nt["ifaces"], [("interface", "name"), ("rx Mbit/s", "rx_mbps"),
                                       ("rx peak", "rx_peak_mbps"), ("tx Mbit/s", "tx_mbps"),
                                       ("tx peak", "tx_peak_mbps"), ("rx err+drop", "rx_err_drop"),
                                       ("tx err+drop", "tx_err_drop"), ("virtual", "virtual")]))
    if cn.get("measured"):
        L.append("## Inbound connections by service port (loopback excluded)")
        L.append(_table([{**g, "top": ", ".join(f"{p['host']} ({p['count']})" for p in g["top_peers"])}
                         for g in cn["inbound"]],
                        [("proto", "proto"), ("port", "port"), ("process", "owner"),
                         ("connections", "count"), ("established", "estab"), ("remote hosts", "peers"),
                         ("top peers", "top")]))
        L.append("## Outbound connections by remote service (loopback excluded)")
        L.append(_table(cn["outbound"], [("proto", "proto"), ("remote port", "port"),
                                         ("remote host", "host"), ("process", "owner"),
                                         ("connections", "count")]))
        L.append("## Processes with network connections")
        L.append(_table([{**x, "ports": " ".join(x["listen"])} for x in cn["processes"]],
                        [("pid", "pid"), ("process", "name"), ("inbound", "inbound"),
                         ("outbound", "outbound"), ("loopback", "local"), ("listening", "ports"),
                         ("CPU avg %", "cpu_avg"), ("RSS MiB", "rss_mib")]))
        L.append("## Listening sockets")
        L.append(_table(cn["listen"], [("proto", "proto"), ("port", "port"), ("address", "addr"),
                                       ("process", "owner")]))
    L.append("## Kernel OOM messages (ring buffer, any time since boot)")
    L.append("```\n" + ("\n".join(r["oom"]) if r["oom"] else "(none, or dmesg not readable)") + "\n```")
    L.append("")
    s = r["series"]
    n = len(s["t"])
    step = max(1, -(-n // 120))
    L.append(f"## Time series (one row per interval{'' if step == 1 else f', every {step}th shown'})")
    hdr = ["time_utc", "busy%", "iowait%", "steal%", "load1", "load5", "load15", "running", "blocked",
           "mem_used%", "swap_used_MiB", "net_rx_Mbps", "net_tx_Mbps"] + [t["name"] for t in s["top"]]
    L.append("```csv")
    L.append(",".join(hdr))
    for i in range(0, n, step):
        row = [datetime.fromtimestamp(s["t"][i], timezone.utc).strftime("%H:%M:%S"),
               s["busy"][i], s["iowait"][i], s["steal"][i], s["load1"][i], s["load5"][i],
               s["load15"][i], s["running"][i], s["blocked"][i], s["mem_used"][i], s["swap_used"][i],
               _blank(s["net_rx_mbps"][i]), _blank(s["net_tx_mbps"][i])]
        row += ["" if t["values"][i] is None else t["values"][i] for t in s["top"]]
        L.append(",".join(str(x) for x in row))
    L.append("```")
    L.append("")
    L.append("## Questions for the analyst")
    L.append("1. Which process or condition best explains the CPU usage, the load average and the "
             "memory usage, and is it expected for a server of this size?")
    L.append("2. Is the load CPU-bound, I/O-bound (D state, iowait) or hypervisor-bound (steal)?")
    L.append("3. Is any memory growth a leak, a cache, or a heap (a JVM's, say) sizing itself?")
    L.append("4. Do the network throughput and the inbound connections explain any of the load "
             "(a flood of sources, a stuck CLOSE-WAIT build-up, drops on an interface)?")
    L.append("5. What should be checked or changed next, in order, and what evidence would confirm it?")
    return "\n".join(L) + "\n"


# =============================================================================
# Layout -- the tiles, charts and tables, in the order every rendering uses
# =============================================================================

def _clock(t: int, tzo_min: int, with_date: bool = False) -> str:
    from datetime import datetime, timezone
    if not t:
        return ""
    d = datetime.fromtimestamp(t - tzo_min * 60, timezone.utc)
    return d.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def _lvl(x: float, warn: float, fail: float) -> str:
    return "fail" if x >= fail else "warn" if x >= warn else "ok"


def layout(r: dict, tzo_min: int = 0, diagnosis: str = "",
           diagnosis_title: str = "AI investigation") -> dict:
    """The report as TractorBeam's PDF lays it out: masthead, tiles, charts,
    findings, tables. The dialog, the HTML and the PDF are all drawn from
    this, so they cannot disagree. `tzo_min` is minutes WEST of UTC, the way
    a browser's getTimezoneOffset() counts. `diagnosis` is an AI reading of
    this report, when there is one, printed after the tables."""
    if not r.get("cpu"):
        return {"pdf_title": "Performance check", "verdict": r.get("verdict", "info"),
                "source": r.get("host", ""), "window": "not enough samples yet",
                "findings": r.get("findings") or []}
    c, ld, m, s = r["cpu"], r["load"], r["mem"], r["series"]
    t = [_clock(x, tzo_min) for x in s["t"]]
    mib = lambda v: f"{v / 1024:.1f} GiB" if v >= 1024 else f"{v:.0f} MiB"
    proc_w = [0.08, 0.10, 0.12, 0.09, 0.08, 0.08, 0.08, 0.37]

    def procs(rows, kind):
        if kind == "cpu":
            return [[str(x["pid"]), x.get("user", ""), x["comm"], f"{x['cpu_avg']:.1f}",
                     f"{x['cpu_peak']:.1f}", f"{x['child_cpu']:.1f}", mib(x["rss_mib"]), x["cmd"]]
                    for x in rows if x["cpu_avg"] > 0 or x["child_cpu"] > 0]
        return [[str(x["pid"]), x.get("user", ""), x["comm"], mib(x["rss_mib"]),
                 f"{x['rss_growth_mib']:+.0f} MiB", f"{x['cpu_avg']:.1f}", str(x["threads"]), x["cmd"]]
                for x in rows]

    tables = [
        {"title": "Top processes by CPU", "numeric_from": 3, "numeric_to": 7, "widths": proc_w,
         "note": "CPU % per process is measured over the window; 100% = one core. Child % is CPU "
                 "used by short-lived processes it spawned and reaped.",
         "headers": ["PID", "User", "Name", "CPU %", "Peak %", "Child %", "RSS", "Command"],
         "rows": procs(r.get("top_cpu") or [], "cpu")[:15]},
        {"title": "Top processes by memory", "numeric_from": 3, "numeric_to": 7, "widths": proc_w,
         "headers": ["PID", "User", "Name", "RSS", "Change", "CPU %", "Threads", "Command"],
         "rows": procs(r.get("top_mem") or [], "mem")[:15]},
    ]
    if r.get("parents"):
        tables.append({"title": "Spawning CPU-heavy short-lived children", "numeric_from": 2, "numeric_to": 3,
                       "widths": [0.10, 0.16, 0.12, 0.62], "headers": ["PID", "Name", "Child %", "Command"],
                       "rows": [[str(x["pid"]), x["comm"], f"{x['child_cpu']:.1f}", x["cmd"]] for x in r["parents"]]})
    if r.get("growth"):
        tables.append({"title": "Memory growing during the window", "numeric_from": 2, "numeric_to": 4,
                       "widths": [0.10, 0.14, 0.12, 0.12, 0.52], "headers": ["PID", "Name", "From", "To", "Command"],
                       "rows": [[str(x["pid"]), x["comm"], mib(x["rss_first_mib"]), mib(x["rss_mib"]), x["cmd"]]
                                for x in r["growth"]]})
    if r.get("dstate"):
        tables.append({"title": "Seen in uninterruptible sleep (D state)", "numeric_from": 2, "numeric_to": 3,
                       "widths": [0.10, 0.16, 0.12, 0.62], "headers": ["PID", "Name", "Samples", "Command"],
                       "rows": [[str(x["pid"]), x["comm"], str(x["dstate_samples"]), x["cmd"]] for x in r["dstate"]]})
    tables.append({"title": "By command name", "numeric_from": 1, "widths": [0.40, 0.15, 0.15, 0.15, 0.15],
                   "headers": ["Name", "Count", "CPU %", "Child %", "RSS"],
                   "rows": [[g["comm"], str(g["count"]), f"{g['cpu_avg']:.1f}", f"{g['child_cpu']:.1f}",
                             mib(g["rss_mib"])] for g in (r.get("groups") or [])[:15]]})
    nt, cn = r.get("net") or {}, r.get("conns") or {}
    mbps = lambda v: f"{v * 1000:.0f} kbit/s" if v < 1 else f"{v:.1f} Mbit/s"
    if nt.get("ifaces"):
        tables.append({"title": "Network interfaces", "numeric_from": 1, "numeric_to": 6,
                       "widths": [0.22, 0.13, 0.13, 0.13, 0.13, 0.13, 0.13],
                       "note": "Averaged over the window. Bridges and container interfaces are listed "
                               "but left out of the totals, because they carry the same packets twice.",
                       "headers": ["Interface", "Received", "Rx peak", "Sent", "Tx peak", "Rx err/drop",
                                   "Tx err/drop"],
                       "rows": [[g["name"] + (" (virtual)" if g["virtual"] else ""), mbps(g["rx_mbps"]),
                                 mbps(g["rx_peak_mbps"]), mbps(g["tx_mbps"]), mbps(g["tx_peak_mbps"]),
                                 str(g["rx_err_drop"]), str(g["tx_err_drop"])] for g in nt["ifaces"][:15]]})
    if cn.get("measured"):
        tables.append({"title": "Inbound connections by service port", "numeric_from": 3, "numeric_to": 5,
                       "widths": [0.08, 0.08, 0.18, 0.10, 0.10, 0.10, 0.36],
                       "note": "A connection is inbound when its local port is one this server listens on. "
                               "Loopback (the server's own services talking) is left out.",
                       "headers": ["Proto", "Port", "Process", "Conns", "Estab.", "Hosts", "Top peers"],
                       "rows": [[g["proto"], str(g["port"]), g["owner"], str(g["count"]), str(g["estab"]),
                                 str(g["peers"]),
                                 ", ".join(f"{x['host']} ({x['count']})" for x in g["top_peers"])]
                                for g in cn["inbound"][:20]]})
        tables.append({"title": "Processes with network connections", "numeric_from": 2, "numeric_to": 7,
                       "widths": [0.08, 0.16, 0.09, 0.09, 0.09, 0.09, 0.10, 0.30],
                       "headers": ["PID", "Process", "In", "Out", "Loopback", "CPU %", "RSS", "Listening"],
                       "rows": [[str(x["pid"] or ""), x["name"], str(x["inbound"]), str(x["outbound"]),
                                 str(x["local"]), f"{x['cpu_avg']:.1f}", mib(x["rss_mib"]),
                                 " ".join(x["listen"])] for x in cn["processes"][:20]]})
        if cn.get("outbound"):
            tables.append({"title": "Outbound connections by remote service", "numeric_from": 4,
                           "widths": [0.08, 0.10, 0.34, 0.34, 0.14],
                           "headers": ["Proto", "Port", "Remote host", "Process", "Conns"],
                           "rows": [[g["proto"], str(g["port"]), g["host"], g["owner"], str(g["count"])]
                                    for g in cn["outbound"][:20]]})
    if r.get("oom"):
        tables.append({"title": "Kernel OOM messages", "widths": [1.0], "headers": ["Line"],
                       "rows": [[x] for x in r["oom"]]})
    charts = [
        {"title": "CPU", "unit": "% of all CPUs", "t": t, "zero_based": True,
         "series": [{"name": "Busy", "values": s["busy"]}, {"name": "I/O wait", "values": s["iowait"]},
                    {"name": "Steal", "values": s["steal"]}]},
        {"title": "Load average", "unit": "processes", "t": t, "zero_based": True,
         "series": [{"name": "1 min", "values": s["load1"]}, {"name": "5 min", "values": s["load5"]},
                    {"name": "15 min", "values": s["load15"]}]},
        {"title": "Run queue", "unit": "processes", "t": t, "zero_based": True,
         "series": [{"name": "Runnable", "values": s["running"]}, {"name": "Blocked (D)", "values": s["blocked"]}]},
        {"title": "Memory used", "unit": "% of RAM (excl. reclaimable cache)", "t": t, "zero_based": True,
         "series": [{"name": "Used", "values": s["mem_used"]}]},
    ]
    if any(v is not None for v in s.get("net_rx_mbps") or []):
        charts.append({"title": "Network throughput", "unit": "Mbit/s, physical interfaces", "t": t,
                       "zero_based": True,
                       "series": [{"name": "Received", "values": s["net_rx_mbps"]},
                                  {"name": "Sent", "values": s["net_tx_mbps"]}]})
    if s.get("top"):
        charts.append({"title": "Top processes", "unit": "% of one core", "t": t, "zero_based": True,
                       "series": s["top"]})
    rep = {
        "pdf_title": "Performance check",
        "verdict": "info" if r.get("live") else r.get("verdict", "info"),
        "source": f"{r.get('host', '')} · kernel {r.get('kernel', '')} · {r.get('ncpu')} CPU · {r.get('model', '')}",
        "window": (f"{r.get('mode', '')} check · {_clock(r.get('start', 0), tzo_min, True)} · "
                   f"{r.get('samples', 0)} samples every {r.get('interval', 0)} s · "
                   f"{r.get('window_s', 0):.0f} s" + (" · still running" if r.get("live") else "")),
        "tiles": [
            {"label": "CPU busy", "value": f"{c['busy']:.1f}%", "status": _lvl(c["busy"], 75, 90),
             "sub": f"iowait {c['iowait']} · steal {c['steal']}"},
            {"label": "Load 1 / 5 / 15 min",
             "value": " / ".join(f"{x:.1f}" for x in ld["last"][:3]) if ld["last"] else "-",
             "status": _lvl(ld["per_cpu"], 1, 2), "sub": f"{ld['per_cpu']} per CPU (1 min)"},
            {"label": "Uptime", "value": fmt_uptime(r.get("uptime_s", 0)),
             "sub": "booted " + _clock(r.get("boot_t", 0), tzo_min, True) if r.get("boot_t") else ""},
            {"label": "Memory used", "value": f"{m['used_pct']:.1f}%", "status": _lvl(m["used_pct"], 85, 95),
             "sub": f"{mib(m['avail_mib'])} available"},
            {"label": "Swap activity", "value": f"{m['swap_in_per_s'] + m['swap_out_per_s']:.0f}/s",
             "status": _lvl(m["swap_in_per_s"] + m["swap_out_per_s"], 10, 50),
             "sub": f"{mib(m['swap_used_mib'])} used"},
            {"label": "Processes", "value": str(r.get("process_count", 0)), "sub": f"{r.get('forks_per_s')} forks/s"},
            {"label": "Unattributed CPU", "value": f"{r.get('unattributed_pct', 0):.1f}%",
             "status": _lvl(r.get("unattributed_pct", 0), 15, 40) if c["busy"] >= 20 else "ok",
             "sub": "short-lived processes"},
        ] + ([{"label": "Network", "value": f"{mbps(nt['rx_mbps'])} in",
               "sub": f"{mbps(nt['tx_mbps'])} out · peak {mbps(nt['rx_peak_mbps'])} in"}]
             if nt.get("ifaces") else []) + (
            [{"label": "Inbound connections", "value": str(cn["inbound_total"]),
              "sub": f"from {cn['inbound_hosts']} hosts · {cn['outbound_total']} outbound"}]
            if cn.get("measured") else []),
        "charts": charts,
        "findings": r.get("findings") or [],
        "tables": tables,
    }
    if diagnosis.strip():
        rep["sections"] = [{"title": diagnosis_title, "text": diagnosis}]
    return rep


def csv_rows(r: dict) -> str:
    s = r.get("series") or {"t": []}
    out = ["time_epoch,busy_pct,iowait_pct,steal_pct,load1,load5,load15,runnable,blocked,mem_used_pct,"
           "swap_used_mib,net_rx_mbps,net_tx_mbps"]
    for i, t in enumerate(s.get("t", [])):
        out.append(",".join(str(x) for x in (t, s["busy"][i], s["iowait"][i], s["steal"][i], s["load1"][i],
                                             s["load5"][i], s["load15"][i], s["running"][i], s["blocked"][i],
                                             s["mem_used"][i], s["swap_used"][i], _blank(s["net_rx_mbps"][i]),
                                             _blank(s["net_tx_mbps"][i]))))
    return "\r\n".join(out) + "\r\n"


def headline(r: dict) -> str:
    """One line for the status bar and the server history."""
    if r.get("live"):
        return f"Performance check running: {r.get('samples', 0)} of {r.get('requested_samples', 0)} samples"
    bad = [f for f in r.get("findings") or [] if f["status"] in ("fail", "warn")]
    if not r.get("cpu"):
        return "Performance check: not enough samples"
    if not bad:
        return "Performance check: nothing stands out"
    return f"Performance check: {len(bad)} issue(s) - " + "; ".join(f["title"] for f in bad[:3])


#: The four verdicts, as the severities the rest of ARES uses.
SEVERITY = {"fail": "crit", "warn": "warn", "info": "info", "ok": "ok"}


def severity(r: dict) -> str:
    return SEVERITY.get(r.get("verdict", "info"), "info")


def redacted_pack(r: dict, server_label: str = "") -> str:
    """The AI pack with anything that looks like a credential replaced.

    Command lines carry passwords as often as logs do (`mysql -pSecret`,
    `--token=...`), so this is the text that may leave the machine, and the
    confirmation shows exactly it."""
    from .serverinsight import redact_log_line
    return "\n".join(redact_log_line(line) for line in ai_pack(r, server_label).splitlines()) + "\n"
