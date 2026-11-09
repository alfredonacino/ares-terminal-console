"""A vulnerability scan of a connected server.

Two halves, and the second is optional.

On the server
-------------
One read-only probe over the open connection, like the others in
:mod:`ares.protocols.serverinsight`. It asks the server's own package manager
what security updates it knows are waiting (``apt-get -s``, ``dnf updateinfo``,
``zypper list-patches``, ``apk version``, ``arch-audit``, ``pkg audit``), and
looks for the usual weak spots: an operating system past its end of support,
a reboot that would load a patched kernel, SSH settings that invite guessing,
a second root account, files in ``/etc`` anyone can write. The listening ports
come from the inventory (:mod:`ares.protocols.inventory`), where a database
or the Docker API open to every interface is reported.

Nothing is changed and nothing is fetched by the server: ``apt-get -s`` only
simulates, against the package lists the server already has. So the report
says how old those lists are, because stale lists undercount.

Online, after asking
--------------------
The installed packages are looked up in OSV (https://osv.dev), Google's open
vulnerability database, which carries the security trackers of Debian,
Ubuntu, Alpine, Red Hat, Rocky, AlmaLinux and SUSE. What is sent is the list of
source package names and versions and the distribution's name - nothing about
the server itself - and the operator is shown that list before it goes. OSV
compares the versions itself, so what comes back is what this server is
exposed to, each with the version that fixes it where there is one.
"""
from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .inventory import InventoryReport, Listener
from .serverinsight import Finding, RunInput, _first, _sections, run_script, worst

OSV_API = "https://api.osv.dev/v1"
#: OSV takes up to a thousand queries in one batch.
BATCH = 1000
#: Records fetched in full, at most: an old server can match thousands, and
#: the ids alone still say which packages to update.
MAX_DETAILS = 600
DETAIL_WORKERS = 8
HTTP_TIMEOUT = 30.0
#: Seconds the server's own package manager gets, under the probe channel's 120.
DNF_LIMIT = 90

#: ``http(method, url, body)`` -> the decoded JSON reply. Replaced in tests.
Http = Callable[[str, str, "bytes | None"], dict]


# ======================================================= server-side checks ==

CHECKS_POSIX = r"""
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
# GNU timeout puts its child in a process group of its own, and dnf then
# prints nothing; --foreground keeps it in ours. Busybox has no such flag.
T=""; command -v timeout >/dev/null 2>&1 && T="timeout 90"
timeout --foreground 1 true >/dev/null 2>&1 && T="timeout --foreground 90"
echo '@@os_release'; cat /etc/os-release 2>/dev/null
echo '@@now'; date +%s
if command -v apt-get >/dev/null 2>&1; then
  echo '@@apt_age'
  newest=$(ls -t /var/lib/apt/lists/*Release /var/lib/apt/lists/*Packages 2>/dev/null | head -n 1)
  [ -n "$newest" ] && (stat -c %Y "$newest" 2>/dev/null || date -r "$newest" +%s 2>/dev/null)
  echo '@@apt'; $T apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep '^Inst '
fi
# dnf can be cut off fetching metadata from a slow mirror and still exit 0
# having printed nothing, so how long it took is kept beside what it said.
if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  started=$(date +%s)
  echo '@@dnf'
  if command -v dnf >/dev/null 2>&1; then $T dnf -q updateinfo list --security 2>/dev/null </dev/null
  else $T yum -q updateinfo list security 2>/dev/null </dev/null; fi
  echo '@@dnf_status'; echo $?
  echo '@@dnf_seconds'; echo $(( $(date +%s) - started ))
fi
if command -v zypper >/dev/null 2>&1; then
  echo '@@zypper'; $T zypper --non-interactive --no-refresh list-patches --category security 2>/dev/null
fi
if command -v apk >/dev/null 2>&1; then echo '@@apk'; $T apk version -l '<' 2>/dev/null; fi
if command -v arch-audit >/dev/null 2>&1; then echo '@@arch_audit'; $T arch-audit 2>/dev/null; fi
if command -v checkupdates >/dev/null 2>&1; then echo '@@checkupdates'; $T checkupdates 2>/dev/null; fi
if command -v pkg >/dev/null 2>&1 && [ "$(uname -s)" = FreeBSD ]; then
  echo '@@pkg_audit'; $T pkg audit 2>&1 | tail -n 200
fi
echo '@@reboot'
[ -f /var/run/reboot-required ] && echo required
if command -v needs-restarting >/dev/null 2>&1; then
  $T needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo required
fi
echo '@@reboot_pkgs'; cat /var/run/reboot-required.pkgs 2>/dev/null
echo '@@kernel_running'; uname -r 2>/dev/null
echo '@@kernel_installed'
ls /boot 2>/dev/null | sed -n 's/^vmlinuz-//p'
echo '@@sshd_t'; sshd -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|protocol|maxauthtries) '
echo '@@sshd_config'
cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | grep -iE '^[[:space:]]*(permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|protocol|maxauthtries)[[:space:]]'
echo '@@uid0'; awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null
echo '@@etc_writable'; find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 20
echo '@@autoupdate'
for u in unattended-upgrades.service apt-daily-upgrade.timer dnf-automatic.timer dnf-automatic-install.timer yum-cron.service; do
  s=$(systemctl is-enabled "$u" 2>/dev/null) && printf '%s %s\n' "$u" "$s"
done
echo '@@end'
"""

CHECKS_WINDOWS = r"""
'@@windows'; $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; "$($os.Caption)`t$($os.BuildNumber)"
'@@now'; [int][double]::Parse((Get-Date -UFormat %s))
'@@defender'; Get-MpComputerStatus -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AntivirusEnabled)`t$($_.RealTimeProtectionEnabled)`t$($_.AntivirusSignatureAge)" }
'@@firewall'; Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)`t$($_.Enabled)" }
'@@smb1'; (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
'@@reboot'
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { 'required' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { 'required' }
'@@hotfix_newest'; $h = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { "$($h.HotFixID)`t$([int][double]::Parse((Get-Date $h.InstalledOn -UFormat %s)))" }
'@@rdp'; $t = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue; $r = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue; "$($t.fDenyTSConnections)`t$($r.UserAuthentication)"
'@@end'
"""

#: The day free security support ends, by distribution and release, as known
#: in October 2026. Ubuntu's date is standard support: Ubuntu Pro extends an
#: LTS for years, and the finding says so. Windows dates are for the Home and
#: Pro editions; Enterprise and LTSC are serviced longer.
END_OF_SUPPORT: dict[str, dict[str, str]] = {
    "debian": {"9": "2022-06-30", "10": "2024-06-30", "11": "2026-08-31",
               "12": "2028-06-30", "13": "2030-06-30"},
    "ubuntu": {"14.04": "2019-04-30", "16.04": "2021-04-30", "18.04": "2023-05-31",
               "20.04": "2025-05-31", "22.04": "2027-06-01", "24.04": "2029-05-31",
               "23.04": "2024-01-25", "23.10": "2024-07-11", "24.10": "2025-07-10",
               "25.04": "2026-01-15", "25.10": "2026-07-09"},
    "rhel": {"6": "2020-11-30", "7": "2024-06-30", "8": "2029-05-31", "9": "2032-05-31"},
    "rocky": {"8": "2029-05-31", "9": "2032-05-31"},
    "almalinux": {"8": "2029-05-31", "9": "2032-05-31"},
    "centos": {"6": "2020-11-30", "7": "2024-06-30", "8": "2024-05-31", "9": "2027-05-31"},
    "fedora": {"38": "2024-05-21", "39": "2024-11-26", "40": "2025-05-13",
               "41": "2025-11-19", "42": "2026-05-13", "43": "2026-12-09"},
    "alpine": {"3.15": "2023-11-01", "3.16": "2024-05-23", "3.17": "2024-11-22",
               "3.18": "2025-05-09", "3.19": "2025-11-01", "3.20": "2026-04-01",
               "3.21": "2026-11-01", "3.22": "2027-05-01"},
    "opensuse-leap": {"15.4": "2023-12-07", "15.5": "2024-12-31", "15.6": "2026-04-30"},
    "freebsd": {"12": "2023-12-31", "13": "2026-04-30", "14": "2028-11-30"},
}

#: Windows, by build number (Windows 10/11) or by the name in the caption.
WINDOWS_BUILDS = {"22000": ("Windows 11 21H2", "2023-10-10"),
                  "22621": ("Windows 11 22H2", "2024-10-08"),
                  "22631": ("Windows 11 23H2", "2025-11-11"),
                  "26100": ("Windows 11 24H2", "2026-10-13")}
WINDOWS_NAMES = (("Server 2008", "2020-01-14"), ("Server 2012", "2023-10-10"),
                 ("Server 2016", "2027-01-12"), ("Server 2019", "2029-01-09"),
                 ("Server 2022", "2031-10-14"), ("Server 2025", "2034-10-10"),
                 ("Windows 7", "2020-01-14"), ("Windows 8", "2023-01-10"),
                 ("Windows 10", "2025-10-14"))

#: Ports that should rarely face every interface, and how bad it is when one does.
RISKY_PORTS = {
    2375: ("crit", "the Docker API without TLS",
           "Anyone who can reach it can run containers as root on this host."),
    23: ("crit", "Telnet", "Passwords cross the network in the clear."),
    21: ("warn", "FTP", "Passwords cross the network in the clear unless it is FTPS."),
    6379: ("warn", "Redis", "Redis has no password by default."),
    11211: ("warn", "Memcached", "Memcached has no authentication."),
    27017: ("warn", "MongoDB", "Check that authorisation is enabled."),
    9200: ("warn", "Elasticsearch", "Check that security is enabled."),
    3306: ("warn", "MySQL/MariaDB", "Databases rarely need to be reachable from everywhere."),
    5432: ("warn", "PostgreSQL", "Databases rarely need to be reachable from everywhere."),
    1433: ("warn", "SQL Server", "Databases rarely need to be reachable from everywhere."),
    5900: ("warn", "VNC", "VNC is often protected by a short password or none."),
    445: ("info", "SMB", "Fine on a file server; worth knowing anywhere else."),
    111: ("info", "rpcbind", "Only needed for NFS."),
}


def _date(text: str) -> float:
    return time.mktime(time.strptime(text, "%Y-%m-%d"))


def _support_finding(label: str, ends: str, now: float, *, extra: str = "") -> Finding | None:
    left = (_date(ends) - now) / 86400
    if left < 0:
        return Finding("crit", f"{label} is past its end of support ({ends})",
                       "It no longer receives security updates." + extra)
    if left < 120:
        return Finding("warn", f"{label} reaches its end of support on {ends}",
                       f"{int(left)} day(s) left to upgrade." + extra)
    return None


def support_finding(release: dict[str, str], now: float) -> Finding | None:
    """An operating system past, or near, the end of its security support."""
    os_id = release.get("ID", "").lower()
    version = release.get("VERSION_ID", "")
    name = release.get("PRETTY_NAME") or f"{os_id} {version}"
    table = END_OF_SUPPORT.get(os_id)
    if not table or not version:
        return None
    key = version
    if os_id == "alpine":
        key = ".".join(version.split(".")[:2])
    elif os_id in ("debian", "rhel", "rocky", "almalinux", "centos", "freebsd"):
        key = version.split(".")[0]
    ends = table.get(key)
    if ends is None:
        # Older than anything in the table is long out of support.
        known = sorted(table, key=_version_key)
        if known and _version_key(key) < _version_key(known[0]):
            return Finding("crit", f"{name} is long past its end of support",
                           "It no longer receives security updates.")
        return None
    extra = (" Ubuntu Pro (free for a few machines) extends security updates for an LTS."
             if os_id == "ubuntu" and key.endswith(".04") and int(key[:2]) % 2 == 0 else "")
    return _support_finding(name, ends, now, extra=extra)


def _version_key(text: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-]", text))


def windows_support_finding(caption: str, build: str, now: float) -> Finding | None:
    if build in WINDOWS_BUILDS and "Server" not in caption:
        label, ends = WINDOWS_BUILDS[build]
        return _support_finding(label, ends, now,
                                extra=" Enterprise and Education editions get longer.")
    for name, ends in WINDOWS_NAMES:
        if name in caption:
            return _support_finding(caption.replace("Microsoft ", ""), ends, now)
    return None


def _apt(lines: list[str]) -> tuple[list[str], int]:
    """Security upgrades (``name old -> new``) and the count of all upgrades."""
    security, total = [], 0
    for line in lines:
        m = re.match(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) ([^)]*)\)", line)
        if not m:
            continue
        total += 1
        if re.search(r"-security|Debian-Security", m.group(4), re.I):
            security.append(f"{m.group(1)} {m.group(2) or '?'} -> {m.group(3)}")
    return security, total


def _dnf(lines: list[str]) -> tuple[list[str], Counter]:
    advisories: dict[str, str] = {}
    packages = []
    for line in lines:
        m = re.match(r"^(\S+)\s+(\S+?)/Sec\.\s+(\S+)", line.strip())
        if not m:
            continue
        advisories[m.group(1)] = m.group(2)
        packages.append(f"{m.group(3)} ({m.group(1)}, {m.group(2)})")
    ratings: Counter = Counter()
    for rating in advisories.values():
        ratings[rating.lower()] += 1
    return packages, ratings


def parse_checks(text: str, platform: str, inventory: InventoryReport | None = None,
                 now: float | None = None) -> list[Finding]:
    """The server-side half of the scan, judged."""
    s = _sections(text)
    stamp = _first(s.get("now"))
    now = now if now is not None else (float(stamp) if stamp.isdigit() else time.time())
    out: list[Finding] = []
    add = out.append
    if platform == "windows":
        _windows_checks(s, now, add)
    else:
        _posix_checks(s, now, add)
    if inventory is not None:
        _exposure(inventory.listeners, add)
    order = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
    out.sort(key=lambda f: order.get(f.severity, 9))
    return out


def _posix_checks(s: dict[str, list[str]], now: float, add) -> None:
    from .inventory import parse_os_release
    release = parse_os_release(s.get("os_release", []))
    found = support_finding(release, now)
    if found:
        add(found)

    if "apt" in s:
        security, total = _apt(s["apt"])
        if security:
            add(Finding("warn", f"{len(security)} security update(s) waiting (apt)",
                        "\n".join(security[:40]) + (f"\n… and {len(security) - 40} more"
                                                    if len(security) > 40 else "")))
        elif total:
            add(Finding("info", f"{total} update(s) waiting, none marked security (apt)"))
        age = _first(s.get("apt_age"))
        if not age.isdigit():
            add(Finding("info", "apt has no package lists, so waiting updates are unknown",
                        "'apt update' downloads them. The online lookup below does not "
                        "need them."))
        elif not total:
            add(Finding("ok", "apt has no updates waiting"))
        if age.isdigit():
            days = (now - int(age)) / 86400
            if days > 7:
                add(Finding("info", f"The package lists are {int(days)} days old",
                            "apt only knows updates published before then, so the count "
                            "above may be low. 'apt update' refreshes them."))
    if "dnf" in s:
        packages, ratings = _dnf(s["dnf"])
        status = _first(s.get("dnf_status"))
        seconds = _first(s.get("dnf_seconds"))
        timed_out = status == "124" or (seconds.isdigit() and int(seconds) >= DNF_LIMIT - 5)
        if not packages and (timed_out or status not in ("", "0")):
            add(Finding("info", "dnf could not list security advisories",
                        (f"It ran out of time ({DNF_LIMIT} s) reading its update metadata, "
                         "probably from a slow mirror. Running it again usually works."
                         if timed_out else
                         f"It exited with status {status}; its metadata may be missing.")
                        + " The online lookup below does not need it."))
        elif packages:
            severity = "crit" if ratings.get("critical") else "warn"
            rated = ", ".join(f"{n} {r}" for r, n in sorted(ratings.items()))
            add(Finding(severity, f"{sum(ratings.values())} security advisory(ies) "
                                  f"not applied ({rated})",
                        "\n".join(packages[:40])))
        else:
            add(Finding("ok", "No security advisories waiting (dnf/yum)"))
    if "zypper" in s:
        needed = []
        for line in s["zypper"]:
            cols = [c.strip() for c in line.split("|")]
            if len(cols) >= 6 and cols[2].lower() == "security" and cols[5].lower() == "needed":
                needed.append((cols[1], cols[3]))
        if needed:
            severity = "crit" if any(sev.lower() == "critical" for _n, sev in needed) else "warn"
            add(Finding(severity, f"{len(needed)} security patch(es) needed (zypper)",
                        "\n".join(f"{n} ({sev})" for n, sev in needed[:40])))
        else:
            add(Finding("ok", "No security patches needed (zypper)"))
    if "apk" in s:
        upgrades = [l.strip() for l in s["apk"] if "<" in l and not l.startswith("Installed")]
        if upgrades:
            add(Finding("warn", f"{len(upgrades)} package update(s) waiting (apk)",
                        "Alpine does not mark which are security fixes.\n"
                        + "\n".join(upgrades[:40])))
        else:
            add(Finding("ok", "apk has no updates waiting"))
    if "arch_audit" in s:
        affected = [l.strip() for l in s["arch_audit"] if "affected by" in l]
        if affected:
            severity = "crit" if any(re.search(r"critical|high risk", l, re.I)
                                     for l in affected) else "warn"
            add(Finding(severity, f"{len(affected)} package(s) with known vulnerabilities "
                                  "(arch-audit)", "\n".join(affected[:40])))
        else:
            add(Finding("ok", "arch-audit found no vulnerable packages"))
    if s.get("checkupdates"):
        updates = [l for l in s["checkupdates"] if "->" in l]
        if updates:
            add(Finding("info", f"{len(updates)} update(s) waiting (pacman)",
                        "\n".join(updates[:40])))
    if "pkg_audit" in s:
        text = "\n".join(s["pkg_audit"])
        m = re.search(r"(\d+) problem\(s\) in (\d+) installed package\(s\) found", text)
        if m and int(m.group(1)):
            vulnerable = [l.split(" is vulnerable")[0].strip() for l in s["pkg_audit"]
                          if "is vulnerable" in l]
            add(Finding("warn", f"{m.group(1)} problem(s) in {m.group(2)} package(s) "
                                "(pkg audit)", "\n".join(vulnerable[:40])))
        elif "vulnxml" in text.lower() or "does not exist" in text:
            add(Finding("info", "pkg audit has no vulnerability database yet",
                        "'pkg audit -F' as root downloads it."))
        elif m:
            add(Finding("ok", "pkg audit found no vulnerable packages"))

    if any(l.strip() == "required" for l in s.get("reboot", [])):
        pkgs = sorted({l.strip() for l in s.get("reboot_pkgs", []) if l.strip()})
        add(Finding("warn", "A reboot is needed to finish installing updates",
                    ("Waiting on: " + ", ".join(pkgs[:20])) if pkgs else
                    "Patched code is installed but not yet running."))
    running = _first(s.get("kernel_running"))
    installed = [k.strip() for k in s.get("kernel_installed", [])
                 if re.match(r"^\d+\.\d+", k.strip())]
    if running and installed and re.match(r"^\d+\.\d+", running):
        newest = max(installed, key=_kernel_key)
        if newest != running and _kernel_key(newest) > _kernel_key(running):
            add(Finding("warn", "A newer kernel is installed than the one running",
                        f"Running {running}; installed {newest}. A reboot loads it."))

    sshd = _sshd(s)
    if sshd:
        source = "sshd -T" if s.get("sshd_t") else "sshd_config"
        if sshd.get("permitemptypasswords") == "yes":
            add(Finding("crit", "SSH allows accounts with empty passwords",
                        f"PermitEmptyPasswords yes ({source})."))
        if sshd.get("protocol", "").strip() == "1" or sshd.get("protocol", "").startswith("1,"):
            add(Finding("crit", "SSH allows protocol 1", f"Protocol 1 ({source})."))
        root = sshd.get("permitrootlogin", "")
        password = sshd.get("passwordauthentication", "")
        if root == "yes":
            add(Finding("warn" if password != "no" else "info",
                        "SSH lets root log in" + (" with a password" if password != "no" else ""),
                        f"PermitRootLogin yes ({source}). 'prohibit-password' keeps "
                        "key logins and stops password guessing."))
        if password == "yes":
            add(Finding("info", "SSH accepts passwords",
                        f"PasswordAuthentication yes ({source}). Keys alone resist guessing; "
                        "fail2ban helps if passwords must stay."))
    root_accounts = [u.strip() for u in s.get("uid0", []) if u.strip() and u.strip() != "root"]
    if root_accounts:
        add(Finding("crit", f"{len(root_accounts)} account(s) besides root have UID 0",
                    ", ".join(root_accounts)))
    writable = [l.strip() for l in s.get("etc_writable", []) if l.strip()]
    if writable:
        add(Finding("warn", f"{len(writable)} file(s) in /etc anyone can write",
                    "\n".join(writable)))
    if "autoupdate" in s:
        enabled = [l.split()[0] for l in s["autoupdate"] if l.strip().endswith("enabled")]
        if enabled:
            add(Finding("ok", "Automatic updates are on", ", ".join(enabled)))
        elif "apt" in s or "dnf" in s:
            add(Finding("info", "Automatic security updates are not turned on",
                        "unattended-upgrades (Debian, Ubuntu) or dnf-automatic "
                        "(Fedora, RHEL family) installs them without waiting for you."))


def _kernel_key(text: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", text)[:6])


def _sshd(s: dict[str, list[str]]) -> dict[str, str]:
    """The effective SSH settings: ``sshd -T`` when root could run it, else the
    files, where the first value given for a keyword is the one that counts."""
    out: dict[str, str] = {}
    for line in s.get("sshd_t") or s.get("sshd_config", []):
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() not in out:
            out[parts[0].lower()] = parts[1].strip().lower()
    return out


def _windows_checks(s: dict[str, list[str]], now: float, add) -> None:
    caption, _, build = _first(s.get("windows")).partition("\t")
    found = windows_support_finding(caption, build.strip(), now)
    if found:
        add(found)
    defender = _first(s.get("defender")).split("\t")
    if len(defender) >= 3:
        if defender[0].lower() != "true" or defender[1].lower() != "true":
            add(Finding("crit", "Microsoft Defender is off",
                        f"Antivirus enabled: {defender[0]}, real-time protection: {defender[1]}."))
        elif defender[2].isdigit() and int(defender[2]) > 7:
            add(Finding("warn", f"Defender's signatures are {defender[2]} days old"))
        else:
            add(Finding("ok", "Microsoft Defender is on and up to date"))
    off = [l.split("\t")[0] for l in s.get("firewall", []) if l.lower().endswith("\tfalse")]
    if off:
        add(Finding("warn", "Windows Firewall is off for " + ", ".join(off)))
    if _first(s.get("smb1")).lower() == "true":
        add(Finding("crit", "SMBv1 is enabled",
                    "The protocol WannaCry spread through. Nothing current needs it."))
    if any(l.strip() == "required" for l in s.get("reboot", [])):
        add(Finding("warn", "A reboot is needed to finish installing updates"))
    hotfix = _first(s.get("hotfix_newest")).split("\t")
    if len(hotfix) == 2 and hotfix[1].strip().isdigit():
        days = (now - int(hotfix[1])) / 86400
        if days > 60:
            add(Finding("warn", f"The newest update was installed {int(days)} days ago",
                        f"{hotfix[0]}. Microsoft ships security updates monthly."))
    rdp = _first(s.get("rdp")).split("\t")
    if len(rdp) == 2 and rdp[0].strip() == "0" and rdp[1].strip() == "0":
        add(Finding("warn", "Remote Desktop is on without Network Level Authentication",
                    "Anyone can reach the login screen before proving who they are."))


def _exposure(listeners: list[Listener], add) -> None:
    for port, (severity, name, why) in RISKY_PORTS.items():
        open_ = [l for l in listeners if l.port == port and l.proto == "tcp" and l.exposed]
        if open_:
            add(Finding(severity, f"{name} is listening on every interface (port {port})",
                        why + " Bind it to 127.0.0.1 or firewall it if only this host needs it."))


# ===================================================================== OSV ==

_UBUNTU_CODENAMES = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04",
                     "focal": "20.04", "jammy": "22.04", "noble": "24.04"}


def ecosystem(inv: InventoryReport) -> str:
    """The OSV ecosystem for this server's packages; "" when OSV has none."""
    release = inv.release
    os_id, version = inv.os_id, inv.os_version
    like = inv.os_like
    major = version.split(".")[0]
    if os_id == "debian" or (os_id == "raspbian"):
        return f"Debian:{major}" if major.isdigit() else ""
    if os_id == "ubuntu":
        return f"Ubuntu:{version}" if version else ""
    if "ubuntu" in like:               # Mint, Pop!_OS: say which Ubuntu they are
        version = _UBUNTU_CODENAMES.get(release.get("UBUNTU_CODENAME", ""), "")
        return f"Ubuntu:{version}" if version else ""
    if os_id == "alpine":
        return "Alpine:v" + ".".join(version.split(".")[:2]) if version else ""
    if os_id == "rocky":
        return f"Rocky Linux:{major}" if major else ""
    if os_id == "almalinux":
        return f"AlmaLinux:{major}" if major else ""
    if os_id == "rhel":
        return "Red Hat"
    if os_id == "opensuse-leap":
        return f"openSUSE:Leap {version}" if version else ""
    if os_id in ("sles", "sled"):
        parts = version.split(".")
        if len(parts) == 2:
            return f"SUSE:Linux Enterprise Server {parts[0]} SP{parts[1]}"
        return f"SUSE:Linux Enterprise Server {parts[0]}" if parts[0] else ""
    return ""


def queries(inv: InventoryReport) -> list[tuple[str, str]]:
    """``(name, version)`` per source package, once each, sorted."""
    managers = {"dpkg", "rpm", "apk"}
    seen = set()
    for p in inv.packages:
        if p.manager in managers:
            seen.add((p.source or p.name, p.source_version or p.version))
    return sorted(seen)


def preview(eco: str, wanted: list[tuple[str, str]]) -> str:
    """Exactly what the lookup sends, for the operator to read first."""
    lines = [f"POST {OSV_API}/querybatch",
             f"Ecosystem: {eco}",
             f"{len(wanted)} package(s), each sent as its name and version:", ""]
    lines += [f"{name} {version}" for name, version in wanted]
    lines += ["", f"Then GET {OSV_API}/vulns/<id> for each vulnerability found, to read "
                  "its summary, severity and fixed version."]
    return "\n".join(lines)


def _http(method: str, url: str, body: bytes | None) -> dict:
    from . import tls_context
    request = urllib.request.Request(url, data=body, method=method, headers={
        "Content-Type": "application/json", "User-Agent": "ARES vulnerability scan"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls_context()))
    with opener.open(request, timeout=HTTP_TIMEOUT) as reply:
        return json.loads(reply.read().decode("utf-8"))


@dataclass
class Vuln:
    id: str
    package: str
    version: str                    # installed
    summary: str = ""
    level: str = "unknown"          # critical | high | medium | low | unknown
    score: float | None = None      # CVSS v3 base score, where there is one
    rating: str = ""                # the distribution's own word, where it gives one
    fixed: str = ""                 # the version that fixes it, "" for none yet
    cves: list[str] = field(default_factory=list)
    note: str = ""                  # e.g. "Ubuntu Pro only"

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

_RATINGS = {"critical": "critical", "important": "high", "high": "high",
            "moderate": "medium", "medium": "medium", "low": "low",
            "negligible": "low", "unimportant": "low"}


_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    whole = round(value * 100000)
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """The CVSS 3.x base score of a vector string, or None if it is not one."""
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope_changed = m["S"] == "C"
        av, ac, ui = _CVSS3["AV"][m["AV"]], _CVSS3["AC"][m["AC"]], _CVSS3["UI"][m["UI"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        c, i, a = (_CVSS3["C"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed
              else 6.42 * iss)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(total, 10.0))


def _level(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "unknown"


def _matches(affected_eco: str, eco: str) -> bool:
    return affected_eco == eco or affected_eco.startswith(eco + ":")


def describe(record: dict, package: str, version: str, eco: str) -> Vuln:
    """A Vuln from an OSV record, as it applies to this package here."""
    v = Vuln(id=record.get("id", ""), package=package, version=version)
    v.summary = (record.get("summary") or record.get("details") or "").strip().splitlines()[0][:200] \
        if (record.get("summary") or record.get("details")) else ""
    v.cves = sorted({c for c in record.get("upstream", []) + record.get("aliases", [])
                     if c.startswith("CVE-")} | ({v.id} if v.id.startswith("CVE-") else set()))
    scores = [cvss3_score(s.get("score", "")) for s in record.get("severity", [])
              if s.get("type") == "CVSS_V3"]
    scores = [s for s in scores if s is not None]
    v.score = max(scores) if scores else None
    words = [s.get("score", "") for s in record.get("severity", []) if s.get("type") == "Ubuntu"]
    m = re.match(r"^(Critical|Important|Moderate|Low):", v.summary)
    if m:
        words.append(m.group(1))
    fixes, pro_only = [], False
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != package or not _matches(pkg.get("ecosystem", ""), eco):
            continue
        urgency = (affected.get("ecosystem_specific") or {}).get("urgency", "")
        if urgency:
            words.append(urgency.split()[0])
        availability = (affected.get("ecosystem_specific") or {}).get("availability", "")
        is_pro = ":Pro:" in pkg.get("ecosystem", "")
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixes.append(event["fixed"])
                    pro_only = pro_only or is_pro or "Ubuntu Pro" in availability
    rating = next((w for w in words if w.lower() in _RATINGS), "")
    v.rating = rating.lower()
    v.level = _RATINGS[v.rating] if v.rating else _level(v.score)
    # "0:" is rpm's way of saying there is no epoch; it is noise in a report.
    v.fixed = re.sub(r"^0:", "", fixes[-1]) if fixes else ""
    if v.fixed and pro_only:
        v.note = "fix through Ubuntu Pro"
    return v


@dataclass
class VulnReport:
    platform: str = ""
    os_name: str = ""
    findings: list[Finding] = field(default_factory=list)
    ecosystem: str = ""
    looked_up: bool = False         # the OSV half ran
    packages_checked: int = 0
    vulns: list[Vuln] = field(default_factory=list)
    unread: int = 0                 # matched, but not fetched in full (MAX_DETAILS)
    online_error: str = ""
    online_note: str = ""           # why there was no lookup, when there was none

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in LEVEL_ORDER}
        for v in self.vulns:
            out[v.level] += 1
        return out

    @property
    def severity(self) -> str:
        levels = self.counts()
        online = ("crit" if any(v.level == "critical" and v.fixed for v in self.vulns)
                  else "warn" if levels["critical"] or levels["high"]
                  else "info" if self.vulns else "ok")
        return worst([online] + [f.severity for f in self.findings])

    def headline(self) -> str:
        bad = [f for f in self.findings if f.severity in ("warn", "crit")]
        parts = []
        if self.looked_up:
            c = self.counts()
            if self.vulns:
                parts.append(f"{len(self.vulns)} known vulnerabilit"
                             f"{'y' if len(self.vulns) == 1 else 'ies'} "
                             f"({c['critical']} critical, {c['high']} high)")
            else:
                parts.append("no known vulnerabilities in the packages")
        parts.append(f"{len(bad)} server issue(s)" if bad else "no server issues")
        return "Vulnerability scan: " + ", ".join(parts)

    def to_text(self) -> str:
        lines = [self.headline(), ""]
        if self.os_name:
            lines += [self.os_name, ""]
        lines.append("On the server:")
        for f in self.findings:
            mark = {"crit": "[CRITICAL]", "warn": "[WARNING]", "info": "[info]",
                    "ok": "[ok]"}.get(f.severity, "")
            lines.append(f"  {mark} {f.title}")
            if f.detail:
                lines.extend("      " + d for d in f.detail.splitlines())
        if not self.findings:
            lines.append("  Nothing to report.")
        lines.append("")
        lines.append("Known vulnerabilities in installed packages (OSV):")
        if self.online_error:
            lines.append(f"  The lookup failed: {self.online_error}")
        elif not self.looked_up:
            lines.append(f"  Not looked up. {self.online_note}".rstrip())
        else:
            lines.append(f"  {self.packages_checked} source package(s) checked against "
                         f"{self.ecosystem}.")
            c = self.counts()
            fixable = sum(1 for v in self.vulns if v.fixed)
            if self.vulns:
                lines.append("  " + ", ".join(f"{n} {k}" for k, n in c.items() if n)
                             + f"; {fixable} with a fixed version available.")
            if self.unread:
                lines.append(f"  {self.unread} more matched but were not read in full; "
                             "they are listed by id only.")
            lines.append("")
            fixed = [v for v in self.vulns if v.fixed]
            open_ = [v for v in self.vulns if not v.fixed]
            if fixed:
                lines.append("  Fixed by an update (level, score, package installed -> fixed, id):")
                lines += [self._line(v) for v in fixed]
                lines.append("")
            if open_:
                lines.append("  No fix published yet:")
                lines += [self._line(v) for v in open_]
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _line(v: Vuln) -> str:
        score = f"{v.score:.1f}" if v.score is not None else "  - "
        fix = f" -> {v.fixed}" if v.fixed else ""
        cves = f" [{', '.join(v.cves[:4])}{' …' if len(v.cves) > 4 else ''}]" \
            if v.cves and v.cves != [v.id] else ""
        note = f" ({v.note})" if v.note else ""
        text = f"    {v.level:<8} {score:>4}  {v.package} {v.version}{fix}  {v.id}{cves}{note}"
        if v.summary:
            text += f"\n             {v.summary}"
        return text


def server_checks(run_input: RunInput, inv: InventoryReport | None = None) -> VulnReport:
    platform, out = run_script(run_input, CHECKS_POSIX, CHECKS_WINDOWS)
    report = VulnReport(platform=platform, os_name=inv.os_name if inv else "")
    report.findings = parse_checks(out, platform, inv)
    return report


def lookup(report: VulnReport, inv: InventoryReport, *, http: Http | None = None,
           progress: Callable[[str], None] | None = None) -> VulnReport:
    """Fill in the OSV half. Never raises: a failure is kept on the report."""
    http = http or _http
    eco = ecosystem(inv)
    wanted = queries(inv)
    report.ecosystem = eco
    if not eco or not wanted:
        report.online_note = no_lookup_reason(inv)
        return report
    try:
        matched: list[tuple[str, str, str]] = []          # name, version, id
        for start in range(0, len(wanted), BATCH):
            chunk = wanted[start:start + BATCH]
            body = json.dumps({"queries": [
                {"package": {"name": n, "ecosystem": eco}, "version": v}
                for n, v in chunk]}).encode("utf-8")
            if progress:
                progress(f"asking OSV about {len(chunk)} package(s)…")
            results = http("POST", f"{OSV_API}/querybatch", body).get("results", [])
            for (name, version), result in zip(chunk, results):
                for vuln in (result or {}).get("vulns", []) or []:
                    matched.append((name, version, vuln["id"]))
        ids = list(dict.fromkeys(i for _n, _v, i in matched))
        fetch = ids[:MAX_DETAILS]
        report.unread = max(0, len(ids) - len(fetch))
        if progress and fetch:
            progress(f"reading {len(fetch)} vulnerability record(s)…")

        def get(vid: str) -> tuple[str, dict]:
            try:
                return vid, http("GET", f"{OSV_API}/vulns/{urllib.request.quote(vid)}", None)
            except Exception:
                return vid, {"id": vid}
        with ThreadPoolExecutor(DETAIL_WORKERS) as pool:
            records = dict(pool.map(get, fetch))
        report.vulns = _dedupe([describe(records.get(i, {"id": i}), n, v, eco)
                                for n, v, i in matched])
        report.packages_checked = len(wanted)
        report.looked_up = True
    except urllib.error.HTTPError as exc:
        report.online_error = f"OSV answered {exc.code} {exc.reason}"
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        report.online_error = f"could not reach OSV: {reason}"
    except (ValueError, KeyError, TypeError) as exc:
        report.online_error = f"OSV's answer could not be read: {exc}"
    return report


def _dedupe(vulns: list[Vuln]) -> list[Vuln]:
    """One entry per problem per package.

    Debian files the same flaw twice - as an advisory (DSA, DLA) and as a CVE
    record - so a CVE an advisory already covers is not listed again.
    """
    out: list[Vuln] = []
    covered: dict[str, set[str]] = {}
    seen = set()
    # Advisories first, so the CVE records they cover are the ones dropped.
    for v in sorted(vulns, key=lambda v: "CVE-" in v.id):
        if (v.package, v.id) in seen:
            continue
        seen.add((v.package, v.id))
        mine = covered.setdefault(v.package, set())
        if "CVE-" in v.id and v.cves and set(v.cves) <= mine:
            continue
        mine.update(v.cves)
        out.append(v)
    out.sort(key=lambda v: (LEVEL_ORDER[v.level], -(v.score or 0), v.package, v.id))
    return out


def no_lookup_reason(inv: InventoryReport) -> str:
    if inv.platform == "windows":
        return "OSV has no Windows data; the checks above cover Windows Update."
    if not inv.packages:
        return "No package list was found on this server."
    managers = set(inv.managers)
    if not managers & {"dpkg", "rpm", "apk"}:
        return (f"OSV has no data for {', '.join(sorted(managers))} packages; "
                "the server's own audit tool, where it has one, is reported above.")
    return (f"OSV has no security data for {inv.os_name or inv.os_id or 'this system'}.")


__all__ = ["CHECKS_POSIX", "CHECKS_WINDOWS", "END_OF_SUPPORT", "OSV_API", "VulnReport",
           "Vuln", "cvss3_score", "describe", "ecosystem", "lookup", "no_lookup_reason",
           "parse_checks", "preview", "queries", "server_checks", "support_finding"]
