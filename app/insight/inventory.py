"""What is installed on a server, and what it is running.

One probe over the connection that is already open, parsed here, like the
others in :mod:`ares.protocols.serverinsight`. Nothing is installed on the
server to be studied, and every parser is tested against canned output.

Packages
--------
Whatever package manager the server has: dpkg, rpm, apk, pacman, FreeBSD's
pkg, Homebrew and snap, or the Uninstall keys of the Windows registry. Each
package keeps the name of the *source* package it was built from where the
manager records one (dpkg, rpm, apk), because that is the name the
distributions' security advisories are filed under - see
:mod:`ares.protocols.vulnscan`.

Technologies
------------
The software that matters on a server: web servers, databases, runtimes,
container engines, mail, directory and VPN services. Each is found by any of
three kinds of evidence, and the report says which:

* its program answered a version question (``nginx -v``),
* a process of that name is running,
* a port it is known for is listening.

A port alone is a guess - something else may listen on 8080 - so a technology
seen only that way is marked as such.

Everything is read-only and runs as the user who logged in, so ``ss`` names
the processes behind other users' sockets only for root; the ports are listed
either way.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .serverinsight import RunInput, _first, _sections, run_script

#: Programs that answer a version question, in the order they are asked.
#: ``(key, program, arguments)``. One key can have several programs: the
#: first that is installed answers.
VERSION_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("nginx", "nginx", "-v"),
    ("apache", "apache2", "-v"),
    ("apache", "httpd", "-v"),
    ("caddy", "caddy", "version"),
    ("haproxy", "haproxy", "-v"),
    ("traefik", "traefik", "version"),
    ("varnish", "varnishd", "-V"),
    ("squid", "squid", "-v"),
    ("mysql", "mysqld", "--version"),
    ("mariadb", "mariadbd", "--version"),
    ("postgresql", "postgres", "--version"),
    ("postgresql", "psql", "--version"),
    ("redis", "redis-server", "--version"),
    ("mongodb", "mongod", "--version"),
    ("memcached", "memcached", "-V"),
    ("docker", "docker", "--version"),
    ("podman", "podman", "--version"),
    ("containerd", "containerd", "--version"),
    ("kubernetes", "kubelet", "--version"),
    ("python", "python3", "--version"),
    ("node", "node", "--version"),
    ("php", "php", "-v"),
    ("java", "java", "-version"),
    ("ruby", "ruby", "-v"),
    ("go", "go", "version"),
    ("dotnet", "dotnet", "--version"),
    ("openssh", "ssh", "-V"),
    ("openssl", "openssl", "version"),
    ("bind", "named", "-v"),
    ("postfix", "postconf", "-h mail_version"),
    ("exim", "exim", "-bV"),
    ("dovecot", "dovecot", "--version"),
    ("samba", "smbd", "-V"),
    ("zfs", "zfs", "version"),
    ("proxmox", "pveversion", ""),
    ("wireguard", "wg", "--version"),
    ("openvpn", "openvpn", "--version"),
    ("grafana", "grafana", "--version"),
    ("grafana", "grafana-server", "-v"),
    ("prometheus", "prometheus", "--version"),
    ("git", "git", "--version"),
)


@dataclass(frozen=True)
class Tech:
    """A kind of software the probe knows how to recognise."""

    key: str
    name: str
    category: str
    processes: tuple[str, ...] = ()     # process names (prefixes end in "*")
    ports: tuple[int, ...] = ()


CATALOG: tuple[Tech, ...] = (
    Tech("nginx", "nginx", "Web server", ("nginx",), (80, 443)),
    Tech("apache", "Apache HTTP Server", "Web server", ("apache2", "httpd")),
    Tech("caddy", "Caddy", "Web server", ("caddy",)),
    Tech("iis", "IIS", "Web server", ("w3wp", "inetinfo")),
    Tech("haproxy", "HAProxy", "Load balancer", ("haproxy",)),
    Tech("traefik", "Traefik", "Load balancer", ("traefik",)),
    Tech("varnish", "Varnish", "Cache", ("varnishd",), (6081,)),
    Tech("squid", "Squid", "Proxy", ("squid",), (3128,)),
    Tech("mysql", "MySQL", "Database", ("mysqld",), (3306,)),
    Tech("mariadb", "MariaDB", "Database", ("mariadbd",)),
    Tech("postgresql", "PostgreSQL", "Database", ("postgres", "postmaster"), (5432,)),
    Tech("mssql", "Microsoft SQL Server", "Database", ("sqlservr",), (1433,)),
    Tech("redis", "Redis", "Database", ("redis-server",), (6379,)),
    Tech("mongodb", "MongoDB", "Database", ("mongod",), (27017,)),
    Tech("elasticsearch", "Elasticsearch", "Search", (), (9200,)),
    Tech("memcached", "Memcached", "Cache", ("memcached",), (11211,)),
    Tech("rabbitmq", "RabbitMQ", "Message broker", ("beam.smp",), (5672,)),
    Tech("docker", "Docker", "Containers", ("dockerd",), (2375, 2376)),
    Tech("podman", "Podman", "Containers", ("podman",)),
    Tech("containerd", "containerd", "Containers", ("containerd",)),
    Tech("kubernetes", "Kubernetes (kubelet)", "Containers", ("kubelet",), (10250, 6443)),
    Tech("python", "Python", "Runtime"),
    Tech("node", "Node.js", "Runtime", ("node",)),
    Tech("php", "PHP", "Runtime", ("php-fpm*",)),
    Tech("java", "Java", "Runtime", ("java",)),
    Tech("ruby", "Ruby", "Runtime"),
    Tech("go", "Go", "Runtime"),
    Tech("dotnet", ".NET", "Runtime", ("dotnet",)),
    Tech("openssh", "OpenSSH", "Remote access", ("sshd",), (22,)),
    Tech("rdp", "Remote Desktop", "Remote access", ("TermService",), (3389,)),
    Tech("openssl", "OpenSSL", "Library"),
    Tech("bind", "BIND", "DNS", ("named",), (53,)),
    Tech("postfix", "Postfix", "Mail", ("master",), (25,)),
    Tech("exim", "Exim", "Mail", ("exim", "exim4")),
    Tech("dovecot", "Dovecot", "Mail", ("dovecot",), (143, 993)),
    Tech("samba", "Samba", "File sharing", ("smbd",), (445,)),
    Tech("nfs", "NFS", "File sharing", ("nfsd",), (2049,)),
    Tech("zfs", "OpenZFS", "Storage"),
    Tech("proxmox", "Proxmox VE", "Virtualisation", ("pvedaemon",), (8006,)),
    Tech("libvirt", "libvirt / KVM", "Virtualisation", ("libvirtd", "qemu-system*")),
    Tech("wireguard", "WireGuard", "VPN"),
    Tech("openvpn", "OpenVPN", "VPN", ("openvpn",), (1194,)),
    Tech("grafana", "Grafana", "Monitoring", ("grafana", "grafana-server"), (3000,)),
    Tech("prometheus", "Prometheus", "Monitoring", ("prometheus",), (9090,)),
    Tech("fail2ban", "fail2ban", "Security", ("fail2ban-server",)),
    Tech("defender", "Microsoft Defender", "Security", ("MsMpEng",)),
    Tech("git", "Git", "Tooling"),
)

TECH_BY_KEY = {t.key: t for t in CATALOG}

#: Well-known ports, for naming a listener nothing else explains.
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
              110: "POP3", 111: "rpcbind", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP",
              161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
              514: "syslog", 587: "submission", 631: "IPP", 636: "LDAPS", 873: "rsync",
              993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "SQL Server",
              2049: "NFS", 2375: "Docker API (plain)", 2376: "Docker API (TLS)",
              3000: "Grafana", 3128: "Squid", 3306: "MySQL", 3389: "RDP",
              5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC", 5985: "WinRM",
              5986: "WinRM (TLS)", 6379: "Redis", 6443: "Kubernetes API",
              8006: "Proxmox", 8080: "HTTP (alt)", 8443: "HTTPS (alt)",
              9090: "Prometheus", 9100: "node_exporter", 9200: "Elasticsearch",
              10250: "kubelet", 11211: "Memcached", 27017: "MongoDB"}


def _version_loop() -> str:
    lines = []
    for key, program, args in VERSION_COMMANDS:
        lines.append(f"v {key} {program} {args}".rstrip())
    return "\n".join(lines)


INVENTORY_POSIX = r"""
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
# GNU timeout puts its child in a process group of its own, and dnf then
# prints nothing; --foreground keeps it in ours. Busybox has no such flag.
T=""; command -v timeout >/dev/null 2>&1 && T="timeout 8"
timeout --foreground 1 true >/dev/null 2>&1 && T="timeout --foreground 8"
echo '@@os_release'; cat /etc/os-release 2>/dev/null
echo '@@uname'; uname -srm 2>/dev/null
if command -v dpkg-query >/dev/null 2>&1; then
  echo '@@dpkg'
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' 2>/dev/null
fi
if command -v rpm >/dev/null 2>&1; then
  echo '@@rpm'
  rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null
fi
if [ -r /lib/apk/db/installed ]; then
  echo '@@apk'
  awk -F: '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^A:/{a=substr($0,3)} /^o:/{o=substr($0,3)}
           /^$/{if(p!="")print p"\t"v"\t"a"\t"o; p="";v="";a="";o=""}
           END{if(p!="")print p"\t"v"\t"a"\t"o}' /lib/apk/db/installed
fi
if command -v pacman >/dev/null 2>&1; then echo '@@pacman'; pacman -Q 2>/dev/null; fi
if command -v pkg >/dev/null 2>&1 && [ "$(uname -s)" = FreeBSD ]; then
  echo '@@pkgng'; pkg query '%n\t%v\t%o' 2>/dev/null
fi
if command -v brew >/dev/null 2>&1; then echo '@@brew'; $T brew list --versions 2>/dev/null; fi
if command -v snap >/dev/null 2>&1; then echo '@@snap'; $T snap list 2>/dev/null; fi
echo '@@versions'
v() { k=$1; b=$2; shift 2
  command -v "$b" >/dev/null 2>&1 || return 0
  out=$($T "$b" "$@" 2>&1 </dev/null | grep -m 1 .)
  printf '%s\t%s\t%s\n' "$k" "$b" "$out"; }
__VERSIONS__
echo '@@processes'; ps -eo comm= 2>/dev/null | sort -u || ps -A -o comm= 2>/dev/null | sort -u
echo '@@listen'
if command -v ss >/dev/null 2>&1; then ss -ltnupH 2>/dev/null || ss -ltnup 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  netstat -ltnup 2>/dev/null || netstat -an 2>/dev/null | grep -E 'LISTEN|^udp'
fi
echo '@@containers'; command -v docker >/dev/null 2>&1 && $T docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null
echo '@@end'
""".replace("__VERSIONS__", _version_loop())

INVENTORY_WINDOWS = r"""
'@@windows'; (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Caption)`t$($_.Version)" })
'@@winpkgs'
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object { "$($_.DisplayName)`t$($_.DisplayVersion)`t$($_.Publisher)" } | Sort-Object -Unique
'@@winhotfix'; Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { "$($_.HotFixID)`t$(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') })" }
'@@processes'; Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique
'@@services'; Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name }
'@@winlisten'
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "tcp`t$($_.LocalAddress)`t$($_.LocalPort)`t$p" }
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { $p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "udp`t$($_.LocalAddress)`t$($_.LocalPort)`t$p" }
'@@end'
"""


@dataclass
class Package:
    name: str
    version: str
    manager: str                    # dpkg | rpm | apk | pacman | pkg | brew | snap | windows
    arch: str = ""
    source: str = ""                # the source package, where the manager says
    source_version: str = ""
    publisher: str = ""


@dataclass
class Listener:
    proto: str                      # tcp | udp
    address: str
    port: int
    process: str = ""

    @property
    def exposed(self) -> bool:
        """Listening on every interface, not just loopback."""
        return self.address in ("0.0.0.0", "::", "*", "[::]", "")

    @property
    def local_only(self) -> bool:
        a = self.address.strip("[]")
        return a.startswith("127.") or a in ("::1", "localhost")

    @property
    def label(self) -> str:
        return PORT_NAMES.get(self.port, "")


@dataclass
class Technology:
    key: str
    name: str
    category: str
    version: str = ""
    evidence: list[str] = field(default_factory=list)   # version | process | port
    ports: list[int] = field(default_factory=list)
    detail: str = ""                                    # the program's own words

    @property
    def guessed(self) -> bool:
        return self.evidence == ["port"]


@dataclass
class InventoryReport:
    platform: str = ""
    os_id: str = ""                 # debian, ubuntu, rocky, alpine, windows, ...
    os_like: list[str] = field(default_factory=list)
    os_version: str = ""            # VERSION_ID
    os_name: str = ""               # PRETTY_NAME
    release: dict[str, str] = field(default_factory=dict)   # /etc/os-release
    kernel: str = ""
    packages: list[Package] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    containers: list[tuple[str, str]] = field(default_factory=list)   # name, image
    hotfixes: list[tuple[str, str]] = field(default_factory=list)     # id, date
    processes: list[str] = field(default_factory=list)

    @property
    def managers(self) -> list[str]:
        seen: list[str] = []
        for p in self.packages:
            if p.manager not in seen:
                seen.append(p.manager)
        return seen

    @property
    def severity(self) -> str:
        return "info"

    def headline(self) -> str:
        managers = ", ".join(self.managers) or "no package manager found"
        return (f"Inventory: {len(self.packages)} package(s) ({managers}), "
                f"{len(self.technologies)} technolog{'y' if len(self.technologies) == 1 else 'ies'}, "
                f"{len(self.listeners)} listening port(s)")

    def search(self, needle: str) -> tuple[list[Technology], list[Package]]:
        """What a search box narrows the inventory to: a case-blind substring
        of a name, version, category or source package."""
        n = (needle or "").strip().casefold()
        if not n:
            return list(self.technologies), list(self.packages)
        techs = [t for t in self.technologies
                 if n in f"{t.name} {t.category} {t.version} {t.key}".casefold()]
        pkgs = [p for p in self.packages
                if n in f"{p.name} {p.version} {p.source} {p.manager} {p.publisher}".casefold()]
        return techs, pkgs

    def to_text(self, needle: str = "") -> str:
        techs, pkgs = self.search(needle)
        lines = [self.headline(), ""]
        if self.os_name or self.kernel:
            lines.append(" · ".join(x for x in (self.os_name, self.kernel) if x))
            lines.append("")
        if needle:
            lines += [f"Matching \"{needle}\": {len(techs)} technolog"
                      f"{'y' if len(techs) == 1 else 'ies'}, {len(pkgs)} package(s)", ""]
        if techs:
            lines.append("Technologies (name, version, category, found by):")
            for t in techs:
                found = ", ".join(t.evidence)
                if t.ports:
                    found += " " + ", ".join(str(p) for p in t.ports)
                lines.append(f"    {t.name:<26} {t.version or '-':<16} {t.category:<16} {found}")
            lines.append("")
        if self.listeners and not needle:
            lines.append("Listening ports (protocol, address, port, process):")
            for l in self.listeners:
                lines.append(f"    {l.proto:<4} {l.address:<24} {l.port:<6} "
                             f"{l.process or '-':<20} {l.label}")
            lines.append("")
        if self.containers and not needle:
            lines.append("Running containers:")
            lines += [f"    {n:<30} {i}" for n, i in self.containers]
            lines.append("")
        if self.hotfixes and not needle:
            lines.append(f"Installed updates: {len(self.hotfixes)}, newest "
                         f"{max((d for _i, d in self.hotfixes if d), default='-')}")
            lines.append("")
        if pkgs:
            lines.append("Packages (name, version, manager):")
            lines += [f"    {p.name:<40} {p.version:<32} {p.manager}" for p in pkgs]
        return "\n".join(lines).rstrip() + "\n"


# ------------------------------------------------------------------ parsing --

_VERSION = re.compile(r"(\d+(?:\.\d+)+[\w.+~-]*|\d+[a-z]\w*)")


def version_of(text: str) -> str:
    """The first version-looking token in a program's answer."""
    found = _VERSION.search(text or "")
    return found.group(1).rstrip(",;)") if found else ""


def parse_os_release(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _parse_dpkg(lines: list[str]) -> list[Package]:
    out = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        status, name, version = parts[0].strip(), parts[1], parts[2]
        if status and not status.startswith("i"):     # "rc" is removed, config left
            continue
        arch = parts[3] if len(parts) > 3 else ""
        source = (parts[4] if len(parts) > 4 else "") or name
        # dpkg writes "src (1.2-3)" when the source version differs.
        m = re.match(r"^(\S+)\s+\((.+)\)$", source)
        if m:
            source = m.group(1)
        source_version = (parts[5] if len(parts) > 5 else "") or version
        out.append(Package(name, version, "dpkg", arch, source, source_version))
    return out


def _rpm_source_name(srpm: str) -> str:
    """``openssl-3.0.1-41.el9_0.src.rpm`` -> ``openssl``."""
    srpm = srpm.strip()
    if not srpm or srpm == "(none)":
        return ""
    stem = re.sub(r"\.(no)?src\.rpm$", "", srpm)
    parts = stem.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else ""


def _parse_rpm(lines: list[str]) -> list[Package]:
    out = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0] or parts[0] == "gpg-pubkey":
            continue
        arch = parts[2] if len(parts) > 2 else ""
        source = _rpm_source_name(parts[3]) if len(parts) > 3 else ""
        out.append(Package(parts[0], parts[1], "rpm", arch, source or parts[0], parts[1]))
    return out


def _parse_apk(lines: list[str]) -> list[Package]:
    out = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            source = parts[3] if len(parts) > 3 and parts[3] else parts[0]
            out.append(Package(parts[0], parts[1], "apk",
                               parts[2] if len(parts) > 2 else "", source, parts[1]))
    return out


def _parse_pairs(lines: list[str], manager: str) -> list[Package]:
    """``name version [version...]`` per line: pacman -Q, brew list --versions."""
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            out.append(Package(parts[0], parts[-1], manager))
    return out


def _parse_pkgng(lines: list[str]) -> list[Package]:
    out = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            out.append(Package(parts[0], parts[1], "pkg",
                               source=parts[2] if len(parts) > 2 else ""))
    return out


def _parse_snap(lines: list[str]) -> list[Package]:
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] != "Name":
            out.append(Package(parts[0], parts[1], "snap"))
    return out


def _parse_windows_packages(lines: list[str]) -> list[Package]:
    out = []
    for line in lines:
        parts = line.split("\t")
        if parts and parts[0].strip():
            out.append(Package(parts[0].strip(), (parts[1] if len(parts) > 1 else "").strip(),
                               "windows", publisher=(parts[2] if len(parts) > 2 else "").strip()))
    return out


def _split_address(text: str) -> tuple[str, int] | None:
    """``0.0.0.0:22``, ``[::]:22``, ``*:22``, ``::1.631`` (BSD) -> (address, port)."""
    text = text.strip()
    m = re.match(r"^(.*)[:.](\d+)$", text)
    if not m:
        return None
    address = m.group(1)
    if "%" in address:                      # 0.0.0.0%lo:53, fe80::1%eth0
        address = address.split("%")[0]
    return address.strip("[]") or "*", int(m.group(2))


def parse_listeners(lines: list[str]) -> list[Listener]:
    out: list[Listener] = []
    seen = set()
    for line in lines:
        parts = line.split()
        if not parts or parts[0] in ("Netid", "State", "Proto", "Active"):
            continue
        proto = parts[0].lower()
        if proto.startswith("tcp"):
            proto = "tcp"
        elif proto.startswith("udp"):
            proto = "udp"
        else:
            continue
        local, process = "", ""
        if len(parts) >= 5 and parts[1] in ("LISTEN", "UNCONN"):      # ss
            local = parts[4]
            m = re.search(r'users:\(\("([^"]+)"', line)
            process = m.group(1) if m else ""
        elif len(parts) >= 4:                                          # netstat
            local = parts[3]
            m = re.search(r"\d+/(\S+)\s*$", line)
            process = m.group(1) if m else ""
        found = _split_address(local)
        if not found:
            continue
        address, port = found
        key = (proto, address, port)
        if key in seen:
            continue
        seen.add(key)
        out.append(Listener(proto, address, port, process))
    out.sort(key=lambda l: (l.proto, l.port, l.address))
    return out


def _parse_windows_listeners(lines: list[str]) -> list[Listener]:
    out, seen = [], set()
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip().isdigit():
            key = (parts[0], parts[1], int(parts[2]))
            if key in seen:
                continue
            seen.add(key)
            out.append(Listener(parts[0], parts[1].strip(), int(parts[2]),
                                parts[3].strip() if len(parts) > 3 else ""))
    out.sort(key=lambda l: (l.proto, l.port, l.address))
    return out


def _process_matches(pattern: str, names: set[str]) -> bool:
    if pattern.endswith("*"):
        return any(n.startswith(pattern[:-1]) for n in names)
    return pattern in names


def detect_technologies(versions: list[str], processes: list[str],
                        listeners: list[Listener]) -> list[Technology]:
    """Every technology there is evidence for, with that evidence."""
    found: dict[str, Technology] = {}

    def tech(key: str) -> Technology:
        if key not in found:
            t = TECH_BY_KEY[key]
            found[key] = Technology(key, t.name, t.category)
        return found[key]

    for line in versions:
        parts = line.split("\t", 2)
        if len(parts) < 2 or parts[0] not in TECH_BY_KEY:
            continue
        answer = parts[2].strip() if len(parts) > 2 else ""
        if re.search(r"not found|no such file|command not found", answer, re.I):
            continue
        t = tech(parts[0])
        if "version" not in t.evidence:
            t.evidence.append("version")
            t.version = version_of(answer)
            t.detail = answer[:200]
    names = {p.strip().rsplit("/", 1)[-1] for p in processes if p.strip()}
    listening = {l.port for l in listeners}
    for t in CATALOG:
        if any(_process_matches(p, names) for p in t.processes):
            entry = tech(t.key)
            if "process" not in entry.evidence:
                entry.evidence.append("process")
        ports = sorted(p for p in t.ports if p in listening)
        # A port is weak evidence: it only counts on its own for software
        # whose port nobody else uses by default.
        if ports and (t.key in found or t.key in ("elasticsearch", "mssql", "rdp",
                                                   "mongodb", "redis", "memcached",
                                                   "kubernetes", "proxmox")):
            entry = tech(t.key)
            entry.ports = ports
            if "port" not in entry.evidence:
                entry.evidence.append("port")
    order = {t.key: i for i, t in enumerate(CATALOG)}
    return sorted(found.values(), key=lambda t: (t.category, order[t.key]))


def parse_inventory(text: str, platform: str = "posix") -> InventoryReport:
    s = _sections(text)
    r = InventoryReport(platform=platform)
    if platform == "windows":
        caption, _, version = _first(s.get("windows")).partition("\t")
        r.os_id, r.os_name, r.os_version = "windows", caption.strip(), version.strip()
        r.packages = _parse_windows_packages(s.get("winpkgs", []))
        for line in s.get("winhotfix", []):
            hid, _, date = line.partition("\t")
            if hid.strip():
                r.hotfixes.append((hid.strip(), date.strip()))
        r.processes = [p.strip() for p in s.get("processes", []) + s.get("services", [])
                       if p.strip()]
        r.listeners = _parse_windows_listeners(s.get("winlisten", []))
        r.technologies = detect_technologies([], r.processes, r.listeners)
        return r
    release = parse_os_release(s.get("os_release", []))
    r.release = release
    r.os_id = release.get("ID", "").lower()
    r.os_like = release.get("ID_LIKE", "").lower().split()
    r.os_version = release.get("VERSION_ID", "")
    r.os_name = release.get("PRETTY_NAME", "")
    r.kernel = _first(s.get("uname"))
    if not r.os_id and r.kernel:
        r.os_id = r.kernel.split()[0].lower()          # darwin, freebsd
    r.packages = (_parse_dpkg(s.get("dpkg", [])) + _parse_rpm(s.get("rpm", []))
                  + _parse_apk(s.get("apk", [])) + _parse_pairs(s.get("pacman", []), "pacman")
                  + _parse_pkgng(s.get("pkgng", [])) + _parse_pairs(s.get("brew", []), "brew")
                  + _parse_snap(s.get("snap", [])))
    r.packages.sort(key=lambda p: (p.manager, p.name.casefold()))
    r.processes = [p.strip() for p in s.get("processes", []) if p.strip()]
    r.listeners = parse_listeners(s.get("listen", []))
    for line in s.get("containers", []):
        name, sep, image = line.partition("\t")
        if sep and name.strip():
            r.containers.append((name.strip(), image.strip()))
    r.technologies = detect_technologies(s.get("versions", []), r.processes, r.listeners)
    return r


def inventory(run_input: RunInput) -> InventoryReport:
    platform, out = run_script(run_input, INVENTORY_POSIX, INVENTORY_WINDOWS)
    return parse_inventory(out, platform)


__all__ = ["CATALOG", "INVENTORY_POSIX", "INVENTORY_WINDOWS", "InventoryReport", "Listener",
           "PORT_NAMES", "Package", "Technology", "detect_technologies", "inventory",
           "parse_inventory", "parse_listeners", "parse_os_release", "version_of"]
