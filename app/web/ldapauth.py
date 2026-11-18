"""LDAP / Active Directory sign-in.

Search-then-bind: a service account (``bind_dn``, or an anonymous bind when it is empty) finds the
user's entry with ``user_filter`` (the typed username is escaped, RFC 4515), then the password is
checked by binding *as that entry's DN* on a fresh connection. The password never goes into a
filter or a log line. An empty password is always refused: many servers treat a simple bind with an
empty password as an anonymous bind and answer "success".

Transport: ``ldaps://`` or ``ldap://`` with StartTLS; certificates are verified by default, against
``ca_pem`` when one is pinned, else the system / certifi trust store. Several server URLs (space or
comma separated) are tried in order for failover. ``ldap3`` is imported lazily, so the rest of the
app runs without it.
"""

from __future__ import annotations

import os
import ssl
import tempfile
from typing import Any
from urllib.parse import urlsplit

from .oidc import Identity

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "server_url": "ldaps://dc.example.com:636",
    "start_tls": False,
    "verify_tls": True,
    "ca_pem": "",
    "bind_dn": "",
    "bind_password_enc": "",
    "base_dn": "",
    "user_filter": "(&(objectClass=person)(|(sAMAccountName={username})(uid={username})"
                   "(userPrincipalName={username})))",
    "username_attr": "sAMAccountName",
    "email_attr": "mail",
    "name_attr": "displayName",
    "group_attr": "memberOf",
    "auto_provision": True,
    "default_role": "user",
    "admin_groups": [],
    "allowed_groups": [],
    "sync_role": True,
    "timeout": 10,
}


class LdapError(Exception):
    """code: invalid_credentials | not_found | not_allowed | config | unreachable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _ldap3():
    try:
        import ldap3
        return ldap3
    except ImportError:
        raise LdapError("config", "LDAP support is not installed on this server (python package ldap3)") from None


def escape(value: str) -> str:
    """RFC 4515 filter escaping (same as ldap3.utils.conv.escape_filter_chars)."""
    out = []
    for ch in value:
        if ch in "\\*()\x00":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def build_filter(template: str, username: str) -> str:
    template = template or DEFAULTS["user_filter"]
    if "{username}" not in template:
        raise LdapError("config", "The user filter must contain {username}")
    f = template.replace("{username}", escape(username))
    if not (f.startswith("(") and f.endswith(")")):
        f = f"({f})"
    return f


def servers_of(cfg: dict) -> list[str]:
    urls = [u for u in str(cfg.get("server_url") or "").replace(",", " ").split() if u]
    for u in urls:
        p = urlsplit(u)
        if p.scheme not in ("ldap", "ldaps") or not p.hostname:
            raise LdapError("config", f"Server URL {u!r} must look like ldaps://host[:636] or ldap://host[:389]")
    if not urls:
        raise LdapError("config", "Set the LDAP server URL")
    return urls


def _rdn_values(dn: str) -> set[str]:
    """Lower-cased CN values of a DN: 'CN=Admins,OU=Groups,DC=x' -> {'admins'}."""
    out = set()
    for part in _split_dn(dn):
        k, _, v = part.partition("=")
        if k.strip().lower() == "cn" and v.strip():
            out.add(v.strip().lower())
    return out


def _split_dn(dn: str) -> list[str]:
    parts, cur, esc = [], [], False
    for ch in dn:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == ",":
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _norm_dn(dn: str) -> str:
    return ",".join(p.split("=", 1)[0].strip().lower() + "=" + p.split("=", 1)[-1].strip().lower()
                    if "=" in p else p.lower() for p in _split_dn(dn))


def group_matches(memberships: list[str], wanted: list[str]) -> bool:
    """Whether any configured group (a full DN, or just a CN) is among the user's groups."""
    if not wanted:
        return False
    have_dn = {_norm_dn(m) for m in memberships}
    have_cn = set()
    for m in memberships:
        have_cn |= _rdn_values(m) or {m.strip().lower()}
    for w in wanted:
        w = str(w).strip()
        if not w:
            continue
        if "=" in w:
            if _norm_dn(w) in have_dn:
                return True
        elif w.lower() in have_cn:
            return True
    return False


def _tls(cfg: dict, ldap3, ca_file: str | None):
    if not cfg.get("verify_tls", True):
        return ldap3.Tls(validate=ssl.CERT_NONE)
    if ca_file:
        return ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file)
    try:
        import certifi
        return ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=certifi.where())
    except ImportError:
        return ldap3.Tls(validate=ssl.CERT_REQUIRED)


class _CaFile:
    """A pinned CA bundle on disk for the duration of one sign-in (ldap3 wants a path)."""

    def __init__(self, pem: str):
        self.pem, self.path = (pem or "").strip(), None

    def __enter__(self):
        if self.pem:
            fd, self.path = tempfile.mkstemp(prefix="ldap-ca-", suffix=".pem")
            with os.fdopen(fd, "w") as f:
                f.write(self.pem + "\n")
        return self.path

    def __exit__(self, *exc):
        if self.path:
            try:
                os.unlink(self.path)
            except OSError:
                pass


def _connect(cfg: dict, user: str | None, password: str | None, ca_file: str | None,
             as_user: bool = False):
    """A bound connection to the first reachable server; raises LdapError."""
    ldap3 = _ldap3()
    from ldap3.core import exceptions as lx
    timeout = max(2, min(int(cfg.get("timeout") or 10), 60))
    tls = _tls(cfg, ldap3, ca_file)
    last = "no server"
    for url in servers_of(cfg):
        p = urlsplit(url)
        use_ssl = p.scheme == "ldaps"
        server = ldap3.Server(p.hostname, port=p.port or (636 if use_ssl else 389), use_ssl=use_ssl,
                              tls=tls, get_info=ldap3.NONE, connect_timeout=timeout)
        conn = ldap3.Connection(server, user=user or None, password=password or None,
                                authentication=ldap3.SIMPLE if user else ldap3.ANONYMOUS,
                                receive_timeout=timeout, raise_exceptions=False, read_only=True,
                                auto_referrals=False)
        try:
            conn.open()
            if cfg.get("start_tls") and not use_ssl and not conn.start_tls():
                last = f"{p.hostname}: StartTLS failed"
                conn.unbind()
                continue
            if not conn.bind():
                code = (conn.result or {}).get("description", "")
                conn.unbind()
                if code == "invalidCredentials" and as_user:
                    raise LdapError("invalid_credentials", "wrong username or password")
                who = "the user" if as_user else "the service account"
                raise LdapError("config", f"{p.hostname} refused the bind as {who}: {code or 'error'}")
            return conn
        except LdapError:
            raise
        except (lx.LDAPSocketOpenError, lx.LDAPSocketReceiveError, lx.LDAPStartTLSError, OSError,
                ssl.SSLError) as e:
            last = f"{p.hostname}: {e}"
            continue
        except lx.LDAPException as e:
            last = f"{p.hostname}: {type(e).__name__}"
            continue
    raise LdapError("unreachable", f"no LDAP server reachable ({last})")


def _first(entry: dict, attr: str) -> str:
    v = entry.get(attr) if attr else None
    if isinstance(v, list):
        v = v[0] if v else ""
    return str(v or "").strip()


def _find(conn, cfg: dict, username: str) -> tuple[str, dict]:
    ldap3 = _ldap3()
    attrs = [a for a in {cfg.get("username_attr"), cfg.get("email_attr"), cfg.get("name_attr"),
                         cfg.get("group_attr"), "objectGUID", "entryUUID"} if a]
    base = str(cfg.get("base_dn") or "").strip()
    if not base:
        raise LdapError("config", "Set the base DN to search for users")
    conn.search(base, build_filter(str(cfg.get("user_filter") or ""), username),
                search_scope=ldap3.SUBTREE, attributes=attrs, size_limit=2)
    hits = [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]
    if not hits:
        raise LdapError("not_found", "wrong username or password")
    if len(hits) > 1:
        raise LdapError("config", "the user filter matches more than one entry; make it stricter")
    return hits[0]["dn"], dict(hits[0].get("attributes") or {})


def to_identity(cfg: dict, dn: str, attrs: dict, typed: str) -> Identity:
    groups_raw = attrs.get(cfg.get("group_attr") or "memberOf") or []
    groups = [str(g) for g in (groups_raw if isinstance(groups_raw, list) else [groups_raw]) if str(g)]
    guid = _first(attrs, "objectGUID") or _first(attrs, "entryUUID")
    username = (_first(attrs, cfg.get("username_attr") or "") or typed).strip().lower()[:128]
    return Identity(subject=guid or dn, username=username, email=_first(attrs, cfg.get("email_attr") or "")[:200],
                    display_name=(_first(attrs, cfg.get("name_attr") or "") or username)[:200],
                    groups=groups, source="ldap")


def authenticate(cfg: dict, bind_password: str, username: str, password: str) -> Identity:
    username = (username or "").strip()
    if not username or len(username) > 256 or not password:
        raise LdapError("invalid_credentials", "wrong username or password")
    with _CaFile(str(cfg.get("ca_pem") or "")) as ca:
        svc = _connect(cfg, str(cfg.get("bind_dn") or "") or None, bind_password or None, ca)
        try:
            dn, attrs = _find(svc, cfg, username)
        finally:
            svc.unbind()
        user = _connect(cfg, dn, password, ca, as_user=True)
        user.unbind()
    ident = to_identity(cfg, dn, attrs, username)
    allowed = [g for g in (cfg.get("allowed_groups") or []) if str(g).strip()]
    if allowed and not group_matches(ident.groups, allowed):
        raise LdapError("not_allowed", f"{ident.username} is not in a group allowed to sign in")
    return ident


def test(cfg: dict, bind_password: str, username: str = "", password: str = "") -> str:
    """Bind with the service account, optionally look up (and authenticate) a user. Human summary."""
    with _CaFile(str(cfg.get("ca_pem") or "")) as ca:
        svc = _connect(cfg, str(cfg.get("bind_dn") or "") or None, bind_password or None, ca)
        try:
            host = svc.server.host
            if not username:
                return f"Connected to {host} and bound as {cfg.get('bind_dn') or 'anonymous'}."
            dn, attrs = _find(svc, cfg, username)
        finally:
            svc.unbind()
    ident = to_identity(cfg, dn, attrs, username)
    msg = f"Found {dn} ({ident.email or 'no email'}, {len(ident.groups)} group(s))."
    if password:
        authenticate(cfg, bind_password, username, password)
        msg += " The password is correct."
    if cfg.get("admin_groups"):
        msg += " Administrator: " + ("yes." if group_matches(ident.groups, cfg["admin_groups"]) else "no.")
    return msg
