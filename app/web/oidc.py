"""OpenID Connect sign-in: Microsoft Entra ID, or any OIDC provider.

Authorization code flow with PKCE (S256) for a confidential client:

1. ``/auth/oidc/login`` stores (state, nonce, verifier) and redirects to :func:`auth_url`.
2. The provider redirects back with ``code`` and ``state``; the caller consumes the state row,
   :func:`exchange_code` swaps the code for tokens at the token endpoint (client secret in the
   body, ``client_secret_post``), and :func:`validate_id_token` checks the ID token.
3. :func:`identity` maps the verified claims to the shared :class:`Identity`.

ID token checks, all required: JWS header ``alg`` in RS256/RS384/RS512/PS256/ES256/ES384 (never
``none`` or HMAC), signature against the provider's JWKS (fetched over HTTPS, cached, refetched once
when the ``kid`` is unknown, for key rollover), ``iss`` equals the discovery issuer (Entra's
multi-tenant ``{tenantid}`` template is resolved from the ``tid`` claim), ``aud`` contains our
client id (and ``azp``, when present with several audiences, is us), ``exp``/``nbf``/``iat`` with
60 s skew, and ``nonce`` equals the one we sent.

Standard library only for HTTP (urllib, with the certifi CA bundle when it is installed);
``cryptography`` verifies the signature.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

SKEW = 60
CACHE_TTL = 3600.0
JWKS_MIN_REFRESH = 60.0          # never refetch the key set more often than this on an unknown kid
MAX_BODY = 1024 * 1024
ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "provider": "entra",                 # entra | generic
    "button_label": "Sign in with Microsoft",
    "tenant_id": "",                     # entra: directory (tenant) id or domain; "organizations" for multi-tenant
    "discovery_url": "",                 # generic: https://idp/.well-known/openid-configuration
    "client_id": "",
    "client_secret_enc": "",             # sealed with APP_KEY by the caller; never returned
    "scopes": "openid profile email",
    "username_claim": "preferred_username",   # preferred_username | email | upn | sub
    "groups_claim": "groups",
    "auto_provision": True,
    "default_role": "user",
    "admin_groups": [],
    "allowed_groups": [],
    "sync_role": True,
}
USERNAME_CLAIMS = ("preferred_username", "email", "upn", "sub")


class OidcError(Exception):
    """Sign-in must not proceed. The message is safe to show and to log (no tokens in it)."""


@dataclass
class Identity:
    """A verified external identity, the same shape for OIDC, SAML and LDAP."""
    subject: str
    username: str
    email: str = ""
    display_name: str = ""
    groups: list[str] = field(default_factory=list)
    source: str = "oidc"


# ─── HTTP ────────────────────────────────────────────────────────────────────

_ctx_lock = threading.Lock()
_ctx: ssl.SSLContext | None = None


def _ssl() -> ssl.SSLContext:
    global _ctx
    with _ctx_lock:
        if _ctx is None:
            try:
                import certifi
                _ctx = ssl.create_default_context(cafile=certifi.where())
            except ImportError:
                _ctx = ssl.create_default_context()
        return _ctx


def _https(url: str, what: str) -> str:
    u = urllib.parse.urlsplit(url or "")
    if u.scheme != "https" or not u.hostname:
        raise OidcError(f"{what} must be an https:// URL")
    return url


def _request(url: str, data: dict | None = None, timeout: float = 10.0) -> dict:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={
        "Accept": "application/json", "User-Agent": "ares-terminal-console",
        **({"Content-Type": "application/x-www-form-urlencoded"} if body else {})})
    host = urllib.parse.urlsplit(url).hostname
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl()) as r:
            raw = r.read(MAX_BODY + 1)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            err = json.loads(e.read(65536) or b"{}")
            detail = str(err.get("error_description") or err.get("error") or "")[:300]
        except ValueError:
            pass
        raise OidcError(f"{host} answered HTTP {e.code}" + (f": {detail}" if detail else "")) from None
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise OidcError(f"cannot reach {host}: {reason}") from None
    if len(raw) > MAX_BODY:
        raise OidcError(f"{host} sent an oversized response")
    try:
        out = json.loads(raw)
    except ValueError:
        raise OidcError(f"{host} did not answer with JSON") from None
    if not isinstance(out, dict):
        raise OidcError(f"{host} answered with unexpected JSON")
    return out


# ─── discovery and keys ──────────────────────────────────────────────────────

_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def discovery_url(cfg: dict) -> str:
    if (cfg.get("provider") or "entra") == "entra":
        tenant = str(cfg.get("tenant_id") or "").strip()
        if not tenant or not all(c.isalnum() or c in "-._" for c in tenant):
            raise OidcError("Set the Entra ID directory (tenant) ID")
        return f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
    return _https(str(cfg.get("discovery_url") or "").strip(), "Discovery URL")


def _cached(url: str, ttl: float = CACHE_TTL) -> dict | None:
    with _cache_lock:
        hit = _cache.get(url)
    return hit[1] if hit and time.time() - hit[0] < ttl else None


def _store(url: str, doc: dict) -> None:
    with _cache_lock:
        _cache[url] = (time.time(), doc)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def discover(cfg: dict, timeout: float = 10) -> dict:
    url = discovery_url(cfg)
    doc = _cached(url)
    if doc is None:
        doc = _request(url, timeout=timeout)
        for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not doc.get(k):
                raise OidcError(f"discovery document has no {k}")
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            _https(doc[k], k)
        _store(url, doc)
    return doc


def _jwks(uri: str, force: bool = False) -> dict:
    if not force:
        doc = _cached(uri)
        if doc is not None:
            return doc
    else:
        with _cache_lock:
            hit = _cache.get(uri)
        if hit and time.time() - hit[0] < JWKS_MIN_REFRESH:
            return hit[1]
    doc = _request(uri)
    if not isinstance(doc.get("keys"), list):
        raise OidcError("the provider's key set (JWKS) has no keys")
    _store(uri, doc)
    return doc


# ─── authorization request and code exchange ─────────────────────────────────

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def new_pkce() -> tuple[str, str]:
    verifier = _b64u(secrets.token_bytes(32))
    return verifier, _b64u(hashlib.sha256(verifier.encode()).digest())


def _scopes(cfg: dict) -> str:
    sc = [s for s in str(cfg.get("scopes") or "").replace(",", " ").split() if s]
    if "openid" not in sc:
        sc.insert(0, "openid")
    return " ".join(sc)


def auth_url(cfg: dict, redirect_uri: str, state: str, nonce: str, challenge: str) -> str:
    if not cfg.get("client_id"):
        raise OidcError("Set the client (application) ID")
    ep = discover(cfg)["authorization_endpoint"]
    q = {"client_id": cfg["client_id"], "response_type": "code", "redirect_uri": redirect_uri,
         "scope": _scopes(cfg), "state": state, "nonce": nonce, "code_challenge": challenge,
         "code_challenge_method": "S256", "response_mode": "query"}
    return ep + ("&" if "?" in ep else "?") + urllib.parse.urlencode(q)


def exchange_code(cfg: dict, client_secret: str, code: str, redirect_uri: str, verifier: str) -> dict:
    if not code or len(code) > 4096:
        raise OidcError("no authorization code in the response")
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": cfg.get("client_id", ""), "code_verifier": verifier}
    if client_secret:
        data["client_secret"] = client_secret
    tok = _request(discover(cfg)["token_endpoint"], data=data)
    if not tok.get("id_token"):
        raise OidcError("the token endpoint returned no ID token (is the openid scope allowed?)")
    return tok


# ─── ID token ────────────────────────────────────────────────────────────────

def _public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(_unb64u(jwk["n"]), "big")
        e = int.from_bytes(_unb64u(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}.get(jwk.get("crv"))
        if curve is None:
            raise OidcError(f"unsupported EC curve {jwk.get('crv')!r}")
        x = int.from_bytes(_unb64u(jwk["x"]), "big")
        y = int.from_bytes(_unb64u(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise OidcError(f"unsupported key type {kty!r}")


def _verify(alg: str, key, signed: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    h = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}[alg[2:]]
    try:
        if alg.startswith(("RS", "PS")):
            if not isinstance(key, rsa.RSAPublicKey):
                return False
            pad = padding.PKCS1v15() if alg.startswith("RS") else \
                padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size)
            key.verify(sig, signed, pad, h)
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return False
            half = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
            key.verify(der, signed, ec.ECDSA(h))
        return True
    except (InvalidSignature, ValueError):
        return False


def _find_key(keys: list[dict], kid: str, alg: str) -> list[dict]:
    usable = [k for k in keys if k.get("use", "sig") == "sig" and k.get("alg", alg) == alg]
    if kid:
        return [k for k in usable if k.get("kid") == kid]
    return usable


def validate_id_token(cfg: dict, id_token: str, nonce: str, client_id: str = "") -> dict:
    client_id = client_id or str(cfg.get("client_id") or "")
    parts = (id_token or "").split(".")
    if len(parts) != 3:
        raise OidcError("the ID token is not a signed JWT")
    try:
        header = json.loads(_unb64u(parts[0]))
        claims = json.loads(_unb64u(parts[1]))
        sig = _unb64u(parts[2])
    except (ValueError, TypeError):
        raise OidcError("the ID token is malformed") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OidcError("the ID token is malformed")
    alg = header.get("alg")
    if alg not in ALGS:
        raise OidcError(f"ID token algorithm {alg!r} is not accepted")
    doc = discover(cfg)
    kid = str(header.get("kid") or "")
    candidates = _find_key(_jwks(doc["jwks_uri"]).get("keys", []), kid, alg)
    if not candidates:                                  # key rollover: one refetch
        candidates = _find_key(_jwks(doc["jwks_uri"], force=True).get("keys", []), kid, alg)
    if not candidates:
        raise OidcError("the ID token is signed with a key the provider does not publish")
    signed = (parts[0] + "." + parts[1]).encode()
    ok = False
    for jwk in candidates:
        try:
            ok = _verify(alg, _public_key(jwk), signed, sig)
        except (KeyError, ValueError, OidcError):
            ok = False
        if ok:
            break
    if not ok:
        raise OidcError("the ID token signature is invalid")

    issuer = str(doc["issuer"])
    if "{tenantid}" in issuer:
        tid = str(claims.get("tid") or "")
        if not tid:
            raise OidcError("the ID token has no tenant (tid) claim")
        issuer = issuer.replace("{tenantid}", tid)
    if claims.get("iss") != issuer:
        raise OidcError(f"unexpected issuer {claims.get('iss')!r}")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if not client_id or client_id not in auds:
        raise OidcError("the ID token is not for this application (audience)")
    if len(auds) > 1 and claims.get("azp") not in (None, client_id):
        raise OidcError("the ID token was issued to another party (azp)")
    now = time.time()
    try:
        exp = float(claims["exp"])
        iat = float(claims.get("iat", now))
        nbf = float(claims.get("nbf", 0))
    except (KeyError, TypeError, ValueError):
        raise OidcError("the ID token has no valid expiry") from None
    if exp + SKEW <= now:
        raise OidcError("the ID token has expired")
    if nbf - SKEW > now or iat - SKEW > now:
        raise OidcError("the ID token is not valid yet (check the server clock)")
    if not nonce or not secrets.compare_digest(str(claims.get("nonce") or ""), nonce):
        raise OidcError("the ID token nonce does not match this sign-in")
    if not claims.get("sub"):
        raise OidcError("the ID token has no subject")
    return claims


def identity(cfg: dict, claims: dict) -> Identity:
    """Shared identity for verified claims. On Entra the stable subject is ``tid:oid``."""
    oid, tid = str(claims.get("oid") or ""), str(claims.get("tid") or "")
    subject = f"{tid}:{oid}" if oid and tid else str(claims["sub"])
    email = str(claims.get("email") or "")
    upn = str(claims.get("preferred_username") or claims.get("upn") or "")
    if not email and "@" in upn:
        email = upn
    which = cfg.get("username_claim") or "preferred_username"
    if which not in USERNAME_CLAIMS:
        which = "preferred_username"
    username = str(claims.get(which) or "") or upn or email or str(claims["sub"])
    display = str(claims.get("name") or "") or \
        f"{claims.get('given_name', '')} {claims.get('family_name', '')}".strip() or username
    groups: list[str] = []
    for c in (str(cfg.get("groups_claim") or "groups"), "roles"):
        v = claims.get(c)
        for g in (v if isinstance(v, list) else [v] if isinstance(v, str) else []):
            if str(g) and str(g) not in groups:
                groups.append(str(g))
    return Identity(subject=subject, username=username.strip().lower()[:128], email=email[:200],
                    display_name=display[:200], groups=groups, source="oidc")


def group_overage(claims: dict) -> bool:
    """Entra sends ``_claim_names.groups`` instead of the list when a user is in >200 groups."""
    names = claims.get("_claim_names")
    return isinstance(names, dict) and "groups" in names


def test(cfg: dict) -> str:
    """Fetch discovery and the key set; a one-line human summary (raises OidcError)."""
    url = discovery_url(cfg)
    with _cache_lock:
        _cache.pop(url, None)
    doc = discover(cfg)
    keys = _jwks(doc["jwks_uri"], force=True).get("keys", [])
    if not cfg.get("client_id"):
        raise OidcError("discovery works, but the client (application) ID is not set")
    return (f"Issuer {doc['issuer']}; {len(keys)} signing key(s); "
            f"authorization endpoint {urllib.parse.urlsplit(doc['authorization_endpoint']).hostname}.")
