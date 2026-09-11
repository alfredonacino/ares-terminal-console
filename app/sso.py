"""
Accepting the suite's single sign-on ticket.

Vendored verbatim from ApexBuild's apexbuild/sso.py so that both ends of the
protocol are the same code. Copy it rather than depending on ApexBuild: a
module has to keep working when it is run on its own, and importing the shell
would make the shell a dependency of every tool it hosts.

THE PROBLEM

The shell does not proxy the modules. Each one runs on its own loopback port,
the browser talks to it directly, and that is deliberate -- it is what lets
TractorBeam hold a WebSocket terminal and the USM API Tester hold its own
storage without the shell understanding either. The cost is that the shell
cannot inject a header, because it is not in the request path.

THE LEVER

The shell *starts* every module. So it can hand each one a shared signing key
in its environment at launch, and there is no key distribution problem at all:
the key never touches the disk, never crosses the network, and dies with the
process that issued it.

THE TICKET

When the shell frames a module it appends a one-time ticket to the URL. The
module verifies it, takes the identity from it, sets its own session cookie and
redirects to itself without the ticket. After that the module's own session is
what carries the user, exactly as if they had signed in there directly.

    v1.<base64url payload>.<base64url HMAC-SHA256>

    payload = {"sub": "alfredo", "role": "admin", "name": "Alfredo",
               "aud": "tractorbeam", "iat": 1789…, "exp": 1789…, "jti": "…"}

Four things make the ticket safe to put in a URL:

  aud   bound to one module id, so a ticket for the terminal is not a ticket
        for the credential vault. A module that accepts any audience has
        handed every other module's tickets a way in.
  exp   seconds, not hours. It only has to survive the frame load.
  jti   single use: the shell will not mint the same one twice and a module
        should refuse a repeat.
  HMAC  over the exact bytes that are signed, compared in constant time.

WHAT IT IS NOT

Not OAuth, not OIDC, and not a bearer token for an API. It is a first-hop
assertion between processes that share a parent and a machine. The trust
boundary is still "whoever can reach loopback", and nothing here pretends
otherwise -- what it removes is every *other* process on the box being able to
walk into a module that has no login of its own.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

# Long enough to survive a frame load on a slow machine, short enough that a
# ticket found in a log or a screenshot is already useless.
TICKET_TTL = 30

ENV_KEY = "APEX_SSO_KEY"
ENV_ISSUER = "APEX_SSO_ISSUER"
QUERY_PARAM = "apex_sso"

VERSION = "v1"


def new_key() -> str:
    """A signing key for one run of the shell.

    Per run, not persisted: a suite that is not running should not leave behind
    anything that would let a ticket be minted for it later.
    """
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")


def _key_bytes(key: str) -> bytes:
    padded = key + "=" * (-len(key) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(key: str, user: dict, audience: str, ttl: int = TICKET_TTL) -> str:
    """A ticket letting `user` into the module called `audience`."""
    now = int(time.time())
    payload = {
        "sub": user["username"],
        "name": user.get("display_name") or user["username"],
        "role": user.get("role", "user"),
        "aud": audience,
        "iat": now,
        "exp": now + max(5, int(ttl)),
        "jti": secrets.token_urlsafe(12),
        "iss": "apexbuild",
    }
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signed = f"{VERSION}.{body}"
    mac = hmac.new(_key_bytes(key), signed.encode("ascii"), hashlib.sha256).digest()
    return f"{signed}.{_b64(mac)}"


class Verifier:
    """Module-side check. Holds the seen-ticket set, so it remembers replays.

    Written here rather than left to each module because getting it slightly
    wrong is the whole risk: comparing the MAC with ==, forgetting the audience,
    or trusting the payload before the signature. A module copies this file or
    imports it; either way it is the same code on both sides.
    """

    def __init__(self, key: str, audience: str, leeway: int = 5):
        self.key = key
        self.audience = audience
        self.leeway = leeway
        self._seen = {}
        self._lock = threading.Lock()

    def verify(self, ticket: str) -> dict:
        """The payload, or raise ValueError. Never returns unverified claims."""
        if not self.key:
            raise ValueError("no signing key configured")
        if not ticket or ticket.count(".") != 2:
            raise ValueError("malformed ticket")
        version, body, mac_b64 = ticket.split(".")
        if version != VERSION:
            raise ValueError(f"unsupported ticket version {version!r}")

        # Signature before anything else: the payload is attacker-supplied
        # until the MAC says otherwise, so it is not even parsed until then.
        expected = hmac.new(_key_bytes(self.key), f"{version}.{body}".encode("ascii"),
                            hashlib.sha256).digest()
        try:
            given = _unb64(mac_b64)
        except Exception as e:
            raise ValueError("malformed signature") from e
        if not hmac.compare_digest(expected, given):
            raise ValueError("bad signature")

        try:
            payload = json.loads(_unb64(body))
        except Exception as e:
            raise ValueError("malformed payload") from e

        now = time.time()
        if payload.get("aud") != self.audience:
            # The most important check after the signature. Without it, a
            # ticket for the terminal opens the credential vault.
            raise ValueError(f"ticket is for {payload.get('aud')!r}, not "
                             f"{self.audience!r}")
        if now > payload.get("exp", 0) + self.leeway:
            raise ValueError("ticket has expired")
        if now < payload.get("iat", 0) - self.leeway:
            raise ValueError("ticket is from the future")

        jti = payload.get("jti")
        if not jti:
            raise ValueError("ticket has no id")
        with self._lock:
            self._prune(now)
            if jti in self._seen:
                raise ValueError("ticket has already been used")
            self._seen[jti] = payload["exp"]
        return payload

    def _prune(self, now: float) -> None:
        for jti, exp in list(self._seen.items()):
            if exp < now - 60:
                del self._seen[jti]


def from_environment(audience: str):
    """A Verifier from APEX_SSO_KEY, or None when the app was started alone.

    None is the normal case: an app run on its own has no shell to trust, and
    should fall back to whatever sign-in it had before.
    """
    key = os.environ.get(ENV_KEY, "")
    return Verifier(key, audience) if key else None
