"""SSO modules: OIDC ID-token validation, LDAP search-then-bind, SAML responses. No network.

    python -m unittest tests.test_sso
"""

import base64
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.web import ldapauth, oidc  # noqa: E402

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_rsa(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64u(n.e.to_bytes(3, "big"))}


def sign_rs256(key, header, claims):
    h, c = b64u(json.dumps(header).encode()), b64u(json.dumps(claims).encode())
    sig = key.sign(f"{h}.{c}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{c}.{b64u(sig)}"


def sign_es256(key, header, claims):
    h, c = b64u(json.dumps(header).encode()), b64u(json.dumps(claims).encode())
    r, s = decode_dss_signature(key.sign(f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{h}.{c}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "app-client-id"
CFG = {**oidc.DEFAULTS, "enabled": True, "provider": "entra", "tenant_id": "organizations", "client_id": CLIENT}
DISCOVERY = {"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
             "authorization_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
             "token_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
             "jwks_uri": "https://login.microsoftonline.com/organizations/discovery/v2.0/keys"}


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class OidcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.eckey = ec.generate_private_key(ec.SECP256R1())

    def setUp(self):
        oidc.clear_cache()
        self.jwks = {"keys": [jwk_rsa(self.key, "k1")]}
        self.fetches = []

        def fake(url, data=None, timeout=10.0):
            self.fetches.append(url)
            if url.endswith("openid-configuration"):
                return dict(DISCOVERY)
            if url == DISCOVERY["jwks_uri"]:
                return self.jwks
            raise AssertionError(f"unexpected fetch {url}")
        p = mock.patch.object(oidc, "_request", side_effect=fake)
        p.start()
        self.addCleanup(p.stop)

    def claims(self, **kw):
        t = int(time.time())
        c = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "sub": "subj",
             "tid": TENANT, "oid": "oid-1", "iat": t, "nbf": t, "exp": t + 600, "nonce": "n1",
             "preferred_username": "Alice@Corp.Example", "name": "Alice A", "groups": ["g-admins"]}
        c.update(kw)
        return {k: v for k, v in c.items() if v is not None}

    def token(self, key=None, kid="k1", **kw):
        return sign_rs256(key or self.key, {"alg": "RS256", "kid": kid, "typ": "JWT"}, self.claims(**kw))

    def test_valid_entra_token_and_identity(self):
        claims = oidc.validate_id_token(CFG, self.token(), "n1")
        ident = oidc.identity(CFG, claims)
        self.assertEqual(ident.subject, f"{TENANT}:oid-1")
        self.assertEqual(ident.username, "alice@corp.example")
        self.assertEqual(ident.email, "Alice@Corp.Example")
        self.assertEqual(ident.groups, ["g-admins"])
        self.assertEqual(ident.source, "oidc")

    def test_discovery_url(self):
        self.assertEqual(oidc.discovery_url({"provider": "entra", "tenant_id": TENANT}),
                         f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration")
        with self.assertRaises(oidc.OidcError):
            oidc.discovery_url({"provider": "generic", "discovery_url": "http://idp/.well-known/x"})
        with self.assertRaises(oidc.OidcError):
            oidc.discovery_url({"provider": "entra", "tenant_id": "a/b"})

    def test_wrong_nonce(self):
        with self.assertRaisesRegex(oidc.OidcError, "nonce"):
            oidc.validate_id_token(CFG, self.token(), "other")

    def test_wrong_audience(self):
        with self.assertRaisesRegex(oidc.OidcError, "audience"):
            oidc.validate_id_token(CFG, self.token(aud="someone-else"), "n1")

    def test_wrong_issuer(self):
        with self.assertRaisesRegex(oidc.OidcError, "issuer"):
            oidc.validate_id_token(CFG, self.token(iss="https://evil.example/v2.0"), "n1")

    def test_issuer_must_match_tid(self):
        tok = self.token(tid="99999999-0000-0000-0000-000000000000")
        with self.assertRaisesRegex(oidc.OidcError, "issuer"):
            oidc.validate_id_token(CFG, tok, "n1")

    def test_expired(self):
        with self.assertRaisesRegex(oidc.OidcError, "expired"):
            oidc.validate_id_token(CFG, self.token(exp=int(time.time()) - 120), "n1")

    def test_not_yet_valid(self):
        with self.assertRaisesRegex(oidc.OidcError, "not valid yet"):
            oidc.validate_id_token(CFG, self.token(nbf=int(time.time()) + 600), "n1")

    def test_bad_signature(self):
        with self.assertRaisesRegex(oidc.OidcError, "signature"):
            oidc.validate_id_token(CFG, self.token(key=self.other), "n1")

    def test_tampered_payload(self):
        h, c, s = self.token().split(".")
        evil = json.loads(base64.urlsafe_b64decode(c + "=="))
        evil["preferred_username"] = "admin@corp.example"
        with self.assertRaisesRegex(oidc.OidcError, "signature"):
            oidc.validate_id_token(CFG, f"{h}.{b64u(json.dumps(evil).encode())}.{s}", "n1")

    def test_alg_none_and_hs256_refused(self):
        for alg in ("none", "HS256"):
            h = b64u(json.dumps({"alg": alg, "kid": "k1"}).encode())
            c = b64u(json.dumps(self.claims()).encode())
            with self.assertRaisesRegex(oidc.OidcError, "algorithm"):
                oidc.validate_id_token(CFG, f"{h}.{c}.", "n1")

    def test_unknown_kid_refetches_once(self):
        tok = self.token(kid="k2", key=self.other)
        with self.assertRaisesRegex(oidc.OidcError, "does not publish"):
            oidc.validate_id_token(CFG, tok, "n1")
        oidc.clear_cache()
        self.fetches.clear()
        self.jwks = {"keys": [jwk_rsa(self.key, "k1")]}
        oidc.validate_id_token(CFG, self.token(), "n1")      # warm cache with k1 only
        self.jwks = {"keys": [jwk_rsa(self.key, "k1"), jwk_rsa(self.other, "k2")]}
        with mock.patch.object(oidc, "JWKS_MIN_REFRESH", 0):
            oidc.validate_id_token(CFG, tok, "n1")           # rollover: k2 found after refetch
        self.assertEqual(self.fetches.count(DISCOVERY["jwks_uri"]), 2)

    def test_es256(self):
        n = self.eckey.public_key().public_numbers()
        self.jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "e1", "use": "sig",
                               "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}]}
        tok = sign_es256(self.eckey, {"alg": "ES256", "kid": "e1"}, self.claims())
        self.assertEqual(oidc.validate_id_token(CFG, tok, "n1")["sub"], "subj")

    def test_generic_provider_fixed_issuer(self):
        cfg = {**CFG, "provider": "generic", "discovery_url": "https://idp.example/.well-known/openid-configuration"}
        global DISCOVERY
        saved = DISCOVERY
        DISCOVERY = {**saved, "issuer": "https://idp.example"}
        try:
            tok = self.token(iss="https://idp.example", tid=None, oid=None)
            ident = oidc.identity(cfg, oidc.validate_id_token(cfg, tok, "n1"))
            self.assertEqual(ident.subject, "subj")
        finally:
            DISCOVERY = saved

    def test_auth_url_has_pkce_and_state(self):
        verifier, challenge = oidc.new_pkce()
        self.assertGreaterEqual(len(verifier), 43)
        url = oidc.auth_url(CFG, "https://app.example/auth/oidc/callback", "st", "nn", challenge)
        self.assertIn("code_challenge_method=S256", url)
        self.assertIn("state=st", url)
        self.assertIn("nonce=nn", url)
        self.assertIn("scope=openid+profile+email", url)

    def test_multiple_audiences_require_azp(self):
        with self.assertRaisesRegex(oidc.OidcError, "azp"):
            oidc.validate_id_token(CFG, self.token(aud=[CLIENT, "other"], azp="other"), "n1")


class FakeConn:
    """Stands in for an ldap3 Connection after _connect()."""

    def __init__(self, response=None):
        self.response = response or []
        self.searches = []
        self.server = mock.Mock(host="dc1.example.com")

    def search(self, base, flt, **kw):
        self.searches.append((base, flt))

    def unbind(self):
        pass


LCFG = {**ldapauth.DEFAULTS, "enabled": True, "server_url": "ldaps://dc1.example.com ldaps://dc2.example.com",
        "base_dn": "DC=corp,DC=example", "bind_dn": "CN=svc,DC=corp,DC=example"}
ENTRY = {"type": "searchResEntry", "dn": "CN=Alice,OU=Users,DC=corp,DC=example",
         "attributes": {"sAMAccountName": "alice", "mail": "alice@corp.example", "displayName": "Alice A",
                        "memberOf": ["CN=Terminal Admins,OU=Groups,DC=corp,DC=example",
                                     "CN=Staff,OU=Groups,DC=corp,DC=example"],
                        "objectGUID": "{guid-1}"}}


class LdapTests(unittest.TestCase):
    def test_escape(self):
        self.assertEqual(ldapauth.escape("a*b(c)d\\e\x00"), "a\\2ab\\28c\\29d\\5ce\\00")
        f = ldapauth.build_filter("(uid={username})", "*)(uid=*")
        self.assertEqual(f, "(uid=\\2a\\29\\28uid=\\2a)")
        with self.assertRaises(ldapauth.LdapError):
            ldapauth.build_filter("(uid=x)", "alice")

    def test_group_matching(self):
        groups = ENTRY["attributes"]["memberOf"]
        self.assertTrue(ldapauth.group_matches(groups, ["cn=terminal admins,ou=groups,dc=corp,dc=example"]))
        self.assertTrue(ldapauth.group_matches(groups, ["Terminal Admins"]))
        self.assertTrue(ldapauth.group_matches(groups, ["CN=Staff, OU=Groups, DC=corp, DC=example"]))
        self.assertFalse(ldapauth.group_matches(groups, ["Domain Admins"]))
        self.assertFalse(ldapauth.group_matches(groups, []))
        self.assertTrue(ldapauth.group_matches(["CN=A\\,B,DC=x"], ["A\\,B"]))

    def test_servers(self):
        self.assertEqual(ldapauth.servers_of(LCFG), ["ldaps://dc1.example.com", "ldaps://dc2.example.com"])
        with self.assertRaises(ldapauth.LdapError):
            ldapauth.servers_of({"server_url": "http://dc"})

    def _patched(self, user_bind_ok=True, entries=(ENTRY,)):
        calls = []

        def fake_connect(cfg, user, password, ca, as_user=False):
            calls.append((user, as_user))
            if as_user:
                if not user_bind_ok:
                    raise ldapauth.LdapError("invalid_credentials", "wrong username or password")
                return FakeConn()
            return FakeConn(list(entries))
        return mock.patch.object(ldapauth, "_connect", side_effect=fake_connect), calls

    def test_authenticate(self):
        p, calls = self._patched()
        with p:
            ident = ldapauth.authenticate(LCFG, "svcpw", "Alice", "pw")
        self.assertEqual((ident.username, ident.email, ident.subject, ident.source),
                         ("alice", "alice@corp.example", "{guid-1}", "ldap"))
        self.assertEqual(calls, [("CN=svc,DC=corp,DC=example", False), (ENTRY["dn"], True)])

    def test_wrong_password(self):
        p, _ = self._patched(user_bind_ok=False)
        with p, self.assertRaises(ldapauth.LdapError) as cm:
            ldapauth.authenticate(LCFG, "svcpw", "alice", "bad")
        self.assertEqual(cm.exception.code, "invalid_credentials")

    def test_empty_password_never_binds(self):
        p, calls = self._patched()
        with p, self.assertRaises(ldapauth.LdapError):
            ldapauth.authenticate(LCFG, "svcpw", "alice", "")
        self.assertEqual(calls, [])

    def test_unknown_user(self):
        p, _ = self._patched(entries=())
        with p, self.assertRaises(ldapauth.LdapError) as cm:
            ldapauth.authenticate(LCFG, "svcpw", "nobody", "pw")
        self.assertEqual(cm.exception.code, "not_found")

    def test_allowed_groups(self):
        p, _ = self._patched()
        with p, self.assertRaises(ldapauth.LdapError) as cm:
            ldapauth.authenticate({**LCFG, "allowed_groups": ["Terminal Users"]}, "svcpw", "alice", "pw")
        self.assertEqual(cm.exception.code, "not_allowed")
        p, _ = self._patched()
        with p:
            ldapauth.authenticate({**LCFG, "allowed_groups": ["Staff"]}, "svcpw", "alice", "pw")

    def test_filter_is_escaped_in_search(self):
        conn = FakeConn([ENTRY])
        ldapauth._find(conn, LCFG, "al*ce")
        self.assertIn("al\\2ace", conn.searches[0][1])


try:
    import lxml  # noqa: F401
    import signxml  # noqa: F401
    HAVE_SAML = HAVE_CRYPTO
except ImportError:  # pragma: no cover
    HAVE_SAML = False


@unittest.skipUnless(HAVE_SAML, "lxml / signxml not installed")
class SamlTests(unittest.TestCase):
    SP = "https://term.example/saml/metadata"
    ACS = "https://term.example/saml/acs"

    @classmethod
    def setUpClass(cls):
        from tests import samlidp
        cls.idp = samlidp
        cls.keys = samlidp.make_cert()

    def setUp(self):
        self.pending, self.seen = {"_req1"}, set()

    def consume(self, rid):
        if rid in self.pending:
            self.pending.discard(rid)
            return True
        return False

    def remember(self, aid, _exp):
        if aid in self.seen:
            return False
        self.seen.add(aid)
        return True

    def validate(self, b64, cert=None, **kw):
        from app.web import saml
        return saml.validate_response(
            b64, idp_entity_id=self.idp.IDP_ENTITY, idp_certs=[saml.normalize_cert(cert or self.keys[1])],
            sp_entity_id=self.SP, acs_url=self.ACS, consume_request=self.consume,
            remember_assertion=self.remember, **kw)

    def signed(self, attributes=None, **kw):
        a = self.idp.assertion_xml(name_id="alice@corp.example", audience=self.SP, recipient=self.ACS,
                                   in_response_to="_req1", attributes=attributes, **kw)
        return self.idp.sign(a, *self.keys)

    def test_valid_generic_attributes(self):
        from app.web import saml
        a = self.signed({"mail": ["alice@corp.example"], "displayName": ["Alice A"],
                         "memberOf": ["cn=ops,dc=corp"], "uid": ["alice"]})
        ident = self.validate(self.idp.response(a, destination=self.ACS, in_response_to="_req1"))
        shared = saml.to_identity(ident, "upn")
        self.assertEqual((shared.username, shared.email, shared.display_name, shared.groups, shared.source),
                         ("alice", "alice@corp.example", "Alice A", ["cn=ops,dc=corp"], "saml"))
        self.assertEqual(saml.to_identity(ident, "email").username, "alice@corp.example")

    def test_entra_claims(self):
        from app.web import saml
        a = self.signed({saml.CLAIM_NAME: ["Alice@Corp.Example"], saml.CLAIM_OID: ["oid-7"],
                         saml.CLAIM_GROUPS: ["g1", "g2"]})
        shared = saml.to_identity(self.validate(self.idp.response(a, destination=self.ACS,
                                                                  in_response_to="_req1")))
        self.assertEqual((shared.subject, shared.username, shared.groups), ("oid-7", "alice@corp.example",
                                                                            ["g1", "g2"]))

    def test_tampered_and_replay(self):
        from app.web import saml
        a = self.signed()
        a.find(".//{%s}NameID" % self.idp.SAML).text = "mallory@corp.example"
        with self.assertRaisesRegex(saml.SamlError, "signature"):
            self.validate(self.idp.response(a, destination=self.ACS, in_response_to="_req1"))
        b64 = self.idp.response(self.signed(), destination=self.ACS, in_response_to="_req1")
        self.validate(b64)
        with self.assertRaises(saml.SamlError):
            self.validate(b64)                           # request consumed and assertion seen

    def test_wrapping_attack(self):
        from app.web import saml
        evil = self.idp.assertion_xml(name_id="admin@corp.example", audience=self.SP, recipient=self.ACS,
                                      in_response_to="_req1")
        b64 = self.idp.response(self.signed(), destination=self.ACS, in_response_to="_req1", extra=evil)
        with self.assertRaisesRegex(saml.SamlError, "exactly one Assertion"):
            self.validate(b64)

    def test_wrong_audience(self):
        from app.web import saml
        a = self.idp.sign(self.idp.assertion_xml(name_id="a@b.c", audience="https://other/sp", recipient=self.ACS,
                                                 in_response_to="_req1"), *self.keys)
        with self.assertRaisesRegex(saml.SamlError, "udience"):
            self.validate(self.idp.response(a, destination=self.ACS, in_response_to="_req1"))

    def test_metadata_roundtrip(self):
        from app.web import saml
        parsed = saml.parse_metadata(self.idp.metadata(self.keys[1]).encode())
        self.assertEqual(parsed["idp_entity_id"], self.idp.IDP_ENTITY)
        self.assertTrue(parsed["idp_certs"])
        self.assertIn("AssertionConsumerService", saml.sp_metadata(self.SP, self.ACS))


if __name__ == "__main__":
    unittest.main()
