"""SAML 2.0 service provider (Web Browser SSO profile): Microsoft Entra ID, ADFS, Okta, Keycloak, any IdP.

SP-initiated: the console sends an AuthnRequest with the HTTP-Redirect binding
and receives the Response with HTTP-POST at ``/saml/acs``. XML signatures are
checked by ``signxml`` (lxml + cryptography, no xmlsec binary to install), and
everything after the signature check reads **only the element signxml returned
as signed**. Reading the original document after verifying is the classic XML
signature wrapping hole: an attacker adds a second, unsigned assertion next to
a genuinely signed one and the code reads the wrong one.

What is checked, in order (all of it must pass):

1. The XML has no DTD (no entity expansion, no external fetches).
2. There is exactly one Assertion, and it is not encrypted (Entra encrypts
   only when "Token encryption" is switched on for the app; the admin guide says
   to leave it off).
3. The Response or the Assertion carries an enveloped signature that verifies
   against one of the IdP certificates configured from its metadata (more than
   one is accepted, for certificate rollover).
4. The Response status is Success.
5. The Assertion's Issuer is the IdP's entity ID.
6. Conditions: NotBefore / NotOnOrAfter (with clock skew), and our entity ID is
   in the AudienceRestriction.
7. A bearer SubjectConfirmation whose Recipient is our ACS URL, unexpired, and
   whose InResponseTo is an AuthnRequest we sent and have not seen answered
   (each is single use). IdP-initiated responses (no InResponseTo) are refused
   unless the admin turned them on.
8. The Response Destination, when present, is our ACS URL.
9. The Assertion ID has not been used before (replay cache until it expires).
"""

from __future__ import annotations

import base64
import re
import secrets
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
from xml.sax.saxutils import escape, quoteattr

from lxml import etree

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
CLOCK_SKEW = 180.0
MAX_RESPONSE_BYTES = 512 * 1024
REQUEST_TTL = 600.0

# Entra ID claim URIs, as the default "Attributes & Claims" section sends them.
CLAIM_EMAIL = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
CLAIM_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
CLAIM_GIVEN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
CLAIM_SURNAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
CLAIM_DISPLAY = "http://schemas.microsoft.com/identity/claims/displayname"
CLAIM_OID = "http://schemas.microsoft.com/identity/claims/objectidentifier"
CLAIM_GROUPS = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
CLAIM_ROLE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"

# Generic attribute names (ADFS, Okta, Keycloak, Shibboleth, OpenLDAP-backed IdPs), tried after the
# Entra URIs. The first non-empty value wins.
OID_URN_MAIL = "urn:oid:0.9.2342.19200300.100.1.3"
OID_URN_UID = "urn:oid:0.9.2342.19200300.100.1.1"
OID_URN_DISPLAY = "urn:oid:2.16.840.1.113730.3.1.241"
OID_URN_MEMBEROF = "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"
SUBJECT_NAMES = (CLAIM_OID, "objectGUID", "uid", OID_URN_UID)
USERNAME_NAMES = (CLAIM_NAME, "upn", "userPrincipalName", "username", "uid", OID_URN_UID,
                  "sAMAccountName", "preferred_username")
EMAIL_NAMES = (CLAIM_EMAIL, "email", "mail", "emailAddress", OID_URN_MAIL)
DISPLAY_NAMES = (CLAIM_DISPLAY, "displayName", "name", "cn", OID_URN_DISPLAY)
GIVEN_NAMES = (CLAIM_GIVEN, "givenName", "firstName")
SURNAME_NAMES = (CLAIM_SURNAME, "sn", "surname", "lastName")
GROUP_NAMES = (CLAIM_GROUPS, CLAIM_ROLE, "groups", "memberOf", "group", "roles", "role", OID_URN_MEMBEROF)


class SamlError(Exception):
    """A response that must not sign anybody in. The message is safe to log."""


@dataclass
class Identity:
    name_id: str
    attributes: dict[str, list[str]] = field(default_factory=dict)
    session_index: str = ""

    def first(self, *names: str) -> str:
        for n in names:
            vals = self.attributes.get(n) or []
            for v in vals:
                if v.strip():
                    return v.strip()
        return ""

    def values(self, name: str) -> list[str]:
        return [v.strip() for v in self.attributes.get(name, []) if v.strip()]


# ─── XML helpers ─────────────────────────────────────────────────────────────

def safe_parse(data: bytes) -> etree._Element:
    head = data[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
        raise SamlError("XML with a DTD is refused")
    parser = etree.XMLParser(resolve_entities=False, no_network=True,
                             load_dtd=False, huge_tree=False)
    try:
        return etree.fromstring(data, parser)
    except etree.XMLSyntaxError as e:
        raise SamlError(f"malformed XML: {e}") from None


def _text(el: etree._Element | None) -> str:
    """Text content, ignoring comments.

    ``el.text`` stops at the first comment, so ``admin@corp.com<!---->.evil``
    would read as ``admin@corp.com``. The signature covers the text without
    comments (exclusive c14n), so joining the text nodes is what was signed.
    """
    if el is None:
        return ""
    return "".join(el.xpath("text()")).strip()


def _parse_time(s: str) -> float:
    s = (s or "").strip()
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)?", s)
    if not m:
        raise SamlError(f"bad timestamp {s!r}")
    frac = (m.group(2) or "")[:7]
    tz = m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else tz
    dt = datetime.fromisoformat(m.group(1) + (frac[:7] if frac else "") + tz)
    return dt.astimezone(timezone.utc).timestamp()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_cert(pem_or_b64: str) -> str:
    body = re.sub(r"-----(BEGIN|END) CERTIFICATE-----|\s+", "", pem_or_b64 or "")
    if not body:
        return ""
    try:
        base64.b64decode(body, validate=True)
    except ValueError:
        raise SamlError("certificate is not valid base64") from None
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


# ─── IdP metadata ────────────────────────────────────────────────────────────

def parse_metadata(xml: bytes) -> dict:
    root = safe_parse(xml)
    ed = root if root.tag == f"{{{NS['md']}}}EntityDescriptor" else root.find(".//md:EntityDescriptor", NS)
    if ed is None:
        raise SamlError("no EntityDescriptor in the metadata")
    idp = ed.find("md:IDPSSODescriptor", NS)
    if idp is None:
        raise SamlError("the metadata describes no identity provider (IDPSSODescriptor)")
    sso = ""
    for binding in (BINDING_REDIRECT, BINDING_POST):
        for svc in idp.findall("md:SingleSignOnService", NS):
            if svc.get("Binding") == binding:
                sso = svc.get("Location", "")
                break
        if sso:
            break
    slo = ""
    for svc in idp.findall("md:SingleLogoutService", NS):
        if svc.get("Binding") == BINDING_REDIRECT:
            slo = svc.get("Location", "")
    certs: list[str] = []
    for kd in idp.findall("md:KeyDescriptor", NS):
        if kd.get("use") not in (None, "", "signing"):
            continue
        for c in kd.findall(".//ds:X509Certificate", NS):
            pem = normalize_cert(_text(c))
            if pem and pem not in certs:
                certs.append(pem)
    if not sso:
        raise SamlError("the metadata has no SingleSignOnService URL")
    if not certs:
        raise SamlError("the metadata has no signing certificate")
    return {"idp_entity_id": ed.get("entityID", ""), "idp_sso_url": sso,
            "idp_slo_url": slo, "idp_certs": certs}


def fetch_metadata(url: str) -> bytes:
    if not url.lower().startswith("https://"):
        raise SamlError("the metadata URL must be https://")
    req = urllib.request.Request(url, headers={"User-Agent": "TractorBeam-Web-SAML/1"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = r.read(2 * 1024 * 1024 + 1)
    except OSError as e:
        raise SamlError(f"could not fetch metadata: {e}") from None
    if len(data) > 2 * 1024 * 1024:
        raise SamlError("metadata is larger than 2 MB")
    return data


# ─── SP side ─────────────────────────────────────────────────────────────────

def sp_metadata(sp_entity_id: str, acs_url: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<md:EntityDescriptor xmlns:md="{NS["md"]}" entityID={quoteattr(sp_entity_id)}>\n'
        '  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        '    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n'
        f'    <md:AssertionConsumerService Binding="{BINDING_POST}" '
        f'Location={quoteattr(acs_url)} index="0" isDefault="true"/>\n'
        '  </md:SPSSODescriptor>\n'
        '</md:EntityDescriptor>\n'
    )


def build_authn_request(idp_sso_url: str, sp_entity_id: str, acs_url: str,
                        relay_state: str = "", force_authn: bool = False) -> tuple[str, str]:
    """Return (request_id, URL to redirect the browser to)."""
    rid = "_" + secrets.token_hex(20)
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" '
        f'ID="{rid}" Version="2.0" IssueInstant="{_now_iso()}" '
        f'Destination={quoteattr(idp_sso_url)} '
        f'AssertionConsumerServiceURL={quoteattr(acs_url)} '
        f'ProtocolBinding="{BINDING_POST}"'
        + (' ForceAuthn="true"' if force_authn else "") + '>'
        f'<saml:Issuer>{escape(sp_entity_id)}</saml:Issuer>'
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" '
        'AllowCreate="true"/>'
        '</samlp:AuthnRequest>'
    )
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = co.compress(xml.encode("utf-8")) + co.flush()
    params = {"SAMLRequest": base64.b64encode(deflated).decode("ascii")}
    if relay_state:
        params["RelayState"] = relay_state
    sep = "&" if "?" in idp_sso_url else "?"
    return rid, idp_sso_url + sep + urllib.parse.urlencode(params)


def _verify_signature(element: etree._Element, certs: list[str]) -> etree._Element:
    from signxml import XMLVerifier
    from signxml.exceptions import InvalidInput, InvalidSignature
    from signxml.verifier import SignatureConfiguration

    blob = etree.tostring(element)
    last = "no IdP certificate is configured"
    for pem in certs:
        try:
            result = XMLVerifier().verify(
                blob, x509_cert=pem,
                expect_config=SignatureConfiguration(location="./", require_x509=False))
        except (InvalidSignature, InvalidInput) as e:
            last = str(e)
            continue
        except Exception as e:  # signxml raises a few non-InvalidSignature types
            last = f"{type(e).__name__}: {e}"
            continue
        signed = result.signed_xml if not isinstance(result, list) else result[0].signed_xml
        if signed is None:
            continue
        return signed
    raise SamlError(f"signature verification failed: {last}")


def validate_response(
    saml_response_b64: str,
    *,
    idp_entity_id: str,
    idp_certs: list[str],
    sp_entity_id: str,
    acs_url: str,
    consume_request: Callable[[str], bool],
    remember_assertion: Callable[[str, float], bool],
    allow_idp_initiated: bool = False,
    now: float | None = None,
) -> Identity:
    """Check a posted SAMLResponse and return who it is for, or raise SamlError.

    ``consume_request(id)`` returns True exactly once for an AuthnRequest ID we
    issued. ``remember_assertion(id, expires)`` returns False if the assertion
    ID was already used.
    """
    import time as _time
    t = _time.time() if now is None else now

    if not saml_response_b64 or len(saml_response_b64) > MAX_RESPONSE_BYTES * 4 // 3 + 8:
        raise SamlError("missing or oversized SAMLResponse")
    try:
        raw = base64.b64decode(saml_response_b64, validate=False)
    except ValueError:
        raise SamlError("SAMLResponse is not base64") from None
    root = safe_parse(raw)
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise SamlError("not a SAML Response")
    if root.findall(".//saml:EncryptedAssertion", NS):
        raise SamlError("encrypted assertions are not supported; switch off token "
                        "encryption for this app at the identity provider")
    all_assertions = root.findall(".//saml:Assertion", NS)
    if len(all_assertions) != 1:
        raise SamlError(f"expected exactly one Assertion, found {len(all_assertions)}")

    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != STATUS_SUCCESS:
        msg = _text(root.find("samlp:Status/samlp:StatusMessage", NS))
        code = status.get("Value", "?") if status is not None else "?"
        raise SamlError(f"IdP returned status {code.rsplit(':', 1)[-1]}"
                        + (f": {msg}" if msg else ""))

    dest = root.get("Destination")
    if dest and dest != acs_url:
        raise SamlError(f"Response Destination {dest!r} is not this ACS URL {acs_url!r}")

    # Which element is signed: the Response (covering the assertion) or the
    # Assertion itself. Only an enveloped signature that is a DIRECT child is
    # accepted, so a signature smuggled deeper in the tree is never the one used.
    assertion_direct = root.find("saml:Assertion", NS)
    if root.find("ds:Signature", NS) is not None:
        signed = _verify_signature(root, idp_certs)
        if signed.tag != root.tag:
            raise SamlError("signed element is not the Response")
        assertion = signed.find("saml:Assertion", NS)
    elif assertion_direct is not None and assertion_direct.find("ds:Signature", NS) is not None:
        assertion = _verify_signature(assertion_direct, idp_certs)
        if assertion.tag != f"{{{NS['saml']}}}Assertion":
            raise SamlError("signed element is not the Assertion")
    else:
        raise SamlError("neither the Response nor the Assertion is signed")
    if assertion is None:
        raise SamlError("no Assertion inside the signed Response")

    issuer = _text(assertion.find("saml:Issuer", NS))
    if not idp_entity_id or issuer != idp_entity_id:
        raise SamlError(f"Assertion Issuer {issuer!r} is not the configured IdP")

    cond = assertion.find("saml:Conditions", NS)
    if cond is None:
        raise SamlError("Assertion has no Conditions")
    nb, noa = cond.get("NotBefore"), cond.get("NotOnOrAfter")
    if nb and _parse_time(nb) - CLOCK_SKEW > t:
        raise SamlError("Assertion is not yet valid (check the server clock)")
    if not noa or _parse_time(noa) + CLOCK_SKEW <= t:
        raise SamlError("Assertion has expired")
    audiences = [_text(a) for a in cond.findall("saml:AudienceRestriction/saml:Audience", NS)]
    if sp_entity_id not in audiences:
        raise SamlError(f"this app's entity ID {sp_entity_id!r} is not in the Audience "
                        f"{audiences!r}; check the Identifier (Entity ID) at the identity provider")

    subject = assertion.find("saml:Subject", NS)
    if subject is None:
        raise SamlError("Assertion has no Subject")
    name_id = _text(subject.find("saml:NameID", NS))
    if not name_id:
        raise SamlError("Assertion has no NameID")
    ok_conf = False
    in_response_to = ""
    for sc in subject.findall("saml:SubjectConfirmation", NS):
        if sc.get("Method") != BEARER:
            continue
        scd = sc.find("saml:SubjectConfirmationData", NS)
        if scd is None:
            continue
        if scd.get("Recipient") != acs_url:
            continue
        exp = scd.get("NotOnOrAfter")
        if not exp or _parse_time(exp) + CLOCK_SKEW <= t:
            continue
        if scd.get("NotBefore") and _parse_time(scd.get("NotBefore")) - CLOCK_SKEW > t:
            continue
        in_response_to = scd.get("InResponseTo") or ""
        ok_conf = True
        break
    if not ok_conf:
        raise SamlError(f"no valid bearer SubjectConfirmation for Recipient {acs_url!r}; "
                        "check the Reply / ACS URL at the identity provider")

    if in_response_to:
        if not consume_request(in_response_to):
            raise SamlError("InResponseTo does not match a pending sign-in (expired, "
                            "already used, or started in another browser)")
    elif not allow_idp_initiated:
        raise SamlError("IdP-initiated sign-in is disabled; start from the sign-in page")

    aid = assertion.get("ID") or ""
    if not aid or not remember_assertion(aid, _parse_time(noa) + CLOCK_SKEW):
        raise SamlError("this assertion was already used (replay)")

    attrs: dict[str, list[str]] = {}
    for a in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        name = a.get("Name") or ""
        attrs.setdefault(name, []).extend(_text(v) for v in a.findall("saml:AttributeValue", NS))
    authn = assertion.find("saml:AuthnStatement", NS)
    return Identity(name_id=name_id, attributes=attrs,
                    session_index=(authn.get("SessionIndex", "") if authn is not None else ""))


def to_identity(ident: Identity, username_claim: str = "upn"):
    """The shared :class:`app.web.oidc.Identity` for a verified SAML identity.

    ``username_claim``: ``upn`` (the IdP's user principal / login name), ``email`` or ``nameid``.
    The subject is the IdP's stable object id when it sends one, else the NameID.
    """
    from .oidc import Identity as Shared

    upn = ident.first(*USERNAME_NAMES) or ident.name_id
    email = ident.first(*EMAIL_NAMES) or (upn if "@" in upn else "")
    display = ident.first(*DISPLAY_NAMES) or \
        f"{ident.first(*GIVEN_NAMES)} {ident.first(*SURNAME_NAMES)}".strip() or upn
    username = email if username_claim == "email" else ident.name_id if username_claim == "nameid" else upn
    groups: list[str] = []
    for n in GROUP_NAMES:
        for v in ident.values(n):
            if v not in groups:
                groups.append(v)
    return Shared(subject=ident.first(*SUBJECT_NAMES) or ident.name_id,
                  username=(username or ident.name_id).strip().lower(), email=email,
                  display_name=display, groups=groups, source="saml")
