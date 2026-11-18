"""A tiny SAML identity provider for the tests: a self-signed cert and signed Responses."""

from __future__ import annotations

import base64
import datetime as dt
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

IDP_ENTITY = "https://sts.windows.net/00000000-test-tenant/"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"


def make_cert(cn: str = "Microsoft Azure Federated SSO Certificate"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


def iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z"


def assertion_xml(*, name_id: str, audience: str, recipient: str, in_response_to: str | None,
                  attributes: dict[str, list[str]] | None = None, issuer: str = IDP_ENTITY,
                  lifetime: int = 300, offset: int = 0) -> etree._Element:
    now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)
    aid = "_" + secrets.token_hex(16)
    irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    attrs = "".join(
        f'<Attribute Name="{n}">' + "".join(f"<AttributeValue>{v}</AttributeValue>" for v in vals) + "</Attribute>"
        for n, vals in (attributes or {}).items())
    xml = (
        f'<Assertion xmlns="{SAML}" ID="{aid}" IssueInstant="{iso(now)}" Version="2.0">'
        f"<Issuer>{issuer}</Issuer>"
        f'<Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</NameID>'
        f'<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<SubjectConfirmationData{irt} NotOnOrAfter="{iso(now + dt.timedelta(seconds=lifetime))}" Recipient="{recipient}"/>'
        f"</SubjectConfirmation></Subject>"
        f'<Conditions NotBefore="{iso(now - dt.timedelta(seconds=5))}" NotOnOrAfter="{iso(now + dt.timedelta(seconds=lifetime))}">'
        f"<AudienceRestriction><Audience>{audience}</Audience></AudienceRestriction></Conditions>"
        f"<AttributeStatement>{attrs}</AttributeStatement>"
        f'<AuthnStatement AuthnInstant="{iso(now)}" SessionIndex="{aid}"><AuthnContext>'
        f"<AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>"
        f"</AuthnContext></AuthnStatement></Assertion>")
    return etree.fromstring(xml)


def sign(el: etree._Element, key_pem: bytes, cert_pem: str) -> etree._Element:
    from signxml import XMLSigner
    return XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
        el, key=key_pem, cert=cert_pem, reference_uri=el.get("ID"), id_attribute="ID")


def response(assertion: etree._Element, *, destination: str, in_response_to: str | None,
             status: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
             extra: etree._Element | None = None, sign_response_with=None) -> str:
    rid = "_" + secrets.token_hex(16)
    irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    root = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{SAMLP}" ID="{rid}" Version="2.0" '
        f'IssueInstant="{iso(dt.datetime.now(dt.timezone.utc))}" Destination="{destination}"{irt}>'
        f'<Issuer xmlns="{SAML}">{IDP_ENTITY}</Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status></samlp:Response>')
    root.append(assertion)
    if extra is not None:
        root.append(extra)
    if sign_response_with:
        root = sign(root, *sign_response_with)
    return base64.b64encode(etree.tostring(root)).decode()


def metadata(cert_pem: str, sso_url: str = "https://login.microsoftonline.com/00000000-test-tenant/saml2") -> str:
    body = "".join(cert_pem.strip().splitlines()[1:-1])
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>'
        f"<X509Certificate>{body}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>"
        f'<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>'
        f'<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>'
        "</IDPSSODescriptor></EntityDescriptor>")
