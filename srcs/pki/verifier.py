"""Relying-party verifier: authenticates an HTTPS server against the internal Root CA.

Steps:
  1. Fetch the server certificate over TLS (unverified, only to inspect it).
  2. Obtain intermediates (AIA caIssuers) and build/validate the path to the trusted Root
     with hostname check (RFC 5280 path validation + RFC 6125 via cryptography.x509.verification).
  3. CRL check (RFC 5280 §6.3) for every non-root certificate in the chain, from its CDP URL.
  4. OCSP check (RFC 6960) for the leaf, from its AIA OCSP URL, with nonce.
  5. Real TLS handshake with Python ssl (CERT_REQUIRED + hostname) trusting only the Root.
Verdict: TRUSTED only if every step passes.
"""

import datetime
import ipaddress
import os
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

TIMEOUT = 5.0


@dataclass
class Step:
    name: str
    ok: bool
    detail: str


@dataclass
class VerificationResult:
    url: str
    steps: List[Step] = field(default_factory=list)
    leaf: Optional[x509.Certificate] = None

    @property
    def trusted(self) -> bool:
        return bool(self.steps) and all(s.ok for s in self.steps)

    def add(self, name: str, ok: bool, detail: str) -> bool:
        self.steps.append(Step(name, ok, detail))
        return ok

    def report(self) -> str:
        lines = [f"Verification of {self.url}"]
        if self.leaf is not None:
            lines.append(f"  Subject : {self.leaf.subject.rfc4514_string()}")
            lines.append(f"  Issuer  : {self.leaf.issuer.rfc4514_string()}")
            lines.append(f"  Serial  : {format(self.leaf.serial_number, 'X')}")
        for s in self.steps:
            lines.append(f"  [{'PASS' if s.ok else 'FAIL'}] {s.name}: {s.detail}")
        lines.append(f"  => {'TRUSTED' if self.trusted else 'REJECTED'}")
        return "\n".join(lines)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _http_get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
        return r.read()


def _http_post(url: str, data: bytes, ctype: str) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"Content-Type": ctype}, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def _load_any_cert(data: bytes) -> x509.Certificate:
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _aia_urls(cert: x509.Certificate, method) -> List[str]:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in aia
            if d.access_method == method and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def _cdp_urls(cert: x509.Certificate) -> List[str]:
    try:
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return []
    return [n.value for dp in cdp for n in (dp.full_name or [])
            if isinstance(n, x509.UniformResourceIdentifier)]


def _verify_signed_by(issuer: x509.Certificate, signature: bytes, data: bytes,
                      hash_alg: Optional[hashes.HashAlgorithm]) -> bool:
    try:
        issuer.public_key().verify(signature, data, padding.PKCS1v15(), hash_alg)
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def fetch_server_certificate(host: str, port: int, server_name: Optional[str] = None) -> x509.Certificate:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name or host) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def fetch_intermediates(leaf: x509.Certificate, root: x509.Certificate) -> List[x509.Certificate]:
    """Follow AIA caIssuers until reaching a cert issued by the Root (max depth 4)."""
    chain: List[x509.Certificate] = []
    current = leaf
    for _ in range(4):
        if current.issuer == root.subject:
            break
        urls = _aia_urls(current, AuthorityInformationAccessOID.CA_ISSUERS)
        if not urls:
            break
        try:
            nxt = _load_any_cert(_http_get(urls[0]))
        except Exception:
            break
        if nxt.subject == root.subject:
            break
        chain.append(nxt)
        current = nxt
    return chain


def check_crl(cert: x509.Certificate, issuer: x509.Certificate) -> Tuple[bool, str]:
    urls = _cdp_urls(cert)
    if not urls:
        return False, "no CRL Distribution Point in certificate"
    try:
        data = _http_get(urls[0])
    except Exception as e:
        return False, f"cannot download CRL from {urls[0]} ({e})"
    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        crl = x509.load_pem_x509_crl(data)
    if crl.issuer != issuer.subject:
        return False, "CRL issuer does not match certificate issuer"
    if not crl.is_signature_valid(issuer.public_key()):
        return False, "CRL signature is INVALID"
    now = _now()
    if crl.next_update_utc is None or crl.next_update_utc < now:
        return False, "CRL is stale (nextUpdate passed)"
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        number = "?"
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked is not None:
        try:
            reason = revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason.value
        except x509.ExtensionNotFound:
            reason = "unspecified"
        return False, (f"serial {format(cert.serial_number, 'X')} is REVOKED in CRL #{number} "
                       f"(reason={reason}, date={revoked.revocation_date_utc})")
    return True, f"not listed in CRL #{number} ({len(crl)} revoked entries, signature OK)"


def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate) -> Tuple[bool, str]:
    urls = _aia_urls(cert, AuthorityInformationAccessOID.OCSP)
    if not urls:
        return False, "no OCSP URL in Authority Information Access"
    nonce = os.urandom(16)
    req = (ocsp.OCSPRequestBuilder()
           .add_certificate(cert, issuer, hashes.SHA1())
           .add_extension(x509.OCSPNonce(nonce), critical=False)
           .build())
    try:
        data = _http_post(urls[0], req.public_bytes(serialization.Encoding.DER), "application/ocsp-request")
    except Exception as e:
        return False, f"OCSP responder unreachable at {urls[0]} ({e})"
    resp = ocsp.load_der_ocsp_response(data)
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return False, f"OCSP response status {resp.response_status.name}"

    # Responder must be the issuing CA itself (we do not accept delegated responders).
    if not _verify_signed_by(issuer, resp.signature, resp.tbs_response_bytes, resp.signature_hash_algorithm):
        return False, "OCSP response signature is INVALID (not signed by the issuing CA)"
    try:
        resp_nonce = resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        resp_nonce = None
    if resp_nonce != nonce:
        return False, "OCSP nonce mismatch (possible replay)"
    if resp.serial_number != cert.serial_number:
        return False, "OCSP response is for a different serial number"
    now = _now()
    if resp.next_update_utc is not None and resp.next_update_utc < now:
        return False, "OCSP response is stale"

    if resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return True, "status=GOOD (signature + nonce verified)"
    if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        reason = resp.revocation_reason.value if resp.revocation_reason else "unspecified"
        return False, f"status=REVOKED at {resp.revocation_time_utc} (reason={reason})"
    return False, "status=UNKNOWN (certificate not issued by this CA)"


def tls_handshake(host: str, port: int, root_pem_path: str, server_name: str) -> Tuple[bool, str]:
    ctx = ssl.create_default_context(cafile=root_pem_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
                return True, f"{tls.version()} {tls.cipher()[0]}"
    except ssl.SSLCertVerificationError as e:
        return False, f"certificate verification failed: {e.verify_message}"
    except (ssl.SSLError, OSError) as e:
        return False, f"handshake failed: {e}"


def _subject_for(host: str):
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def verify_url(url: str, root_pem_path: str) -> VerificationResult:
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or "localhost"
    port = parsed.port or 443
    result = VerificationResult(url=url)

    with open(root_pem_path, "rb") as f:
        root = x509.load_pem_x509_certificate(f.read())

    # 1. Fetch server certificate
    try:
        leaf = fetch_server_certificate(host, port)
    except Exception as e:
        result.add("Fetch certificate", False, f"cannot connect: {e}")
        return result
    result.leaf = leaf
    result.add("Fetch certificate", True, f"received leaf CN={_cn(leaf)}")

    # 2. Chain building + path validation + hostname
    intermediates = fetch_intermediates(leaf, root)
    try:
        verifier = (PolicyBuilder().store(Store([root])).time(_now())
                    .build_server_verifier(_subject_for(host)))
        chain = verifier.verify(leaf, intermediates)
        result.add("Chain & hostname", True,
                   " -> ".join(f"CN={_cn(c)}" for c in chain) + f" (hostname '{host}' matches SAN)")
    except VerificationError as e:
        result.add("Chain & hostname", False, f"path validation failed: {e}")
        return result

    # 3. CRL for every non-root element of the chain
    for cert, issuer in zip(chain[:-1], chain[1:]):
        ok, detail = check_crl(cert, issuer)
        result.add(f"CRL ({_cn(cert)})", ok, detail)

    # 4. OCSP for the leaf
    ok, detail = check_ocsp(chain[0], chain[1])
    result.add("OCSP", ok, detail)

    # 5. Real TLS handshake trusting only our Root
    ok, detail = tls_handshake(host, port, root_pem_path, host)
    result.add("TLS handshake", ok, detail)
    return result


def _cn(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else cert.subject.rfc4514_string()
