"""OCSP Responder (RFC 6960).

The Issuing CA signs the responses directly (CA-designated responder = the issuer itself),
so relying parties can verify them with the Issuing CA certificate from the chain.
"""

import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from srcs.pki.ca import CertificateAuthority, ISSUING, ROOT, parse_reason, utcnow
from srcs.pki.config import OCSP_VALIDITY_HOURS


def _issuer_hashes(cert: x509.Certificate, algorithm: hashes.HashAlgorithm):
    name_hash = hashes.Hash(algorithm)
    name_hash.update(cert.subject.public_bytes())
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    # Key hash = hash of the BIT STRING value of subjectPublicKey (RFC 6960 §4.1.1)
    key_bits = _subject_public_key_bits(spki)
    key_hash = hashes.Hash(algorithm)
    key_hash.update(key_bits)
    return name_hash.finalize(), key_hash.finalize()


def _read_der_length(data: bytes, pos: int):
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    return int.from_bytes(data[pos:pos + n], "big"), pos + n


def _subject_public_key_bits(spki: bytes) -> bytes:
    """Extract the subjectPublicKey BIT STRING contents (without unused-bits byte) from SPKI DER."""
    # SEQUENCE { AlgorithmIdentifier SEQUENCE, BIT STRING }
    assert spki[0] == 0x30
    _, pos = _read_der_length(spki, 1)
    assert spki[pos] == 0x30
    alg_len, alg_start = _read_der_length(spki, pos + 1)
    pos = alg_start + alg_len
    assert spki[pos] == 0x03
    bits_len, bits_start = _read_der_length(spki, pos + 1)
    return spki[bits_start + 1: bits_start + bits_len]


class OCSPResponder:
    def __init__(self, ca: CertificateAuthority):
        self.ca = ca

    def _match_issuer(self, req: ocsp.OCSPRequest) -> Optional[str]:
        for which, cert in ((ISSUING, self.ca.issuing_cert), (ROOT, self.ca.root_cert)):
            name_hash, key_hash = _issuer_hashes(cert, req.hash_algorithm)
            if name_hash == req.issuer_name_hash and key_hash == req.issuer_key_hash:
                return which
        return None

    def respond(self, request_der: bytes) -> bytes:
        """Return a DER-encoded OCSPResponse for a DER-encoded OCSPRequest."""
        try:
            req = ocsp.load_der_ocsp_request(request_der)
        except Exception:
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(serialization.Encoding.DER)

        which = self._match_issuer(req)
        if which is None:
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(serialization.Encoding.DER)

        if which == ISSUING:
            signer_cert, signer_key = self.ca.issuing_cert, self.ca.issuing_key
        else:
            signer_cert, signer_key = self.ca.root_cert, self.ca.root_key

        status_text, entry = self.ca.get_status(req.serial_number, issuer=which)
        now = utcnow()
        revocation_time = None
        revocation_reason = None
        if status_text == "good":
            status = ocsp.OCSPCertStatus.GOOD
        elif status_text == "revoked":
            status = ocsp.OCSPCertStatus.REVOKED
            revocation_time = datetime.datetime.fromisoformat(entry["revoked_at"])
            revocation_reason = parse_reason(entry["reason"])
        else:
            status = ocsp.OCSPCertStatus.UNKNOWN

        builder = (
            ocsp.OCSPResponseBuilder()
            .add_response_by_hash(
                issuer_name_hash=req.issuer_name_hash,
                issuer_key_hash=req.issuer_key_hash,
                serial_number=req.serial_number,
                algorithm=req.hash_algorithm,
                cert_status=status,
                this_update=now,
                next_update=now + datetime.timedelta(hours=OCSP_VALIDITY_HOURS),
                revocation_time=revocation_time,
                revocation_reason=revocation_reason,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, signer_cert)
            .certificates([signer_cert])
        )
        try:
            nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value
            builder = builder.add_extension(nonce, critical=False)
        except x509.ExtensionNotFound:
            pass
        resp = builder.sign(signer_key, hashes.SHA256())
        return resp.public_bytes(serialization.Encoding.DER)
