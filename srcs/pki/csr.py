"""Web Server side: generate a private key and a PKCS#10 Certificate Signing Request (RFC 2986)."""

import os
from typing import Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from srcs.pki.ca import parse_san
from srcs.pki.config import LEAF_KEY_SIZE, COUNTRY, ORGANIZATION


def generate_key(key_size: int = LEAF_KEY_SIZE) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def build_csr(
    key: rsa.RSAPrivateKey,
    common_name: str,
    san: Optional[Sequence[str]] = None,
) -> x509.CertificateSigningRequest:
    """Build a CSR signed with `key` (proof of possession of the private key)."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    names = parse_san(san or [f"DNS:{common_name}"])
    builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(key, hashes.SHA256())


def save_key(path: str, key: rsa.RSAPrivateKey) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def create_key_and_csr(
    out_dir: str, common_name: str, san: Optional[Sequence[str]] = None
) -> Tuple[rsa.RSAPrivateKey, x509.CertificateSigningRequest]:
    """Generate `<out_dir>/server.key` and `<out_dir>/server.csr`."""
    key = generate_key()
    csr = build_csr(key, common_name, san)
    save_key(os.path.join(out_dir, "server.key"), key)
    with open(os.path.join(out_dir, "server.csr"), "wb") as f:
        f.write(csr_to_pem(csr))
    return key, csr
