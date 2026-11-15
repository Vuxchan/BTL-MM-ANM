"""Asymmetric Cryptography Module.

Implements:
1. Ephemeral Diffie-Hellman Key Exchange (ECDHE using X25519 - RFC 7748)
   Provides Perfect Forward Secrecy (PFS).
2. Long-Term Identity & Digital Signatures (RSA-PSS 2048-bit with SHA-256)
   Provides Authentication & Integrity to protect against Man-in-the-Middle (MitM) attacks.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# 1. Ephemeral Key Exchange (ECDHE - X25519)
# ---------------------------------------------------------------------------

def generate_ephemeral_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """Generate a fresh ephemeral X25519 private key and its raw public bytes (32 bytes).

    Returns:
        (private_key_object, raw_public_bytes)
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, raw_public_bytes


def compute_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public_bytes: bytes
) -> bytes:
    """Compute ECDH shared secret using local ephemeral private key and peer's raw public bytes.

    Args:
        private_key: Local X25519 private key object
        peer_public_bytes: 32 bytes received from peer
        
    Returns:
        32-byte Diffie-Hellman shared secret
    """
    if len(peer_public_bytes) != 32:
        raise ValueError(f"Invalid peer X25519 public key length: {len(peer_public_bytes)} (expected 32 bytes)")
    
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)


# ---------------------------------------------------------------------------
# 2. Long-Term Identity & Signatures (RSA-PSS 2048-bit)
# ---------------------------------------------------------------------------

def generate_identity_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate long-term RSA key pair used for client identity and signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()


def export_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    """Export RSA public key to PEM string format."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode("utf-8")


def export_private_key_pem(private_key: rsa.RSAPrivateKey) -> str:
    """Export RSA private key to PEM string format (unencrypted for demo simplicity)."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode("utf-8")


def load_public_key_pem(pem_str: str) -> rsa.RSAPublicKey:
    """Load RSA public key from PEM string format."""
    key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Loaded key is not an RSA public key")
    return key


def load_private_key_pem(pem_str: str) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM string format."""
    key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key")
    return key


def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign data using RSA-PSS padding with SHA-256.

    Args:
        private_key: Signer's RSA private key
        data: Arbitrary bytes to be signed
        
    Returns:
        Digital signature bytes (256 bytes for 2048-bit RSA)
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """Verify digital signature using RSA-PSS with SHA-256.

    Args:
        public_key: Signer's RSA public key
        signature: Signature bytes to verify
        data: Original data bytes that were signed
        
    Returns:
        True if valid, False if verification fails or signature is forged/corrupted
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False

