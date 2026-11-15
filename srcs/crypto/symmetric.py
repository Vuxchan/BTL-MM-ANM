"""Symmetric Cryptography Module.

Implements AES-256-GCM (Galois/Counter Mode):
- Authenticated Encryption with Associated Data (AEAD)
- 256-bit key length
- 96-bit (12-byte) unique Nonce/IV per encryption
- 128-bit (16-byte) Authentication Tag (MAC)
Provides both Confidentiality and Authenticity/Integrity.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class SymmetricCryptoError(Exception):
    """Raised when encryption or decryption fails."""
    pass


class IntegrityVerificationError(SymmetricCryptoError):
    """Raised when authentication tag verification fails (tampering detected)."""
    pass


def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b""
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        key: 32-byte (256-bit) AES key
        plaintext: Raw data bytes to encrypt
        associated_data: Optional authenticated metadata (AAD)
        
    Returns:
        (ciphertext, nonce, tag)
        where:
            ciphertext: encrypted data (same length as plaintext)
            nonce: 12-byte initialization vector
            tag: 16-byte authentication tag
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes (got {len(key)})")

    # Generate 96-bit (12-byte) cryptographically secure random nonce
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    # cryptography's AESGCM.encrypt returns ciphertext + 16-byte tag
    combined = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = combined[:-16]
    tag = combined[-16:]

    return ciphertext, nonce, tag


def decrypt_aes_gcm(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: bytes = b""
) -> bytes:
    """Decrypt ciphertext and verify authenticity tag using AES-256-GCM.

    Args:
        key: 32-byte (256-bit) AES key
        ciphertext: Encrypted data
        nonce: 12-byte initialization vector
        tag: 16-byte authentication tag
        associated_data: Optional authenticated metadata (must match encryption AAD)
        
    Returns:
        Decrypted plaintext bytes
        
    Raises:
        IntegrityVerificationError: If tag does not match (data corrupted or tampered)
        ValueError: If key or nonce length is invalid
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes (got {len(key)})")
    if len(nonce) != 12:
        raise ValueError(f"AES-GCM nonce must be exactly 12 bytes (got {len(nonce)})")
    if len(tag) != 16:
        raise ValueError(f"AES-GCM tag must be exactly 16 bytes (got {len(tag)})")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
        return plaintext
    except InvalidTag as e:
        raise IntegrityVerificationError(
            "Integrity check failed: AES-GCM Authentication Tag mismatch! "
            "Data has been tampered with or corrupted in transit."
        ) from e
    except Exception as e:
        raise SymmetricCryptoError(f"Decryption failed: {str(e)}") from e

