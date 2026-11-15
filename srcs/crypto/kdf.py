"""KDF (Key Derivation Function) Module for E2EE System.

Implements:
1. K_init derivation from team members' Student IDs (MSSV):
   K_init = SHA256(MSSV_1 || MSSV_2 || ...)
2. Session Key derivation using HKDF (RFC 5869) with SHA-256:
   K_session = HKDF(salt=K_init, IKM=ECDH_Shared_Secret, info="E2EE-Session-Key-v1", length=32)
"""

import hashlib
from typing import List, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def compute_k_init(mssv_list: List[Union[str, int]]) -> bytes:
    """Derive initialization key K_init by hashing concatenated MSSVs.

    Formula: K_init = SHA256(MSSV_1 || MSSV_2 || ...)
    
    Args:
        mssv_list: List of Student IDs (e.g. ["2313955", "2313593", "2311593", "2311681"])
        
    Returns:
        32-byte digest of SHA256.
    """
    if not mssv_list:
        raise ValueError("MSSV list cannot be empty.")
    
    # Concatenate MSSV strings directly (UTF-8 encoded)
    concatenated = "".join(str(item).strip() for item in mssv_list).encode("utf-8")
    return hashlib.sha256(concatenated).digest()


def derive_session_key(
    shared_secret: bytes,
    k_init: bytes,
    info: bytes = b"E2EE-Session-Key-v1",
    key_length: int = 32
) -> bytes:
    """Derive symmetric session key from ECDH shared secret and K_init via HKDF-SHA256.

    Args:
        shared_secret: 32-byte Diffie-Hellman / ECDHE shared secret (IKM)
        k_init: Salt value computed from SHA256(MSSV_1 || MSSV_2 ...)
        info: Context and application specific information
        key_length: Output key length in bytes (32 bytes = 256 bits for AES-256)
        
    Returns:
        Derived session key bytes (32 bytes for AES-256).
    """
    if len(shared_secret) == 0:
        raise ValueError("Shared secret cannot be empty.")
    if len(k_init) == 0:
        raise ValueError("k_init cannot be empty.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=k_init,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

