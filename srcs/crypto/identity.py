"""Client Identity and Key Storage Management.

Manages long-term RSA key pairs for clients, saving/loading from disk,
and maintaining a trusted key directory to verify client identity and prevent MitM.
"""

import os
from typing import Optional, Dict
from cryptography.hazmat.primitives.asymmetric import rsa
from srcs.crypto.asymmetric import (
    generate_identity_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem
)


class ClientIdentity:
    """Represents a client's long-term cryptographic identity."""

    def __init__(
        self,
        client_id: str,
        private_key: Optional[rsa.RSAPrivateKey] = None,
        public_key: Optional[rsa.RSAPublicKey] = None
    ):
        self.client_id = client_id
        if private_key is None:
            self.private_key, self.public_key = generate_identity_keypair()
        else:
            self.private_key = private_key
            self.public_key = public_key or self.private_key.public_key()

    @property
    def public_pem(self) -> str:
        return export_public_key_pem(self.public_key)

    @property
    def private_pem(self) -> str:
        return export_private_key_pem(self.private_key)

    def save_to_dir(self, directory: str) -> None:
        """Persist keypair to specified directory."""
        os.makedirs(directory, exist_ok=True)
        priv_path = os.path.join(directory, f"{self.client_id}_private.pem")
        pub_path = os.path.join(directory, f"{self.client_id}_public.pem")
        
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(self.private_pem)
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(self.public_pem)

    @classmethod
    def load_from_dir(cls, directory: str, client_id: str) -> "ClientIdentity":
        """Load keypair from directory if exists, otherwise generate and save."""
        priv_path = os.path.join(directory, f"{client_id}_private.pem")
        pub_path = os.path.join(directory, f"{client_id}_public.pem")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "r", encoding="utf-8") as f:
                priv = load_private_key_pem(f.read())
            with open(pub_path, "r", encoding="utf-8") as f:
                pub = load_public_key_pem(f.read())
            return cls(client_id, private_key=priv, public_key=pub)

        identity = cls(client_id)
        identity.save_to_dir(directory)
        return identity


class TrustedKeyStore:
    """Store of trusted public keys to prevent identity spoofing / MitM."""

    def __init__(self):
        self._keys: Dict[str, rsa.RSAPublicKey] = {}

    def register(self, client_id: str, public_key_pem: str) -> None:
        key = load_public_key_pem(public_key_pem)
        self._keys[client_id] = key

    def get(self, client_id: str) -> Optional[rsa.RSAPublicKey]:
        return self._keys.get(client_id)

    def is_trusted(self, client_id: str, public_key_pem: str) -> bool:
        if client_id not in self._keys:
            # First use / trust on first use, or registration
            return True
        existing = export_public_key_pem(self._keys[client_id]).strip()
        return existing == public_key_pem.strip()

