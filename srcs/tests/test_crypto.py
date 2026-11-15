"""Unit tests for Cryptographic Engine (KDF, ECDHE, RSA-PSS, AES-256-GCM)."""

import hashlib
import unittest
from srcs.crypto.kdf import compute_k_init, derive_session_key
from srcs.crypto.asymmetric import (
    generate_ephemeral_keypair,
    compute_shared_secret,
    generate_identity_keypair,
    export_public_key_pem,
    load_public_key_pem,
    sign_data,
    verify_signature
)
from srcs.crypto.symmetric import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    IntegrityVerificationError
)


class TestCryptoModule(unittest.TestCase):
    """Test suite for cryptographic primitives and requirements."""

    def test_01_k_init_derivation(self):
        """Test K_init derivation from MSSV list as required by assignment:

        K_init = SHA256(MSSV_1 || MSSV_2 ..)
        """
        mssv_list = ["2313955", "2313593", "2311593", "2311681"]
        k_init = compute_k_init(mssv_list)
        
        # Verify manual computation
        expected_raw = b"2313955231359323115932311681"
        expected_hash = hashlib.sha256(expected_raw).digest()
        self.assertEqual(k_init, expected_hash)
        self.assertEqual(len(k_init), 32)
        print(f"[PASS] K_init test: SHA256(MSSV) = {k_init.hex()}")

    def test_02_ecdhe_key_exchange(self):
        """Test Ephemeral Diffie-Hellman Key Exchange (X25519) for Perfect Forward Secrecy."""
        # Alice generates ephemeral keypair
        alice_priv, alice_pub_bytes = generate_ephemeral_keypair()
        # Bob generates ephemeral keypair
        bob_priv, bob_pub_bytes = generate_ephemeral_keypair()

        self.assertEqual(len(alice_pub_bytes), 32)
        self.assertEqual(len(bob_pub_bytes), 32)

        # Alice computes shared secret
        secret_alice = compute_shared_secret(alice_priv, bob_pub_bytes)
        # Bob computes shared secret
        secret_bob = compute_shared_secret(bob_priv, alice_pub_bytes)

        # Shared secrets must match
        self.assertEqual(secret_alice, secret_bob)
        self.assertEqual(len(secret_alice), 32)
        print(f"[PASS] ECDHE Shared Secret Match: {secret_alice.hex()[:16]}...")

    def test_03_hkdf_session_key_derivation(self):
        """Test HKDF derivation combining ECDH shared secret and K_init."""
        mssv_list = ["2313955", "2313593", "2311593", "2311681"]
        k_init = compute_k_init(mssv_list)

        alice_priv, alice_pub_bytes = generate_ephemeral_keypair()
        bob_priv, bob_pub_bytes = generate_ephemeral_keypair()
        shared_secret = compute_shared_secret(alice_priv, bob_pub_bytes)

        session_key_alice = derive_session_key(shared_secret, k_init)
        session_key_bob = derive_session_key(shared_secret, k_init)

        self.assertEqual(session_key_alice, session_key_bob)
        self.assertEqual(len(session_key_alice), 32)
        print(f"[PASS] HKDF Session Key: {session_key_alice.hex()[:16]}...")

    def test_04_rsa_signature_anti_mitm(self):
        """Test RSA-PSS digital signatures for authenticity and anti-tamper."""
        alice_priv, alice_pub = generate_identity_keypair(2048)
        bob_priv, bob_pub = generate_identity_keypair(2048)

        # Test export/load PEM
        pub_pem = export_public_key_pem(alice_pub)
        loaded_pub = load_public_key_pem(pub_pem)

        # Alice signs handshake message
        handshake_payload = b"Hello, We are [2313955], [2313593], [2311593], [2311681] || EphemeralPubKeyA"
        signature = sign_data(alice_priv, handshake_payload)
        self.assertEqual(len(signature), 256)

        # Bob verifies Alice's signature with Alice's public key
        is_valid = verify_signature(loaded_pub, signature, handshake_payload)
        self.assertTrue(is_valid)

        # Bob verifies with Bob's public key (impersonation attempt) -> must fail
        self.assertFalse(verify_signature(bob_pub, signature, handshake_payload))

        # Tampered message -> verification must fail
        tampered_payload = b"Hello, We are [MALLORY] || EphemeralPubKeyMallory"
        self.assertFalse(verify_signature(loaded_pub, signature, tampered_payload))
        print("[PASS] RSA-PSS Signature and Anti-MitM verification passed.")

    def test_05_aes_256_gcm_encryption_and_integrity(self):
        """Test AES-256-GCM authenticated encryption, decryption, and tamper detection."""
        key = hashlib.sha256(b"test-secret-key-32-bytes-long!").digest()
        original_plaintext = b"Mat Ma va An Ninh Mang - Assignment 1.1: E2EE Chat & File Transfer"
        aad = b"header-aad-sender-alice"

        ciphertext, nonce, tag = encrypt_aes_gcm(key, original_plaintext, associated_data=aad)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(tag), 16)
        self.assertEqual(len(ciphertext), len(original_plaintext))

        # Decrypt successfully
        decrypted = decrypt_aes_gcm(key, ciphertext, nonce, tag, associated_data=aad)
        self.assertEqual(decrypted, original_plaintext)

        # Tamper 1 byte in ciphertext -> must raise IntegrityVerificationError
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0x01
        with self.assertRaises(IntegrityVerificationError):
            decrypt_aes_gcm(key, bytes(tampered_ciphertext), nonce, tag, associated_data=aad)

        # Tamper 1 byte in tag -> must raise IntegrityVerificationError
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0x01
        with self.assertRaises(IntegrityVerificationError):
            decrypt_aes_gcm(key, ciphertext, nonce, bytes(tampered_tag), associated_data=aad)

        # Tamper Associated Data -> must raise IntegrityVerificationError
        with self.assertRaises(IntegrityVerificationError):
            decrypt_aes_gcm(key, ciphertext, nonce, tag, associated_data=b"header-tampered")

        print("[PASS] AES-256-GCM AEAD encryption, decryption and tamper detection verified.")


if __name__ == "__main__":
    unittest.main()

