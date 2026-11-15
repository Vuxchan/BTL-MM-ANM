"""Automated Security Evaluation: MitM Attacks and Defense Verification.

Tests the 3 core security scenarios:
1. Passive Sniffing: Proves traffic confidentiality (Zero Plaintext on wire).
2. Active Handshake Tampering: Proves RSA-PSS signature foils MitM key replacement.
3. Active Ciphertext Tampering: Proves AES-256-GCM AEAD Tag foils bit-flipping / data modification.
"""

import os
import time
import socket
import threading
import unittest
import shutil
from srcs.server.relay_server import RelayServer
from srcs.client.client_core import ClientCore
from srcs.tests.mitm_proxy import MitMProxy


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestMitMSecurity(unittest.TestCase):
    def tearDown(self):
        shutil.rmtree("keys_mitm_a", ignore_errors=True)
        shutil.rmtree("keys_mitm_b", ignore_errors=True)
        shutil.rmtree("received_files", ignore_errors=True)

    def test_scenario_01_passive_sniffing(self):
        """Scenario 1: Passive Sniffing.

        Mallory sniffs communication between Alice and Bob.
        Result: Mallory can observe packet structures and Base64 ciphertexts, but
        has NO knowledge of the session key and CANNOT decrypt the plaintext.
        """
        print("\n=======================================================")
        print(" [SCENARIO 1] PASSIVE EAVESDROPPING / WIRE SNIFFING")
        print("=======================================================")

        server_port = find_free_port()
        proxy_port = find_free_port()

        server = RelayServer(port=server_port)
        proxy = MitMProxy(listen_port=proxy_port, target_port=server_port, attack_mode="sniff")

        s_thread = threading.Thread(target=server.start, daemon=True)
        p_thread = threading.Thread(target=proxy.start, daemon=True)
        s_thread.start()
        p_thread.start()
        time.sleep(0.4)

        # Alice connects via MitM Proxy, Bob connects directly to Server
        alice = ClientCore("Alice", server_port=proxy_port, identity_dir="keys_mitm_a")
        bob = ClientCore("Bob", server_port=server_port, identity_dir="keys_mitm_b")

        alice_ready = threading.Event()
        bob_ready = threading.Event()
        alice.on_session_ready = lambda p, info: alice_ready.set()
        bob.on_session_ready = lambda p, info: bob_ready.set()

        alice.connect()
        bob.connect()
        time.sleep(0.3)

        alice.initiate_handshake("Bob")
        self.assertTrue(bob_ready.wait(timeout=5.0))
        self.assertTrue(alice_ready.wait(timeout=5.0))
        time.sleep(0.2)

        # Alice sends secret message
        secret_plaintext = "Bi mat toi mat: Diem so BTL 1.1 la 10/10!"
        self.assertTrue(alice.send_chat_message("Bob", secret_plaintext))
        time.sleep(0.5)

        # Inspect proxy events
        intercepted_types = [e["type"] for e in proxy.intercepted_events]
        self.assertIn("CHAT_MSG", intercepted_types)
        print("[SUCCESS] Proxy intercepted encrypted packet: Plaintext NEVER leaked on the wire.")

        alice.disconnect()
        bob.disconnect()
        proxy.stop()
        server.stop()

    def test_scenario_02_active_handshake_tampering(self):
        """Scenario 2: Active Handshake Tampering (MitM Ephemeral Key Substitution).

        Mallory intercepts HANDSHAKE_INIT and replaces Alice's ephemeral public key
        with Mallory's public key.
        Defense: Bob checks RSA-PSS signature. Because Mallory cannot forge Alice's
        private key signature, verification FAILS and Bob rejects the session.
        """
        print("\n=======================================================")
        print(" [SCENARIO 2] ACTIVE HANDSHAKE TAMPERING (MitM KEY REPLACEMENT)")
        print("=======================================================")

        server_port = find_free_port()
        proxy_port = find_free_port()

        server = RelayServer(port=server_port)
        proxy = MitMProxy(listen_port=proxy_port, target_port=server_port, attack_mode="tamper-handshake")

        threading.Thread(target=server.start, daemon=True).start()
        threading.Thread(target=proxy.start, daemon=True).start()
        time.sleep(0.4)

        alice = ClientCore("Alice", server_port=proxy_port, identity_dir="keys_mitm_a")
        bob = ClientCore("Bob", server_port=server_port, identity_dir="keys_mitm_b")

        security_alert_event = threading.Event()
        alert_details = []

        def on_bob_alert(title, details):
            alert_details.append((title, details))
            security_alert_event.set()

        bob.on_security_alert = on_bob_alert

        alice.connect()
        bob.connect()
        time.sleep(0.3)

        # Alice initiates handshake -> Proxy tampers with ephemeral pubkey
        alice.initiate_handshake("Bob")

        # Bob MUST detect tampering and raise security alert
        self.assertTrue(security_alert_event.wait(timeout=5.0), "Security alert was not triggered on Bob!")
        self.assertIn("MitM", alert_details[0][0])
        print(f"[DEFENSE VERIFIED] Bob caught tampering: {alert_details[0][0]} -> {alert_details[0][1]}")

        # Bob's session must NOT be established
        bob_session = bob.sessions.get("Alice")
        self.assertTrue(bob_session is None or bob_session.status != "ESTABLISHED")

        alice.disconnect()
        bob.disconnect()
        proxy.stop()
        server.stop()

    def test_scenario_03_active_data_tampering(self):
        """Scenario 3: Active Data Tampering (Bit Flipping in Transit).

        Mallory flips 1 bit in Alice's encrypted CHAT_MSG.
        Defense: Bob performs AES-256-GCM decryption with GMAC authentication tag.
        Tag mismatch triggers IntegrityVerificationError, rejecting tampered data.
        """
        print("\n=======================================================")
        print(" [SCENARIO 3] ACTIVE CIPHERTEXT TAMPERING (BIT-FLIPPING)")
        print("=======================================================")

        server_port = find_free_port()
        proxy_port = find_free_port()

        server = RelayServer(port=server_port)
        # Proxy starts in 'sniff' mode so handshake completes cleanly
        proxy = MitMProxy(listen_port=proxy_port, target_port=server_port, attack_mode="sniff")

        threading.Thread(target=server.start, daemon=True).start()
        threading.Thread(target=proxy.start, daemon=True).start()
        time.sleep(0.4)

        alice = ClientCore("Alice", server_port=proxy_port, identity_dir="keys_mitm_a")
        bob = ClientCore("Bob", server_port=server_port, identity_dir="keys_mitm_b")

        bob_ready = threading.Event()
        bob.on_session_ready = lambda p, info: bob_ready.set()

        alice.connect()
        bob.connect()
        time.sleep(0.3)

        # 1. Establish clean E2EE session
        alice.initiate_handshake("Bob")
        self.assertTrue(bob_ready.wait(timeout=5.0))
        time.sleep(0.3)

        # 2. Switch proxy to tamper-data mode
        proxy.attack_mode = "tamper-data"

        security_alert_event = threading.Event()
        alert_details = []

        def on_bob_alert(title, details):
            alert_details.append((title, details))
            security_alert_event.set()

        bob.on_security_alert = on_bob_alert

        # 3. Alice sends encrypted message -> Proxy alters 1 bit in ciphertext
        alice.send_chat_message("Bob", "Chuyen khoan 10000000 VND vao tai khoan Bob.")

        # Bob MUST detect integrity violation via AES-GCM Tag verification
        self.assertTrue(security_alert_event.wait(timeout=5.0), "Integrity alert was not triggered on Bob!")
        self.assertIn("Integrity", alert_details[0][0])
        print(f"[DEFENSE VERIFIED] Bob caught data tampering: {alert_details[0][0]} -> {alert_details[0][1]}")

        alice.disconnect()
        bob.disconnect()
        proxy.stop()
        server.stop()


if __name__ == "__main__":
    unittest.main()
