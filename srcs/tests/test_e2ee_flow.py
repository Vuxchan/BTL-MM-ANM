"""Automated Integration Test for End-to-End Encryption Flow.

Tests:
1. Relay Server startup and client registration.
2. Handshake initiation with MSSV plaintext requirement ("Hello, We are [MSSV_1]...").
3. K_init derivation from SHA256(MSSV_1 || MSSV_2).
4. Ephemeral ECDHE exchange and session key convergence.
5. End-to-end encrypted chat message transfer.
6. End-to-end encrypted file transfer with chunking and SHA-256 integrity check.
"""

import os
import time
import socket
import threading
import unittest
import hashlib
from srcs.server.relay_server import RelayServer
from srcs.client.client_core import ClientCore


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestE2EEFlow(unittest.TestCase):
    server: RelayServer
    server_thread: threading.Thread
    port: int

    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        cls.server = RelayServer(host="127.0.0.1", port=cls.port)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        time.sleep(0.2)

    def test_complete_e2ee_workflow(self):
        mssvs = ["2313955", "2313593", "2311593", "2311681"]

        # 1. Initialize Clients
        alice = ClientCore("Alice", server_host="127.0.0.1", server_port=self.port, identity_dir="keys_test_a", mssv_list=mssvs)
        bob = ClientCore("Bob", server_host="127.0.0.1", server_port=self.port, identity_dir="keys_test_b", mssv_list=mssvs)

        alice_handshake_done = threading.Event()
        bob_handshake_done = threading.Event()
        alice_received_msg_event = threading.Event()
        bob_received_msg_event = threading.Event()
        file_done_event = threading.Event()

        alice_msgs = []
        bob_msgs = []
        received_files = []

        def on_alice_session(peer, info):
            if peer == "Bob":
                alice_handshake_done.set()

        def on_bob_session(peer, info):
            if peer == "Alice":
                bob_handshake_done.set()

        def on_bob_msg(sender, text, raw):
            bob_msgs.append((sender, text))
            bob_received_msg_event.set()

        def on_alice_msg(sender, text, raw):
            alice_msgs.append((sender, text))
            alice_received_msg_event.set()

        def on_bob_file(sender, fname, path):
            received_files.append((fname, path))
            file_done_event.set()

        alice.on_session_ready = on_alice_session
        bob.on_session_ready = on_bob_session
        bob.on_message_received = on_bob_msg
        bob.on_file_completed = on_bob_file
        alice.on_message_received = on_alice_msg

        # Connect clients
        self.assertTrue(alice.connect())
        self.assertTrue(bob.connect())
        time.sleep(0.5)

        # 2. Perform Handshake
        print("\n--- [TEST] Initiating Handshake Alice -> Bob ---")
        alice.initiate_handshake("Bob")
        self.assertTrue(bob_handshake_done.wait(timeout=5.0), "Bob Handshake timed out")
        self.assertTrue(alice_handshake_done.wait(timeout=5.0), "Alice Handshake timed out")

        session_alice = alice.sessions.get("Bob")
        session_bob = bob.sessions.get("Alice")

        self.assertIsNotNone(session_alice)
        self.assertIsNotNone(session_bob)
        self.assertEqual(session_alice.status, "ESTABLISHED")
        self.assertEqual(session_bob.status, "ESTABLISHED")

        # Verify K_init
        expected_k_init = hashlib.sha256(b"2313955231359323115932311681").digest()
        self.assertEqual(session_alice.k_init, expected_k_init)
        self.assertEqual(session_bob.k_init, expected_k_init)

        # Verify Identical Session Key derived via HKDF
        self.assertEqual(session_alice.session_key, session_bob.session_key)
        print(f"[TEST PASS] Session Key Converged: {session_alice.session_key.hex()[:32]}...")

        # 3. Test Chat Messaging (Alice -> Bob and Bob -> Alice)
        print("--- [TEST] Testing AES-256-GCM Chat Messages ---")
        alice.send_chat_message("Bob", "Xin chao Bob! Day la tin nhan ma hoa E2EE tu Alice.")
        self.assertTrue(bob_received_msg_event.wait(timeout=5.0))
        self.assertEqual(bob_msgs[-1][1], "Xin chao Bob! Day la tin nhan ma hoa E2EE tu Alice.")

        bob.send_chat_message("Alice", "Chao Alice! Toi da giai ma tin nhan thanh cong.")
        self.assertTrue(alice_received_msg_event.wait(timeout=5.0))
        self.assertEqual(alice_msgs[-1][1], "Chao Alice! Toi da giai ma tin nhan thanh cong.")
        print("[TEST PASS] Two-way AES-256-GCM Chat verified.")

        # 4. Test File Transfer
        print("--- [TEST] Testing AES-256-GCM Chunked File Transfer ---")
        test_file_path = "test_payload.dat"
        test_content = os.urandom(150000)  # ~150 KB (spans multiple 64KB chunks)
        with open(test_file_path, "wb") as f:
            f.write(test_content)

        alice.send_file("Bob", test_file_path)
        self.assertTrue(file_done_event.wait(timeout=10.0), "File transfer timed out")

        self.assertEqual(len(received_files), 1)
        _, saved_path = received_files[0]
        with open(saved_path, "rb") as f:
            received_bytes = f.read()

        self.assertEqual(received_bytes, test_content)
        self.assertEqual(hashlib.sha256(received_bytes).hexdigest(), hashlib.sha256(test_content).hexdigest())
        print("[TEST PASS] Chunked File Transfer with SHA-256 Integrity verified.")

        # Cleanup
        alice.disconnect()
        bob.disconnect()
        if os.path.exists(test_file_path):
            os.remove(test_file_path)
        if os.path.exists(saved_path):
            os.remove(saved_path)
        import shutil
        shutil.rmtree("keys_test_a", ignore_errors=True)
        shutil.rmtree("keys_test_b", ignore_errors=True)
        shutil.rmtree("received_files", ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
