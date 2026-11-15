"""Client Core: Manages TCP connection, E2EE sessions, Handshake, Encrypted Chat & File Transfer."""

import os
import json
import socket
import threading
import hashlib
import time
from typing import Dict, List, Optional, Callable, Any
from srcs.protocol.packet import (
    Packet, MsgType, send_packet, recv_packet, b64_encode, b64_decode
)
from srcs.protocol.handshake import (
    create_handshake_init,
    create_handshake_resp,
    verify_handshake_packet,
    canonical_json_bytes
)
from srcs.crypto.kdf import compute_k_init, derive_session_key
from srcs.crypto.asymmetric import (
    generate_ephemeral_keypair,
    compute_shared_secret
)
from srcs.crypto.symmetric import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    IntegrityVerificationError
)
from srcs.crypto.identity import ClientIdentity


class E2EESession:
    """Maintains state of an active E2EE session with a specific peer."""
    def __init__(self, peer_id: str):
        self.peer_id = peer_id
        self.status = "DISCONNECTED"  # DISCONNECTED, INITIATED, ESTABLISHED
        self.ephemeral_priv = None
        self.ephemeral_pub_bytes = None
        self.peer_ephemeral_pub_bytes = None
        self.k_init: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.mssv_list: List[str] = []
        self.peer_public_key_pem: Optional[str] = None
        self.last_init_nonce: Optional[str] = None
        self.incoming_file_transfers: Dict[str, Dict[str, Any]] = {}


class ClientCore:
    def __init__(
        self,
        client_id: str,
        server_host: str = "127.0.0.1",
        server_port: int = 9000,
        identity_dir: str = "keys",
        mssv_list: Optional[List[str]] = None
    ):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.mssv_list = mssv_list or ["2313955", "2313593", "2311593", "2311681"]
        self.identity = ClientIdentity.load_from_dir(identity_dir, client_id)

        self.sock: Optional[socket.socket] = None
        self.is_connected = False
        self.receiver_thread: Optional[threading.Thread] = None

        self.sessions: Dict[str, E2EESession] = {}
        self.online_users: List[str] = []

        # Callbacks for GUI / CLI
        self.on_log: Optional[Callable[[str, str], None]] = None  # (level, message)
        self.on_user_list_updated: Optional[Callable[[List[str]], None]] = None
        self.on_session_ready: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.on_message_received: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
        self.on_file_progress: Optional[Callable[[str, str, int, int], None]] = None
        self.on_file_completed: Optional[Callable[[str, str, str], None]] = None
        self.on_security_alert: Optional[Callable[[str, str], None]] = None  # (title, details)

    def log(self, message: str, level: str = "INFO") -> None:
        if self.on_log:
            self.on_log(level, message)
        else:
            print(f"[{level}] [{self.client_id}] {message}")

    def get_or_create_session(self, peer_id: str) -> E2EESession:
        if peer_id not in self.sessions:
            self.sessions[peer_id] = E2EESession(peer_id)
        return self.sessions[peer_id]

    def connect(self) -> bool:
        """Connect to Relay Server and register identity."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            self.is_connected = True

            # Register with server
            reg_packet = Packet(
                msg_type=MsgType.REGISTER,
                sender=self.client_id,
                receiver="SERVER",
                payload={"client_id": self.client_id}
            )
            send_packet(self.sock, reg_packet)

            # Start background listener thread
            self.receiver_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.receiver_thread.start()
            self.log(f"Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            self.log(f"Connection failed: {e}", "ERROR")
            self.is_connected = False
            return False

    def disconnect(self) -> None:
        """Disconnect from Relay Server."""
        self.is_connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.log("Disconnected from server.")

    def request_online_users(self) -> None:
        """Request the current active client list from the server."""
        if not self.is_connected or not self.sock:
            return
        send_packet(self.sock, Packet(
            msg_type=MsgType.CLIENT_LIST_REQ,
            sender=self.client_id,
            receiver="SERVER"
        ))

    # -----------------------------------------------------------------------
    # E2EE Handshake Operations
    # -----------------------------------------------------------------------

    def initiate_handshake(self, peer_id: str, custom_mssv_list: Optional[List[str]] = None) -> None:
        """Initiate E2EE Handshake with a peer.

        Generates Ephemeral ECDH keypair, formats greeting with MSSVs, signs packet with RSA.
        """
        if not self.is_connected:
            self.log("Cannot initiate handshake: Not connected to server.", "ERROR")
            return

        session = self.get_or_create_session(peer_id)
        mssv = custom_mssv_list or self.mssv_list
        session.mssv_list = mssv

        # 1. Generate Ephemeral ECDHE Keypair (PFS)
        eph_priv, eph_pub_bytes = generate_ephemeral_keypair()
        session.ephemeral_priv = eph_priv
        session.ephemeral_pub_bytes = eph_pub_bytes

        # 2. Derive K_init = SHA256(MSSV_1 || MSSV_2 ...)
        session.k_init = compute_k_init(mssv)

        # 3. Create Signed HANDSHAKE_INIT packet
        packet = create_handshake_init(
            sender=self.client_id,
            receiver=peer_id,
            mssv_list=mssv,
            identity=self.identity,
            ephemeral_pub_bytes=eph_pub_bytes
        )
        session.last_init_nonce = packet.payload["nonce"]
        session.status = "INITIATED"

        self.log(f"Sending HANDSHAKE_INIT to [{peer_id}]")
        self.log(f"Plaintext Greeting: \"{packet.payload['greeting']}\"")
        self.log(f"K_init = SHA256(MSSV): {session.k_init.hex()}")
        self.log(f"Ephemeral Public Key: {eph_pub_bytes.hex()}")

        send_packet(self.sock, packet)

    def _handle_handshake_init(self, packet: Packet) -> None:
        """Handle incoming HANDSHAKE_INIT from peer."""
        peer_id = packet.sender
        self.log(f"Received HANDSHAKE_INIT from [{peer_id}]")

        # 1. Verify digital signature and extract peer ephemeral public key (Anti-MitM)
        is_valid, msg, peer_eph_pub = verify_handshake_packet(packet)
        if not is_valid or peer_eph_pub is None:
            alert_msg = f"Handshake signature verification failed from {peer_id}! Reason: {msg}"
            self.log(alert_msg, "SECURITY_ALERT")
            if self.on_security_alert:
                self.on_security_alert("MitM Attack / Tampering Detected", alert_msg)
            return

        session = self.get_or_create_session(peer_id)
        session.peer_public_key_pem = packet.public_key
        session.peer_ephemeral_pub_bytes = peer_eph_pub
        session.mssv_list = packet.payload.get("mssv_list", self.mssv_list)

        # 2. Derive K_init = SHA256(MSSV_1 || MSSV_2 ...)
        session.k_init = compute_k_init(session.mssv_list)

        # 3. Generate local ephemeral ECDHE keypair
        eph_priv, eph_pub_bytes = generate_ephemeral_keypair()
        session.ephemeral_priv = eph_priv
        session.ephemeral_pub_bytes = eph_pub_bytes

        # 4. Compute ECDH Shared Secret
        shared_secret = compute_shared_secret(eph_priv, peer_eph_pub)
        session.shared_secret = shared_secret

        # 5. Derive Session Key via HKDF-SHA256
        session_key = derive_session_key(shared_secret, session.k_init)
        session.session_key = session_key
        session.status = "ESTABLISHED"

        self.log(f"Handshake signature from [{peer_id}] VERIFIED (RSA-PSS).")
        self.log(f"ECDHE Shared Secret: {shared_secret.hex()[:24]}...")
        self.log(f"Session Key Derived (AES-256): {session_key.hex()[:24]}...")

        # 6. Reply with HANDSHAKE_RESP
        init_nonce = packet.payload.get("nonce", "")
        resp_packet = create_handshake_resp(
            sender=self.client_id,
            receiver=peer_id,
            identity=self.identity,
            ephemeral_pub_bytes=eph_pub_bytes,
            init_packet_nonce=init_nonce
        )
        send_packet(self.sock, resp_packet)

        # Notify UI / application
        if self.on_session_ready:
            self.on_session_ready(peer_id, {
                "greeting": packet.payload.get("greeting"),
                "k_init_hex": session.k_init.hex(),
                "shared_secret_hex": shared_secret.hex(),
                "session_key_hex": session_key.hex(),
                "peer_eph_pub_hex": peer_eph_pub.hex(),
                "local_eph_pub_hex": eph_pub_bytes.hex()
            })

    def _handle_handshake_resp(self, packet: Packet) -> None:
        """Handle incoming HANDSHAKE_RESP from peer."""
        peer_id = packet.sender
        self.log(f"Received HANDSHAKE_RESP from [{peer_id}]")

        session = self.get_or_create_session(peer_id)
        if session.status != "INITIATED":
            self.log(f"Unexpected HANDSHAKE_RESP from {peer_id}", "WARNING")
            return

        # 1. Verify digital signature and extract peer ephemeral public key (Anti-MitM)
        is_valid, msg, peer_eph_pub = verify_handshake_packet(packet)
        if not is_valid or peer_eph_pub is None:
            alert_msg = f"Handshake response signature verification failed from {peer_id}! Reason: {msg}"
            self.log(alert_msg, "SECURITY_ALERT")
            if self.on_security_alert:
                self.on_security_alert("MitM Attack / Tampering Detected", alert_msg)
            return

        # 2. Compute ECDH Shared Secret
        shared_secret = compute_shared_secret(session.ephemeral_priv, peer_eph_pub)
        session.peer_ephemeral_pub_bytes = peer_eph_pub
        session.shared_secret = shared_secret

        # 3. Derive Session Key via HKDF-SHA256
        session_key = derive_session_key(shared_secret, session.k_init)
        session.session_key = session_key
        session.status = "ESTABLISHED"

        self.log(f"Handshake response from [{peer_id}] VERIFIED (RSA-PSS).")
        self.log(f"ECDHE Shared Secret: {shared_secret.hex()[:24]}...")
        self.log(f"Session Key Derived (AES-256): {session_key.hex()[:24]}...")

        # 4. Send Confirmation ACK
        ack_packet = Packet(
            msg_type=MsgType.HANDSHAKE_ACK,
            sender=self.client_id,
            receiver=peer_id,
            payload={"status": "SESSION_ACTIVE"}
        )
        send_packet(self.sock, ack_packet)

        # Notify UI / application
        if self.on_session_ready:
            self.on_session_ready(peer_id, {
                "greeting": f"Handshake established with {peer_id}",
                "k_init_hex": session.k_init.hex(),
                "shared_secret_hex": shared_secret.hex(),
                "session_key_hex": session_key.hex(),
                "peer_eph_pub_hex": peer_eph_pub.hex(),
                "local_eph_pub_hex": session.ephemeral_pub_bytes.hex()
            })

    # -----------------------------------------------------------------------
    # Encrypted Chat Operations (AES-256-GCM)
    # -----------------------------------------------------------------------

    def send_chat_message(self, peer_id: str, text: str) -> bool:
        """Encrypt and send a chat message to peer using AES-256-GCM."""
        session = self.sessions.get(peer_id)
        if not session or session.status != "ESTABLISHED" or not session.session_key:
            self.log(f"Cannot send message: E2EE Session with [{peer_id}] is not established.", "ERROR")
            return False

        plaintext_bytes = text.encode("utf-8")
        # Associated data ensures binding to sender, receiver, and message type
        aad = canonical_json_bytes({"sender": self.client_id, "receiver": peer_id, "type": MsgType.CHAT_MSG})

        ciphertext, nonce, tag = encrypt_aes_gcm(session.session_key, plaintext_bytes, associated_data=aad)

        packet = Packet(
            msg_type=MsgType.CHAT_MSG,
            sender=self.client_id,
            receiver=peer_id,
            payload=b64_encode(ciphertext),
            nonce=b64_encode(nonce),
            tag=b64_encode(tag)
        )
        send_packet(self.sock, packet)
        self.log(f"Sent encrypted message to [{peer_id}] (AES-256-GCM)")
        return True

    def _handle_chat_msg(self, packet: Packet) -> None:
        """Decrypt incoming AES-256-GCM chat message and verify integrity tag."""
        peer_id = packet.sender
        session = self.sessions.get(peer_id)
        if not session or session.status != "ESTABLISHED" or not session.session_key:
            self.log(f"Received message from [{peer_id}], but no established session exists.", "WARNING")
            return

        try:
            ciphertext = b64_decode(packet.payload)
            nonce = b64_decode(packet.nonce)
            tag = b64_decode(packet.tag)
            aad = canonical_json_bytes({"sender": peer_id, "receiver": self.client_id, "type": MsgType.CHAT_MSG})

            plaintext_bytes = decrypt_aes_gcm(session.session_key, ciphertext, nonce, tag, associated_data=aad)
            plaintext_str = plaintext_bytes.decode("utf-8")

            self.log(f"Received valid encrypted message from [{peer_id}]")
            if self.on_message_received:
                self.on_message_received(peer_id, plaintext_str, {
                    "ciphertext_b64": packet.payload,
                    "nonce_b64": packet.nonce,
                    "tag_b64": packet.tag,
                    "length": len(ciphertext)
                })
        except IntegrityVerificationError as e:
            alert_msg = f"Data Tampering Detected in message from {peer_id}! Reason: {e}"
            self.log(alert_msg, "SECURITY_ALERT")
            if self.on_security_alert:
                self.on_security_alert("Ciphertext Integrity Violation", alert_msg)
        except Exception as e:
            self.log(f"Decryption error from {peer_id}: {e}", "ERROR")

    # -----------------------------------------------------------------------
    # Encrypted File Transfer Operations (AES-256-GCM Chunked)
    # -----------------------------------------------------------------------

    def send_file(self, peer_id: str, file_path: str, chunk_size: int = 65536) -> bool:
        """Encrypt and send a file to peer in authenticated chunks."""
        if not os.path.exists(file_path):
            self.log(f"File not found: {file_path}", "ERROR")
            return False

        session = self.sessions.get(peer_id)
        if not session or session.status != "ESTABLISHED" or not session.session_key:
            self.log(f"Cannot send file: E2EE Session with [{peer_id}] is not established.", "ERROR")
            return False

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        total_chunks = (file_size + chunk_size - 1) // chunk_size if file_size > 0 else 1
        transfer_id = f"transfer-{int(time.time())}-{hashlib.md5(file_name.encode()).hexdigest()[:6]}"

        # Compute full file SHA-256 hash for end-to-end integrity verification
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        # 1. Send FILE_START packet
        start_payload = {
            "transfer_id": transfer_id,
            "file_name": file_name,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "file_hash": file_hash
        }
        send_packet(self.sock, Packet(
            msg_type=MsgType.FILE_START,
            sender=self.client_id,
            receiver=peer_id,
            payload=start_payload
        ))
        self.log(f"Starting encrypted file transfer: '{file_name}' ({file_size} bytes, {total_chunks} chunks)")

        # 2. Send Chunks encrypted with AES-256-GCM
        with open(file_path, "rb") as f:
            chunk_index = 0
            while True:
                chunk_bytes = f.read(chunk_size)
                if not chunk_bytes and chunk_index > 0:
                    break

                aad = canonical_json_bytes({
                    "transfer_id": transfer_id,
                    "chunk_index": chunk_index,
                    "sender": self.client_id,
                    "receiver": peer_id
                })
                ciphertext, nonce, tag = encrypt_aes_gcm(session.session_key, chunk_bytes, associated_data=aad)

                chunk_packet = Packet(
                    msg_type=MsgType.FILE_CHUNK,
                    sender=self.client_id,
                    receiver=peer_id,
                    payload={
                        "transfer_id": transfer_id,
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks,
                        "ciphertext": b64_encode(ciphertext)
                    },
                    nonce=b64_encode(nonce),
                    tag=b64_encode(tag)
                )
                send_packet(self.sock, chunk_packet)
                chunk_index += 1

                if self.on_file_progress:
                    self.on_file_progress(peer_id, file_name, chunk_index, total_chunks)

                if not chunk_bytes:
                    break

        # 3. Send FILE_END packet
        send_packet(self.sock, Packet(
            msg_type=MsgType.FILE_END,
            sender=self.client_id,
            receiver=peer_id,
            payload={"transfer_id": transfer_id, "file_name": file_name, "file_hash": file_hash}
        ))
        self.log(f"Finished sending file '{file_name}' to [{peer_id}] successfully.")
        return True

    def _handle_file_start(self, packet: Packet) -> None:
        peer_id = packet.sender
        session = self.get_or_create_session(peer_id)
        payload = packet.payload
        transfer_id = payload["transfer_id"]
        session.incoming_file_transfers[transfer_id] = {
            "file_name": payload["file_name"],
            "file_size": payload["file_size"],
            "total_chunks": payload["total_chunks"],
            "file_hash": payload["file_hash"],
            "chunks": {},
            "received_chunks": 0
        }
        self.log(f"Incoming encrypted file '{payload['file_name']}' from [{peer_id}] ({payload['file_size']} bytes)")

    def _handle_file_chunk(self, packet: Packet) -> None:
        peer_id = packet.sender
        session = self.sessions.get(peer_id)
        if not session or not session.session_key:
            return

        payload = packet.payload
        transfer_id = payload["transfer_id"]
        meta = session.incoming_file_transfers.get(transfer_id)
        if not meta:
            return

        chunk_idx = payload["chunk_index"]
        ciphertext = b64_decode(payload["ciphertext"])
        nonce = b64_decode(packet.nonce)
        tag = b64_decode(packet.tag)

        aad = canonical_json_bytes({
            "transfer_id": transfer_id,
            "chunk_index": chunk_idx,
            "sender": peer_id,
            "receiver": self.client_id
        })

        try:
            chunk_data = decrypt_aes_gcm(session.session_key, ciphertext, nonce, tag, associated_data=aad)
            meta["chunks"][chunk_idx] = chunk_data
            meta["received_chunks"] += 1

            if self.on_file_progress:
                self.on_file_progress(peer_id, meta["file_name"], meta["received_chunks"], meta["total_chunks"])
        except IntegrityVerificationError:
            alert_msg = f"Tampered File Chunk #{chunk_idx} detected from {peer_id}! File transfer aborted."
            self.log(alert_msg, "SECURITY_ALERT")
            if self.on_security_alert:
                self.on_security_alert("File Chunk Tampering Detected", alert_msg)
            del session.incoming_file_transfers[transfer_id]

    def _handle_file_end(self, packet: Packet) -> None:
        peer_id = packet.sender
        session = self.sessions.get(peer_id)
        if not session:
            return

        transfer_id = packet.payload["transfer_id"]
        meta = session.incoming_file_transfers.pop(transfer_id, None)
        if not meta:
            return

        # Reassemble chunks
        os.makedirs("received_files", exist_ok=True)
        out_path = os.path.join("received_files", f"{self.client_id}_{meta['file_name']}")

        hasher = hashlib.sha256()
        with open(out_path, "wb") as f:
            for idx in range(meta["total_chunks"]):
                chunk_data = meta["chunks"].get(idx, b"")
                hasher.update(chunk_data)
                f.write(chunk_data)

        # Verify End-to-End File Hash
        computed_hash = hasher.hexdigest()
        if computed_hash == meta["file_hash"]:
            self.log(f"File '{meta['file_name']}' received and VERIFIED (SHA-256 match: {computed_hash[:16]}...)")
            if self.on_file_completed:
                self.on_file_completed(peer_id, meta["file_name"], out_path)
        else:
            alert_msg = f"File hash mismatch for '{meta['file_name']}'! File is corrupted or tampered."
            self.log(alert_msg, "SECURITY_ALERT")
            if self.on_security_alert:
                self.on_security_alert("File Hash Verification Failed", alert_msg)

    # -----------------------------------------------------------------------
    # Socket Listener Loop
    # -----------------------------------------------------------------------

    def _listen_loop(self) -> None:
        try:
            while self.is_connected and self.sock:
                packet = recv_packet(self.sock)
                if not packet:
                    break

                if packet.msg_type == MsgType.REGISTER_OK:
                    self.log("Server registered identity confirmed.")
                    self.request_online_users()
                elif packet.msg_type == MsgType.CLIENT_LIST_RESP:
                    users = packet.payload.get("online_clients", [])
                    self.online_users = [u for u in users if u != self.client_id]
                    if self.on_user_list_updated:
                        self.on_user_list_updated(self.online_users)
                elif packet.msg_type == MsgType.HANDSHAKE_INIT:
                    self._handle_handshake_init(packet)
                elif packet.msg_type == MsgType.HANDSHAKE_RESP:
                    self._handle_handshake_resp(packet)
                elif packet.msg_type == MsgType.HANDSHAKE_ACK:
                    self.log(f"Session with [{packet.sender}] is fully active.")
                elif packet.msg_type == MsgType.CHAT_MSG:
                    self._handle_chat_msg(packet)
                elif packet.msg_type == MsgType.FILE_START:
                    self._handle_file_start(packet)
                elif packet.msg_type == MsgType.FILE_CHUNK:
                    self._handle_file_chunk(packet)
                elif packet.msg_type == MsgType.FILE_END:
                    self._handle_file_end(packet)
                elif packet.msg_type == MsgType.ERROR:
                    self.log(f"Server Error: {packet.payload.get('error')}", "ERROR")

        except Exception as e:
            if self.is_connected:
                self.log(f"Listener loop disconnected: {e}", "WARNING")
        finally:
            self.is_connected = False

