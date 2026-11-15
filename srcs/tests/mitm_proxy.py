"""Man-in-the-Middle (MitM) Attack Simulation and Interception Proxy.

Demonstrates security resistance against:
1. Passive Eavesdropping (Sniffing): Verifies that observer only captures ciphertext and cannot decrypt.
2. Active Handshake Tampering (Key Substitution / MitM): Mallory replaces Alice's ephemeral public key
   with her own. Verified that RSA-PSS signature check detects forgery and drops connection.
3. Active Data Tampering (Bit-flipping in transit): Mallory modifies 1 byte in AES-256-GCM ciphertext.
   Verified that GMAC authentication tag verification fails (IntegrityViolation).
"""

import socket
import threading
import time
import argparse
import logging
from typing import Optional
from srcs.protocol.packet import recv_packet, send_packet, Packet, MsgType, b64_encode, b64_decode
from srcs.crypto.asymmetric import generate_ephemeral_keypair

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MITM PROXY] %(message)s")
logger = logging.getLogger("MitMProxy")


class MitMProxy:
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 9001,
        target_host: str = "127.0.0.1",
        target_port: int = 9000,
        attack_mode: str = "sniff"  # "sniff", "tamper-handshake", "tamper-data"
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.attack_mode = attack_mode
        self.is_running = False
        self.server_sock: Optional[socket.socket] = None
        self.intercepted_events = []

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.listen_host, self.listen_port))
        self.server_sock.listen(10)
        self.is_running = True

        logger.info(f"MitM Proxy listening on {self.listen_host}:{self.listen_port}")
        logger.info(f"Forwarding to target {self.target_host}:{self.target_port}")
        logger.info(f"Active Attack Mode: [{self.attack_mode.upper()}]")

        try:
            while self.is_running:
                try:
                    client_sock, addr = self.server_sock.accept()
                except OSError:
                    break
                logger.info(f"Client connected to proxy: {addr}")
                # Connect to real server
                real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                real_sock.connect((self.target_host, self.target_port))

                # Bi-directional forwarding threads
                t1 = threading.Thread(target=self._forward_flow, args=(client_sock, real_sock, "CLIENT -> SERVER"), daemon=True)
                t2 = threading.Thread(target=self._forward_flow, args=(real_sock, client_sock, "SERVER -> CLIENT"), daemon=True)
                t1.start()
                t2.start()
        except KeyboardInterrupt:
            logger.info("Proxy shutting down...")
        finally:
            self.stop()

    def stop(self):
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

    def _forward_flow(self, src: socket.socket, dst: socket.socket, direction: str):
        try:
            while self.is_running:
                packet = recv_packet(src)
                if not packet:
                    break

                modified_packet = self._apply_attack(packet, direction)
                send_packet(dst, modified_packet)
        except Exception:
            pass
        finally:
            try:
                src.close()
                dst.close()
            except Exception:
                pass

    def _apply_attack(self, packet: Packet, direction: str) -> Packet:
        # Record intercepted packet summary
        self.intercepted_events.append({
            "direction": direction,
            "type": packet.msg_type,
            "sender": packet.sender,
            "receiver": packet.receiver
        })

        # -------------------------------------------------------------
        # Mode 1: Passive Sniffing
        # -------------------------------------------------------------
        if self.attack_mode == "sniff":
            if packet.msg_type in [MsgType.CHAT_MSG, MsgType.FILE_CHUNK]:
                logger.info(
                    f"[SNIFFED ENCRYPTED PACKET] {packet.sender} -> {packet.receiver} | "
                    f"Type: {packet.msg_type} | Ciphertext: {str(packet.payload)[:30]}... | "
                    f"Nonce: {packet.nonce} | Tag: {packet.tag} (UNABLE TO DECRYPT WITHOUT SESSION KEY)"
                )
            elif packet.msg_type == MsgType.HANDSHAKE_INIT:
                logger.info(
                    f"[SNIFFED HANDSHAKE] Greeting: {packet.payload.get('greeting')} | "
                    f"Sender PubKey: {packet.payload.get('ephemeral_pub')[:20]}..."
                )
            return packet

        # -------------------------------------------------------------
        # Mode 2: Active Handshake Tampering (Ephemeral Key Replacement)
        # -------------------------------------------------------------
        elif self.attack_mode == "tamper-handshake":
            if packet.msg_type == MsgType.HANDSHAKE_INIT:
                logger.warning(
                    f"[ATTACK EXECUTION] Intercepted HANDSHAKE_INIT from {packet.sender} to {packet.receiver}!"
                )
                logger.warning("Mallory replaces Alice's ephemeral public key with Mallory's key...")

                # Mallory generates forged ephemeral keypair
                _, mallory_eph_pub = generate_ephemeral_keypair()
                
                # Replace ephemeral public key in payload without updating the RSA signature
                # (Mallory cannot sign with Alice's private key)
                tampered_payload = dict(packet.payload)
                tampered_payload["ephemeral_pub"] = b64_encode(mallory_eph_pub)

                tampered_packet = Packet(
                    msg_type=packet.msg_type,
                    sender=packet.sender,
                    receiver=packet.receiver,
                    payload=tampered_payload,
                    signature=packet.signature,  # Original Alice's signature (now invalid for tampered payload!)
                    public_key=packet.public_key,
                    packet_id=packet.packet_id,
                    timestamp=packet.timestamp
                )
                logger.warning("[ATTACK SENT] Forwarded tampered handshake packet to Bob.")
                return tampered_packet
            return packet

        # -------------------------------------------------------------
        # Mode 3: Active Data Tampering (Bit-flipping in Ciphertext)
        # -------------------------------------------------------------
        elif self.attack_mode == "tamper-data":
            if packet.msg_type == MsgType.CHAT_MSG:
                logger.warning(
                    f"[ATTACK EXECUTION] Intercepted CHAT_MSG from {packet.sender} to {packet.receiver}!"
                )
                raw_cipher = bytearray(b64_decode(packet.payload))
                if len(raw_cipher) > 0:
                    logger.warning(f"Flipping bit in ciphertext byte 0: {raw_cipher[0]} -> {raw_cipher[0] ^ 0x01}")
                    raw_cipher[0] ^= 0x01  # Flip one bit

                tampered_packet = Packet(
                    msg_type=packet.msg_type,
                    sender=packet.sender,
                    receiver=packet.receiver,
                    payload=b64_encode(bytes(raw_cipher)),
                    nonce=packet.nonce,
                    tag=packet.tag,  # Original tag (now invalid for tampered ciphertext!)
                    packet_id=packet.packet_id,
                    timestamp=packet.timestamp
                )
                logger.warning("[ATTACK SENT] Forwarded tampered ciphertext to receiver.")
                return tampered_packet
            return packet

        return packet


def main():
    parser = argparse.ArgumentParser(description="E2EE MitM Proxy Demonstration")
    parser.add_argument("--listen-port", type=int, default=9001, help="Proxy listen port (default: 9001)")
    parser.add_argument("--target-port", type=int, default=9000, help="Target Relay Server port (default: 9000)")
    parser.add_argument("--mode", choices=["sniff", "tamper-handshake", "tamper-data"], default="sniff",
                        help="Attack mode (sniff, tamper-handshake, tamper-data)")
    args = parser.parse_args()

    proxy = MitMProxy(listen_port=args.listen_port, target_port=args.target_port, attack_mode=args.mode)
    proxy.start()


if __name__ == "__main__":
    main()
