"""Relay Server (Untrusted Message Router).

Acts as a central communication router for E2EE clients:
- Forwards handshake and encrypted packets between clients.
- Maintains active online client registry.
- NEVER possesses clients' private keys or session keys.
- Cannot read or tamper with encrypted message/file payloads without detection.
"""

import socket
import threading
import logging
from typing import Dict, Optional
from srcs.protocol.packet import Packet, MsgType, send_packet, recv_packet

# Setup server logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SERVER] %(message)s"
)
logger = logging.getLogger("RelayServer")


class RelayServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 9000):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.clients: Dict[str, socket.socket] = {}
        self.lock = threading.Lock()
        self.is_running = False

    def start(self) -> None:
        """Start TCP Relay Server and accept incoming connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(50)
        self.is_running = True

        logger.info(f"Relay Server running on {self.host}:{self.port}")
        logger.info("Security Mode: E2EE Relay (Zero-Knowledge of Plaintext)")

        try:
            while self.is_running:
                client_sock, addr = self.server_socket.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            logger.info("Server shutting down by user request...")
        except Exception as e:
            if self.is_running:
                logger.error(f"Server accept loop error: {e}")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop server and disconnect all clients."""
        self.is_running = False
        with self.lock:
            for cid, sock in list(self.clients.items()):
                try:
                    sock.close()
                except Exception:
                    pass
            self.clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        logger.info("Server stopped.")

    def _broadcast_client_list(self) -> None:
        """Send the list of online clients to all connected clients."""
        with self.lock:
            online_ids = list(self.clients.keys())
            packet = Packet(
                msg_type=MsgType.CLIENT_LIST_RESP,
                sender="SERVER",
                receiver="ALL",
                payload={"online_clients": online_ids}
            )
            for cid, sock in self.clients.items():
                try:
                    send_packet(sock, packet)
                except Exception as e:
                    logger.warning(f"Failed to send client list to {cid}: {e}")

    def _handle_client(self, client_sock: socket.socket, addr) -> None:
        client_id: Optional[str] = None
        logger.info(f"New incoming TCP connection from {addr}")

        try:
            while self.is_running:
                packet = recv_packet(client_sock)
                if not packet:
                    break

                # 1. Handle Registration
                if packet.msg_type == MsgType.REGISTER:
                    client_id = packet.sender.strip()
                    with self.lock:
                        self.clients[client_id] = client_sock
                    logger.info(f"Client registered successfully: [{client_id}] from {addr}")
                    send_packet(client_sock, Packet(
                        msg_type=MsgType.REGISTER_OK,
                        sender="SERVER",
                        receiver=client_id,
                        payload={"status": "REGISTERED", "client_id": client_id}
                    ))
                    self._broadcast_client_list()
                    continue

                # 2. Handle Client List Request
                if packet.msg_type == MsgType.CLIENT_LIST_REQ:
                    with self.lock:
                        online_ids = list(self.clients.keys())
                    send_packet(client_sock, Packet(
                        msg_type=MsgType.CLIENT_LIST_RESP,
                        sender="SERVER",
                        receiver=packet.sender,
                        payload={"online_clients": online_ids}
                    ))
                    continue

                # 3. Forward Message to Designated Receiver
                receiver = packet.receiver
                with self.lock:
                    target_sock = self.clients.get(receiver)

                if target_sock:
                    # Log packet passing through server (Demonstrating E2EE zero-knowledge)
                    if packet.msg_type in [MsgType.CHAT_MSG, MsgType.FILE_CHUNK]:
                        if packet.msg_type == MsgType.FILE_CHUNK and isinstance(packet.payload, dict):
                            cipher_str = str(packet.payload.get("ciphertext", ""))[:30]
                            payload_preview = f"Chunk #{packet.payload.get('chunk_index')} Cipher: {cipher_str}..."
                        else:
                            payload_preview = f"Cipher: {str(packet.payload)[:30]}..." if packet.payload else ""
                        logger.info(
                            f"[FORWARD OK] {packet.sender} -> {receiver} | Type: {packet.msg_type} | "
                            f"{payload_preview} (Bảo mật E2EE: Server chuyển tiếp thành công, không thể đọc trộm)"
                        )
                    elif packet.msg_type == MsgType.HANDSHAKE_INIT:
                        logger.info(
                            f"[FORWARD OK] {packet.sender} -> {receiver} | Bắt tay Handshake | "
                            f"Lời chào: {packet.payload.get('greeting', '')}"
                        )
                    else:
                        logger.info(f"[FORWARD OK] {packet.sender} -> {receiver} | Type: {packet.msg_type}")

                    send_packet(target_sock, packet)
                else:
                    logger.warning(f"Routing failed: Recipient [{receiver}] not found or offline.")
                    send_packet(client_sock, Packet(
                        msg_type=MsgType.ERROR,
                        sender="SERVER",
                        receiver=packet.sender,
                        payload={"error": f"Recipient '{receiver}' is currently offline."}
                    ))

        except ConnectionError:
            pass
        except Exception as e:
            logger.error(f"Exception handling client {client_id}: {e}")
        finally:
            if client_id:
                with self.lock:
                    if client_id in self.clients and self.clients[client_id] == client_sock:
                        del self.clients[client_id]
                logger.info(f"Client disconnected: [{client_id}]")
                self._broadcast_client_list()
            try:
                client_sock.close()
            except Exception:
                pass


def main():
    import argparse
    parser = argparse.ArgumentParser(description="E2EE Relay Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host IP (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9000, help="Binding port (default: 9000)")
    args = parser.parse_args()

    server = RelayServer(args.host, args.port)
    server.start()


if __name__ == "__main__":
    main()

