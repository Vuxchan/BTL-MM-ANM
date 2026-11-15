"""Packet framing and serialization for TCP communication.

Standardizes JSON payloads with 4-byte length-prefix framing over TCP sockets.
Handles Base64 encoding for binary cryptographic fields (nonces, tags, signatures, ciphertexts).
"""

import json
import struct
import base64
import time
import uuid
from typing import Optional, Dict, Any, Union


class MsgType:
    REGISTER = "REGISTER"
    REGISTER_OK = "REGISTER_OK"
    CLIENT_LIST_REQ = "CLIENT_LIST_REQ"
    CLIENT_LIST_RESP = "CLIENT_LIST_RESP"
    HANDSHAKE_INIT = "HANDSHAKE_INIT"
    HANDSHAKE_RESP = "HANDSHAKE_RESP"
    HANDSHAKE_ACK = "HANDSHAKE_ACK"
    CHAT_MSG = "CHAT_MSG"
    FILE_START = "FILE_START"
    FILE_CHUNK = "FILE_CHUNK"
    FILE_END = "FILE_END"
    DISCONNECT = "DISCONNECT"
    ERROR = "ERROR"
    SYSTEM_ALERT = "SYSTEM_ALERT"


def b64_encode(data: bytes) -> str:
    """Encode bytes to Base64 string."""
    return base64.b64encode(data).decode("ascii")


def b64_decode(data_str: str) -> bytes:
    """Decode Base64 string to bytes."""
    return base64.b64decode(data_str.encode("ascii"))


class Packet:
    """Represents a protocol packet."""

    def __init__(
        self,
        msg_type: str,
        sender: str,
        receiver: str,
        payload: Union[str, Dict[str, Any]] = "",
        nonce: Optional[str] = None,
        tag: Optional[str] = None,
        signature: Optional[str] = None,
        public_key: Optional[str] = None,
        packet_id: Optional[str] = None,
        timestamp: Optional[float] = None
    ):
        self.msg_type = msg_type
        self.sender = sender
        self.receiver = receiver
        self.payload = payload
        self.nonce = nonce
        self.tag = tag
        self.signature = signature
        self.public_key = public_key
        self.packet_id = packet_id or str(uuid.uuid4())
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.msg_type,
            "sender": self.sender,
            "receiver": self.receiver,
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "nonce": self.nonce,
            "tag": self.tag,
            "signature": self.signature,
            "public_key": self.public_key
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Packet":
        return cls(
            msg_type=d.get("type", MsgType.ERROR),
            sender=d.get("sender", ""),
            receiver=d.get("receiver", ""),
            payload=d.get("payload", ""),
            nonce=d.get("nonce"),
            tag=d.get("tag"),
            signature=d.get("signature"),
            public_key=d.get("public_key"),
            packet_id=d.get("packet_id"),
            timestamp=d.get("timestamp")
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Packet":
        return cls.from_dict(json.loads(json_str))


def send_packet(sock, packet: Packet) -> None:
    """Send length-prefixed JSON packet over socket.

    Format: [4-byte big-endian length] + [UTF-8 JSON bytes]
    """
    raw_data = packet.to_json().encode("utf-8")
    length_prefix = struct.pack("!I", len(raw_data))
    sock.sendall(length_prefix + raw_data)


def recv_exact(sock, num_bytes: int) -> bytes:
    """Receive exact number of bytes from socket or raise ConnectionError."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Socket connection closed while receiving data.")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock) -> Optional[Packet]:
    """Receive next length-prefixed packet from socket."""
    try:
        raw_length = recv_exact(sock, 4)
        length = struct.unpack("!I", raw_length)[0]
        raw_json = recv_exact(sock, length)
        json_str = raw_json.decode("utf-8")
        return Packet.from_json(json_str)
    except ConnectionError:
        return None
    except Exception as e:
        raise IOError(f"Error parsing incoming packet: {e}")

