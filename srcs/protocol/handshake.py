"""Handshake protocol implementation with MSSV plaintext requirement and digital signature anti-MitM.

Strictly adheres to:
1. Plaintext Handshake Greeting: "Hello, We are [MSSV_1], [MSSV_2], .."
2. K_init derived from SHA256(MSSV_1 || MSSV_2 ...)
3. ECDHE Ephemeral Public Key Exchange signed by RSA-PSS Identity Key.
"""

import json
import os
import time
from typing import List, Tuple, Dict, Any, Optional
from srcs.protocol.packet import Packet, MsgType, b64_encode, b64_decode
from srcs.crypto.asymmetric import sign_data, verify_signature, load_public_key_pem
from srcs.crypto.identity import ClientIdentity


def format_mssv_greeting(mssv_list: List[str]) -> str:
    """Format required handshake greeting string:

    'Hello, We are [MSSV_1], [MSSV_2], ..'
    """
    joined = ", ".join(f"[{str(m).strip()}]" for m in mssv_list)
    return f"Hello, We are {joined}"


def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    """Serialize dictionary to deterministic UTF-8 JSON bytes for digital signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_handshake_init(
    sender: str,
    receiver: str,
    mssv_list: List[str],
    identity: ClientIdentity,
    ephemeral_pub_bytes: bytes
) -> Packet:
    """Build HANDSHAKE_INIT packet containing the required MSSV plaintext greeting,

    the sender's ephemeral public key, and RSA-PSS signature.
    """
    greeting = format_mssv_greeting(mssv_list)
    nonce = b64_encode(os.urandom(16))
    
    payload = {
        "greeting": greeting,
        "mssv_list": [str(m).strip() for m in mssv_list],
        "ephemeral_pub": b64_encode(ephemeral_pub_bytes),
        "nonce": nonce,
        "timestamp": time.time()
    }

    # Digitally sign canonical payload using RSA-PSS
    signature = sign_data(identity.private_key, canonical_json_bytes(payload))

    return Packet(
        msg_type=MsgType.HANDSHAKE_INIT,
        sender=sender,
        receiver=receiver,
        payload=payload,
        signature=b64_encode(signature),
        public_key=identity.public_pem
    )


def create_handshake_resp(
    sender: str,
    receiver: str,
    identity: ClientIdentity,
    ephemeral_pub_bytes: bytes,
    init_packet_nonce: str
) -> Packet:
    """Build HANDSHAKE_RESP packet replying to initiator, containing responder's

    ephemeral public key and RSA-PSS signature.
    """
    resp_nonce = b64_encode(os.urandom(16))
    payload = {
        "status": "ACCEPTED",
        "echo_nonce": init_packet_nonce,
        "ephemeral_pub": b64_encode(ephemeral_pub_bytes),
        "resp_nonce": resp_nonce,
        "timestamp": time.time()
    }

    signature = sign_data(identity.private_key, canonical_json_bytes(payload))

    return Packet(
        msg_type=MsgType.HANDSHAKE_RESP,
        sender=sender,
        receiver=receiver,
        payload=payload,
        signature=b64_encode(signature),
        public_key=identity.public_pem
    )


def verify_handshake_packet(packet: Packet) -> Tuple[bool, str, Optional[bytes]]:
    """Verify digital signature and structure of a handshake packet.

    Returns:
        (is_valid, message, ephemeral_pub_bytes)
    """
    if not isinstance(packet.payload, dict):
        return False, "Handshake payload is not a valid JSON dictionary.", None

    if not packet.signature or not packet.public_key:
        return False, "Handshake packet is missing signature or public key.", None

    try:
        pub_key = load_public_key_pem(packet.public_key)
        sig_bytes = b64_decode(packet.signature)
        data_to_verify = canonical_json_bytes(packet.payload)

        if not verify_signature(pub_key, sig_bytes, data_to_verify):
            return False, "RSA-PSS Signature Verification Failed! Message was altered or forged (MitM detected).", None

        # Extract ephemeral public key bytes
        raw_eph_pub = packet.payload.get("ephemeral_pub")
        if not raw_eph_pub:
            return False, "Payload does not contain ephemeral public key.", None

        eph_bytes = b64_decode(raw_eph_pub)
        if len(eph_bytes) != 32:
            return False, f"Ephemeral public key length is invalid: {len(eph_bytes)} (expected 32)", None

        return True, "Handshake signature successfully verified.", eph_bytes

    except Exception as e:
        return False, f"Error verifying handshake: {str(e)}", None

