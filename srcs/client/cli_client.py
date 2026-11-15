"""Interactive Command Line Interface (CLI) for E2EE Client.

Allows full testing of Handshake, Chat, File Transfer, and Cryptographic inspection.
"""

import sys
import os
import time
import argparse
from srcs.client.client_core import ClientCore


def main():
    parser = argparse.ArgumentParser(description="E2EE Chat & File Transfer CLI Client")
    parser.add_argument("--id", required=True, help="Client ID / Username (e.g. Alice or MSSV_1)")
    parser.add_argument("--server", default="127.0.0.1", help="Relay Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Relay Server port (default: 9000)")
    parser.add_argument("--mssv", default="2313955,2313593,2311593,2311681", help="Comma-separated MSSVs")
    parser.add_argument("--peer", default="", help="Target peer ID to chat with")
    args = parser.parse_args()

    mssv_list = [m.strip() for m in args.mssv.split(",") if m.strip()]

    client = ClientCore(
        client_id=args.id,
        server_host=args.server,
        server_port=args.port,
        mssv_list=mssv_list
    )

    current_peer = args.peer

    def on_log(level: str, msg: str):
        if level == "SECURITY_ALERT":
            print(f"\n[!!! SECURITY ALERT !!!] {msg}\n> ", end="", flush=True)
        elif level == "ERROR":
            print(f"\n[ERROR] {msg}\n> ", end="", flush=True)
        else:
            print(f"\n[{level}] {msg}\n> ", end="", flush=True)

    def on_users(users):
        print(f"\n[ACTIVE USERS] Online: {', '.join(users) if users else 'None'}\n> ", end="", flush=True)

    def on_session_ready(peer, info):
        print(f"\n=======================================================")
        print(f" [SUCCESS] E2EE SESSION ESTABLISHED WITH [{peer}]")
        print(f" - Plaintext Greeting: {info.get('greeting')}")
        print(f" - K_init = SHA256(MSSV): {info.get('k_init_hex')}")
        print(f" - ECDHE Shared Secret: {info.get('shared_secret_hex')[:32]}...")
        print(f" - HKDF AES-256 Session Key: {info.get('session_key_hex')[:32]}...")
        print(f"=======================================================\n> ", end="", flush=True)

    def on_msg_received(sender, text, raw_info):
        print(f"\n[{sender} -> ME]: {text}")
        print(f"  [E2EE Ciphertext Hex]: {raw_info['ciphertext_b64'][:30]}... (Tag: {raw_info['tag_b64']})\n> ", end="", flush=True)

    def on_file_prog(peer, filename, current, total):
        pct = (current / total) * 100
        print(f"\r[FILE TRANSFER] {filename}: {pct:.1f}% ({current}/{total} chunks)", end="", flush=True)

    def on_file_done(peer, filename, path):
        print(f"\n[FILE RECEIVED] Successfully saved '{filename}' to: {path}\n> ", end="", flush=True)

    client.on_log = on_log
    client.on_user_list_updated = on_users
    client.on_session_ready = on_session_ready
    client.on_message_received = on_msg_received
    client.on_file_progress = on_file_prog
    client.on_file_completed = on_file_done

    print("=================================================================")
    print(f" Starting E2EE Client: [{args.id}]")
    print(f" Group MSSVs: {', '.join(mssv_list)}")
    print("=================================================================")

    if not client.connect():
        sys.exit(1)

    time.sleep(0.5)

    print("\nCommands:")
    print("  /peer <client_id>          : Set target peer to communicate with")
    print("  /handshake [m1,m2...]      : Perform ECDHE Handshake with current peer")
    print("  /msg <text>                : Send AES-256-GCM encrypted message")
    print("  /file <filepath>           : Send encrypted file in authenticated chunks")
    print("  /info                      : View current cryptographic session details")
    print("  /users                     : List online clients")
    print("  /quit                      : Exit program")
    print("-----------------------------------------------------------------")

    try:
        while True:
            cmd = input(f"[{args.id} -> {current_peer or 'NO_PEER'}]> ").strip()
            if not cmd:
                continue

            if cmd == "/quit":
                break
            elif cmd.startswith("/peer "):
                current_peer = cmd[6:].strip()
                print(f"Target peer set to: [{current_peer}]")
            elif cmd == "/users":
                client.request_online_users()
            elif cmd.startswith("/handshake"):
                if not current_peer:
                    print("Please set target peer first with /peer <id>")
                    continue
                parts = cmd.split(maxsplit=1)
                custom_mssvs = None
                if len(parts) > 1:
                    custom_mssvs = [m.strip() for m in parts[1].split(",") if m.strip()]
                client.initiate_handshake(current_peer, custom_mssvs)
            elif cmd.startswith("/msg "):
                if not current_peer:
                    print("Please set target peer first with /peer <id>")
                    continue
                msg_body = cmd[5:]
                client.send_chat_message(current_peer, msg_body)
            elif cmd.startswith("/file "):
                if not current_peer:
                    print("Please set target peer first with /peer <id>")
                    continue
                fpath = cmd[6:].strip().strip('"').strip("'")
                client.send_file(current_peer, fpath)
            elif cmd == "/info":
                if not current_peer or current_peer not in client.sessions:
                    print(f"No active session with '{current_peer}'")
                else:
                    sess = client.sessions[current_peer]
                    print(f"Session with: {current_peer}")
                    print(f"Status: {sess.status}")
                    print(f"K_init = SHA256(MSSV): {sess.k_init.hex() if sess.k_init else 'None'}")
                    print(f"ECDHE Shared Secret: {sess.shared_secret.hex() if sess.shared_secret else 'None'}")
                    print(f"Session Key (AES-256): {sess.session_key.hex() if sess.session_key else 'None'}")
            else:
                # If peer is set and not a command, treat as chat message
                if current_peer:
                    client.send_chat_message(current_peer, cmd)
                else:
                    print("Unknown command. Type /help or /peer <id> to begin.")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.disconnect()
        print("\nExited.")


if __name__ == "__main__":
    main()

