"""Modern Tkinter Graphical User Interface (GUI) for E2EE Chat and File Transfer.

Provides visual demonstration of:
1. MSSV Handshake Greeting ("Hello, We are [MSSV_1], [MSSV_2]...")
2. Cryptographic Parameters (K_init, Ephemeral PubKeys, Shared Secret, AES-256 Session Key)
3. End-to-End Encrypted Chat with Real-Time Ciphertext / Nonce / Tag Inspector
4. End-to-End Encrypted File Transfer with Progress and SHA-256 Integrity Verification
5. Security Alert Console for MitM and Data Tampering Detection
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, Any, List
from srcs.client.client_core import ClientCore


class E2EEGuiApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("E2EE Chat & File Transfer - BTL 1.1 Mat Ma & An Ninh Mang")
        self.root.geometry("1100x720")
        self.root.minsize(950, 600)

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.client_core: ClientCore = None
        self.current_peer = tk.StringVar(value="")
        self.connection_status = tk.StringVar(value="Status: Disconnected")
        self.handshake_status = tk.StringVar(value="E2EE: Inactive")

        self._build_ui()

    def _build_ui(self):
        # Main split container: Left panel (Settings & Users) + Right panel (Notebook Tabs)
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # -------------------------------------------------------------
        # Left Control Panel
        # -------------------------------------------------------------
        left_frame = ttk.Frame(main_paned, width=300, padding=8)
        main_paned.add(left_frame, weight=1)

        # Title
        lbl_title = ttk.Label(left_frame, text="E2EE Messenger", font=("Helvetica", 14, "bold"))
        lbl_title.pack(anchor=tk.W, pady=(0, 10))

        # Connection Config Group
        grp_conn = ttk.LabelFrame(left_frame, text="Connection Config", padding=8)
        grp_conn.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(grp_conn, text="Client ID / MSSV:").pack(anchor=tk.W)
        self.ent_client_id = ttk.Entry(grp_conn)
        self.ent_client_id.insert(0, "")
        self.ent_client_id.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(grp_conn, text="Server Host & Port:").pack(anchor=tk.W)
        host_box = ttk.Frame(grp_conn)
        host_box.pack(fill=tk.X, pady=(2, 6))
        self.ent_host = ttk.Entry(host_box, width=14)
        self.ent_host.insert(0, "127.0.0.1")
        self.ent_host.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.ent_port = ttk.Entry(host_box, width=6)
        self.ent_port.insert(0, "9000")
        self.ent_port.pack(side=tk.LEFT)

        ttk.Label(grp_conn, text="MSSV (comma-separated):").pack(anchor=tk.W)
        self.ent_mssv = ttk.Entry(grp_conn)
        self.ent_mssv.insert(0, "2313955, 2313593, 2311593, 2311681")
        self.ent_mssv.pack(fill=tk.X, pady=(2, 8))

        self.btn_connect = ttk.Button(grp_conn, text="Connect to Server", command=self._toggle_connection)
        self.btn_connect.pack(fill=tk.X)

        # Online Peers Group
        grp_peers = ttk.LabelFrame(left_frame, text="Online Peers", padding=8)
        grp_peers.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.peer_listbox = tk.Listbox(grp_peers, height=6, selectmode=tk.SINGLE, font=("Consolas", 10))
        self.peer_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
        self.peer_listbox.bind("<<ListboxSelect>>", self._on_peer_selected)

        btn_refresh = ttk.Button(grp_peers, text="Refresh Peers", command=self._refresh_peers)
        btn_refresh.pack(fill=tk.X, pady=(0, 6))

        # Handshake Group
        grp_hs = ttk.LabelFrame(left_frame, text="E2EE Handshake", padding=8)
        grp_hs.pack(fill=tk.X)

        lbl_peer = ttk.Label(grp_hs, text="Target Peer:")
        lbl_peer.pack(anchor=tk.W)
        self.lbl_selected_peer = ttk.Label(grp_hs, textvariable=self.current_peer, font=("Helvetica", 10, "bold"), foreground="#0055aa")
        self.lbl_selected_peer.pack(anchor=tk.W, pady=(0, 6))

        self.btn_handshake = ttk.Button(grp_hs, text="Start ECDHE Handshake", command=self._start_handshake, state=tk.DISABLED)
        self.btn_handshake.pack(fill=tk.X, pady=(2, 4))

        # Status labels
        lbl_c_status = ttk.Label(left_frame, textvariable=self.connection_status, foreground="#555555")
        lbl_c_status.pack(anchor=tk.W, pady=(6, 2))
        lbl_h_status = ttk.Label(left_frame, textvariable=self.handshake_status, font=("Helvetica", 9, "bold"), foreground="#aa0000")
        lbl_h_status.pack(anchor=tk.W)

        # -------------------------------------------------------------
        # Right Notebook Tabs Panel
        # -------------------------------------------------------------
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=3)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_chat_tab()
        self._build_crypto_tab()
        self._build_file_tab()
        self._build_log_tab()

    # -----------------------------------------------------------------
    # Tab 1: Chat and Ciphertext Inspector
    # -----------------------------------------------------------------
    def _build_chat_tab(self):
        tab_chat = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(tab_chat, text="Chat & E2EE View")

        chat_paned = ttk.PanedWindow(tab_chat, orient=tk.VERTICAL)
        chat_paned.pack(fill=tk.BOTH, expand=True)

        # Top: Chat messages
        top_chat_frame = ttk.Frame(chat_paned)
        chat_paned.add(top_chat_frame, weight=3)

        self.txt_chat = tk.Text(top_chat_frame, wrap=tk.WORD, font=("Segoe UI", 10), state=tk.DISABLED, bg="#fafafa")
        scroll_chat = ttk.Scrollbar(top_chat_frame, command=self.txt_chat.yview)
        self.txt_chat.configure(yscrollcommand=scroll_chat.set)
        self.txt_chat.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_chat.pack(side=tk.RIGHT, fill=tk.Y)

        # Configure chat tags
        self.txt_chat.tag_configure("me", foreground="#004085", font=("Segoe UI", 10, "bold"))
        self.txt_chat.tag_configure("peer", foreground="#155724", font=("Segoe UI", 10, "bold"))
        self.txt_chat.tag_configure("system", foreground="#6c757d", font=("Segoe UI", 9, "italic"))
        self.txt_chat.tag_configure("alert", foreground="#721c24", background="#f8d7da", font=("Segoe UI", 10, "bold"))

        # Bottom: Ciphertext Inspector
        bottom_inspector_frame = ttk.LabelFrame(chat_paned, text="Packet Inspector (AES-256-GCM Wire Data)", padding=6)
        chat_paned.add(bottom_inspector_frame, weight=2)

        self.txt_inspector = tk.Text(bottom_inspector_frame, height=5, font=("Consolas", 9), bg="#1e1e1e", fg="#00ff66", state=tk.DISABLED)
        scroll_insp = ttk.Scrollbar(bottom_inspector_frame, command=self.txt_inspector.yview)
        self.txt_inspector.configure(yscrollcommand=scroll_insp.set)
        self.txt_inspector.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_insp.pack(side=tk.RIGHT, fill=tk.Y)

        # Send Box
        send_frame = ttk.Frame(tab_chat, padding=(0, 6, 0, 0))
        send_frame.pack(fill=tk.X)

        self.ent_msg = ttk.Entry(send_frame, font=("Segoe UI", 10))
        self.ent_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.ent_msg.bind("<Return>", lambda e: self._send_message())

        self.btn_send_msg = ttk.Button(send_frame, text="Send (AES-GCM)", command=self._send_message, state=tk.DISABLED)
        self.btn_send_msg.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_send_file = ttk.Button(send_frame, text="Send File...", command=self._send_file_dialog, state=tk.DISABLED)
        self.btn_send_file.pack(side=tk.LEFT)

    # -----------------------------------------------------------------
    # Tab 2: Cryptographic Parameters & Handshake Audit
    # -----------------------------------------------------------------
    def _build_crypto_tab(self):
        tab_crypto = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab_crypto, text="Handshake & Keys")

        lbl_desc = ttk.Label(
            tab_crypto,
            text="Cryptographic Parameters and Verification Data (Requirement 1.1)",
            font=("Helvetica", 11, "bold")
        )
        lbl_desc.pack(anchor=tk.W, pady=(0, 10))

        fields = [
            ("MSSV Plaintext Handshake:", "lbl_greeting_val"),
            ("K_init = SHA256(MSSV_1 || MSSV_2 ...):", "lbl_kinit_val"),
            ("Local Ephemeral Public Key (ECDHE X25519):", "lbl_local_eph_val"),
            ("Peer Ephemeral Public Key (ECDHE X25519):", "lbl_peer_eph_val"),
            ("ECDHE Shared Secret (Diffie-Hellman):", "lbl_secret_val"),
            ("HKDF Derived Session Key (AES-256):", "lbl_session_val"),
            ("Digital Signature (Anti-MitM Protection):", "lbl_sig_val"),
        ]

        self.crypto_fields: Dict[str, tk.StringVar] = {}

        for title, key in fields:
            box = ttk.LabelFrame(tab_crypto, text=title, padding=6)
            box.pack(fill=tk.X, pady=3)
            var = tk.StringVar(value="(Not available)")
            self.crypto_fields[key] = var
            lbl = ttk.Label(box, textvariable=var, font=("Consolas", 9), wraplength=700)
            lbl.pack(anchor=tk.W)

    # -----------------------------------------------------------------
    # Tab 3: File Transfer History
    # -----------------------------------------------------------------
    def _build_file_tab(self):
        tab_file = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_file, text="File Transfer")

        lbl_hdr = ttk.Label(tab_file, text="Encrypted File Transfer Status (AES-256-GCM Chunks)", font=("Helvetica", 11, "bold"))
        lbl_hdr.pack(anchor=tk.W, pady=(0, 8))

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0.0)
        self.lbl_progress_info = ttk.Label(tab_file, text="No active file transfer.")
        self.lbl_progress_info.pack(anchor=tk.W, pady=(0, 4))
        self.progress_bar = ttk.Progressbar(tab_file, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 12))

        # File history table
        columns = ("direction", "peer", "filename", "size", "status")
        self.tree_files = ttk.Treeview(tab_file, columns=columns, show="headings", height=8)
        self.tree_files.heading("direction", text="Direction")
        self.tree_files.heading("peer", text="Peer")
        self.tree_files.heading("filename", text="File Name")
        self.tree_files.heading("size", text="Size")
        self.tree_files.heading("status", text="Integrity / Status")

        self.tree_files.column("direction", width=80)
        self.tree_files.column("peer", width=100)
        self.tree_files.column("filename", width=200)
        self.tree_files.column("size", width=100)
        self.tree_files.column("status", width=220)

        self.tree_files.pack(fill=tk.BOTH, expand=True)

    # -----------------------------------------------------------------
    # Tab 4: System & Security Log
    # -----------------------------------------------------------------
    def _build_log_tab(self):
        tab_log = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(tab_log, text="Security & Event Logs")

        self.txt_logs = tk.Text(tab_log, font=("Consolas", 9), bg="#181818", fg="#cccccc", state=tk.DISABLED)
        scroll_logs = ttk.Scrollbar(tab_log, command=self.txt_logs.yview)
        self.txt_logs.configure(yscrollcommand=scroll_logs.set)
        self.txt_logs.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_logs.pack(side=tk.RIGHT, fill=tk.Y)

        self.txt_logs.tag_configure("SECURITY_ALERT", foreground="#ff4444", font=("Consolas", 9, "bold"))
        self.txt_logs.tag_configure("ERROR", foreground="#ff6666")
        self.txt_logs.tag_configure("INFO", foreground="#88ccff")

    # -----------------------------------------------------------------
    # Controller Actions
    # -----------------------------------------------------------------
    def _append_log(self, level: str, message: str):
        self.root.after(0, self.__safe_append_log, level, message)

    def __safe_append_log(self, level: str, message: str):
        self.txt_logs.configure(state=tk.NORMAL)
        self.txt_logs.insert(tk.END, f"[{level}] {message}\n", level)
        self.txt_logs.see(tk.END)
        self.txt_logs.configure(state=tk.DISABLED)

    def _toggle_connection(self):
        if self.client_core and self.client_core.is_connected:
            self.client_core.disconnect()
            self.client_core = None
            self.btn_connect.configure(text="Connect to Server")
            self.connection_status.set("Status: Disconnected")
            self.handshake_status.set("E2EE: Inactive")
            self.btn_handshake.configure(state=tk.DISABLED)
            self.btn_send_msg.configure(state=tk.DISABLED)
            self.btn_send_file.configure(state=tk.DISABLED)
            self.peer_listbox.delete(0, tk.END)
            return

        client_id = self.ent_client_id.get().strip()
        host = self.ent_host.get().strip()
        port = int(self.ent_port.get().strip())
        raw_mssv = self.ent_mssv.get().strip()
        mssv_list = [m.strip() for m in raw_mssv.split(",") if m.strip()]

        if not client_id:
            messagebox.showerror("Error", "Client ID cannot be empty.")
            return

        self.client_core = ClientCore(
            client_id=client_id,
            server_host=host,
            server_port=port,
            mssv_list=mssv_list
        )

        self.client_core.on_log = self._append_log
        self.client_core.on_user_list_updated = self._on_user_list_updated
        self.client_core.on_session_ready = self._on_session_ready
        self.client_core.on_message_received = self._on_message_received
        self.client_core.on_file_progress = self._on_file_progress
        self.client_core.on_file_completed = self._on_file_completed
        self.client_core.on_security_alert = self._on_security_alert

        if self.client_core.connect():
            self.btn_connect.configure(text="Disconnect")
            self.connection_status.set(f"Connected: {client_id} @ {host}:{port}")
        else:
            messagebox.showerror("Connection Error", f"Could not connect to {host}:{port}")

    def _refresh_peers(self):
        if self.client_core and self.client_core.is_connected:
            self.client_core.request_online_users()

    def _on_user_list_updated(self, users: List[str]):
        self.root.after(0, self.__safe_update_users, users)

    def __safe_update_users(self, users: List[str]):
        self.peer_listbox.delete(0, tk.END)
        for u in users:
            self.peer_listbox.insert(tk.END, u)

    def _on_peer_selected(self, event):
        sel = self.peer_listbox.curselection()
        if sel:
            peer = self.peer_listbox.get(sel[0])
            self.current_peer.set(peer)
            self.btn_handshake.configure(state=tk.NORMAL)
            self._check_peer_session_status()

    def _check_peer_session_status(self):
        peer = self.current_peer.get()
        if not self.client_core or not peer:
            return
        session = self.client_core.sessions.get(peer)
        if session and session.status == "ESTABLISHED":
            self.handshake_status.set(f"E2EE: Active with [{peer}]")
            self.btn_send_msg.configure(state=tk.NORMAL)
            self.btn_send_file.configure(state=tk.NORMAL)
        else:
            self.handshake_status.set(f"E2EE: Not established with [{peer}]")
            self.btn_send_msg.configure(state=tk.DISABLED)
            self.btn_send_file.configure(state=tk.DISABLED)

    def _start_handshake(self):
        peer = self.current_peer.get()
        if not peer:
            messagebox.showwarning("Warning", "Select an online peer first.")
            return
        raw_mssv = self.ent_mssv.get().strip()
        mssv_list = [m.strip() for m in raw_mssv.split(",") if m.strip()]
        self.client_core.initiate_handshake(peer, mssv_list)
        self.handshake_status.set(f"E2EE: Handshake sent to [{peer}]...")

    def _on_session_ready(self, peer: str, info: Dict[str, Any]):
        self.root.after(0, self.__safe_session_ready, peer, info)

    def __safe_session_ready(self, peer: str, info: Dict[str, Any]):
        if self.current_peer.get() == peer or not self.current_peer.get():
            self.current_peer.set(peer)
            self.handshake_status.set(f"E2EE: Active (PFS & AES-256) with [{peer}]")
            self.btn_send_msg.configure(state=tk.NORMAL)
            self.btn_send_file.configure(state=tk.NORMAL)

            # Update Handshake & Keys Tab
            self.crypto_fields["lbl_greeting_val"].set(info.get("greeting", ""))
            self.crypto_fields["lbl_kinit_val"].set(info.get("k_init_hex", ""))
            self.crypto_fields["lbl_local_eph_val"].set(info.get("local_eph_pub_hex", ""))
            self.crypto_fields["lbl_peer_eph_val"].set(info.get("peer_eph_pub_hex", ""))
            self.crypto_fields["lbl_secret_val"].set(info.get("shared_secret_hex", ""))
            self.crypto_fields["lbl_session_val"].set(info.get("session_key_hex", ""))
            self.crypto_fields["lbl_sig_val"].set("VERIFIED (RSA-PSS 2048-bit with SHA-256) - Anti-MitM OK")

            # Insert system message to chat
            self._append_chat(f"--- E2EE Channel Established with [{peer}] ---", "system")

    def _send_message(self):
        text = self.ent_msg.get().strip()
        peer = self.current_peer.get()
        if not text or not peer or not self.client_core:
            return

        if self.client_core.send_chat_message(peer, text):
            self.ent_msg.delete(0, tk.END)
            self._append_chat(f"Me -> {peer}: {text}", "me")

    def _on_message_received(self, sender: str, plaintext: str, raw_info: Dict[str, Any]):
        self.root.after(0, self.__safe_message_received, sender, plaintext, raw_info)

    def __safe_message_received(self, sender: str, plaintext: str, raw_info: Dict[str, Any]):
        self._append_chat(f"{sender}: {plaintext}", "peer")

        # Update Wire Inspector
        self.txt_inspector.configure(state=tk.NORMAL)
        inspector_text = (
            f"[WIRE AES-256-GCM] From: {sender} | Nonce: {raw_info.get('nonce_b64')} | "
            f"Tag: {raw_info.get('tag_b64')}\n"
            f"Ciphertext (Base64): {raw_info.get('ciphertext_b64')}\n"
            f"--- Server and wire listeners CANNOT decrypt this payload ---\n\n"
        )
        self.txt_inspector.insert(tk.END, inspector_text)
        self.txt_inspector.see(tk.END)
        self.txt_inspector.configure(state=tk.DISABLED)

    def _append_chat(self, text: str, tag: str):
        self.txt_chat.configure(state=tk.NORMAL)
        self.txt_chat.insert(tk.END, text + "\n", tag)
        self.txt_chat.see(tk.END)
        self.txt_chat.configure(state=tk.DISABLED)

    def _send_file_dialog(self):
        peer = self.current_peer.get()
        if not peer:
            return
        fpath = filedialog.askopenfilename(title="Select file to send encrypted")
        if not fpath:
            return

        threading.Thread(
            target=self.client_core.send_file,
            args=(peer, fpath),
            daemon=True
        ).start()

        fname = os.path.basename(fpath)
        fsize = f"{os.path.getsize(fpath):,} B"
        self.tree_files.insert("", tk.END, values=("Outgoing", peer, fname, fsize, "Transmitting..."))

    def _on_file_progress(self, peer: str, filename: str, current: int, total: int):
        self.root.after(0, self.__safe_file_progress, peer, filename, current, total)

    def __safe_file_progress(self, peer: str, filename: str, current: int, total: int):
        pct = (current / total) * 100
        self.progress_var.set(pct)
        self.lbl_progress_info.configure(text=f"Transferring {filename}: {pct:.1f}% ({current}/{total} chunks)")

    def _on_file_completed(self, peer: str, filename: str, saved_path: str):
        self.root.after(0, self.__safe_file_completed, peer, filename, saved_path)

    def __safe_file_completed(self, peer: str, filename: str, saved_path: str):
        self.progress_var.set(100.0)
        self.lbl_progress_info.configure(text=f"Completed '{filename}' -> Saved to {saved_path}")
        fsize = f"{os.path.getsize(saved_path):,} B" if os.path.exists(saved_path) else "N/A"
        self.tree_files.insert("", tk.END, values=("Incoming", peer, filename, fsize, "VERIFIED (SHA-256 Match)"))
        messagebox.showinfo("File Received", f"Encrypted file '{filename}' received and verified successfully!\nSaved at:\n{saved_path}")

    def _on_security_alert(self, title: str, details: str):
        self.root.after(0, self.__safe_security_alert, title, details)

    def __safe_security_alert(self, title: str, details: str):
        self._append_chat(f"!!! SECURITY ALERT: {title} - {details} !!!", "alert")
        messagebox.showerror(f"Security Alert: {title}", details)


def main():
    root = tk.Tk()
    app = E2EEGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

