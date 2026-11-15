"""Demo Web Server over HTTPS (TLS >= 1.2) using a certificate issued by the internal CA."""

import html
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from cryptography import x509


class HTTPSServer:
    def __init__(self, cert_chain_path: str, key_path: str, host: str = "127.0.0.1", port: int = 8443,
                 verbose: bool = True):
        self.verbose = verbose
        with open(cert_chain_path, "rb") as f:
            self.leaf = x509.load_pem_x509_certificates(f.read())[0]

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_chain_path, keyfile=key_path)
        self.context = ctx

        self.httpd = ThreadingHTTPServer((host, port), self._make_handler())
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.host = host
        self.port = self.httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start_background(self) -> "HTTPSServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def _make_handler(self):
        server = self
        leaf = self.leaf

        class Handler(BaseHTTPRequestHandler):
            server_version = "HCMUT-SecureWeb/1.0"

            def log_message(self, fmt, *args):
                if server.verbose:
                    print(f"[HTTPS] {self.address_string()} - {fmt % args}", flush=True)

            def do_GET(self):
                cipher = self.request.cipher()
                rows = [
                    ("Subject", leaf.subject.rfc4514_string()),
                    ("Issuer", leaf.issuer.rfc4514_string()),
                    ("Serial", format(leaf.serial_number, "X")),
                    ("Valid", f"{leaf.not_valid_before_utc} → {leaf.not_valid_after_utc}"),
                    ("TLS", f"{self.request.version()} / {cipher[0] if cipher else '?'}"),
                ]
                body = (
                    "<!doctype html><meta charset='utf-8'><title>HCMUT Internal PKI</title>"
                    "<h1>HTTPS OK - certificate issued by the internal CA</h1><table border=1 cellpadding=4>"
                    + "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in rows)
                    + "</table>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
