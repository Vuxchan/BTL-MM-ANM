"""CA HTTP Service: certificate/CRL distribution, OCSP responder and admin API.

Public endpoints (no auth, as in a real PKI repository):
    GET  /ca/root.crt | /ca/issuing.crt | /ca/chain.pem
    GET  /crl/root.crl | /crl/issuing.crl          (DER, application/pkix-crl)
    POST /ocsp                                      (application/ocsp-request -> ocsp-response)
    GET  /ocsp/<base64(DER request)>                (RFC 6960 Appendix A.1)
Admin endpoints (header `X-Admin-Token` required):
    POST /api/issue   JSON {"csr": "<PEM>", "san": ["DNS:..."], "days": 365}
    POST /api/revoke  JSON {"serial": "<hex>", "reason": "keyCompromise"}
    GET  /api/certs
"""

import base64
import hmac
import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from srcs.pki.ca import CertificateAuthority, CAError, ISSUING, ROOT, parse_serial, serial_to_hex
from srcs.pki.ocsp_responder import OCSPResponder

MAX_BODY = 64 * 1024


class CAService:
    def __init__(self, ca: CertificateAuthority, host: Optional[str] = None, port: Optional[int] = None,
                 verbose: bool = True):
        self.ca = ca
        self.ocsp = OCSPResponder(ca)
        self.verbose = verbose
        self.host = host or ca.config.ca_host
        self.port = ca.config.ca_port if port is None else port
        self.httpd = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        self.port = self.httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start_background(self) -> "CAService":
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def _make_handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "HCMUT-InternalCA/1.0"

            def log_message(self, fmt, *args):
                if service.verbose:
                    print(f"[CA-SERVICE] {self.address_string()} - {fmt % args}", flush=True)

            # ---------------------------------------------------------------- helpers
            def _send(self, code: int, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, code: int, obj):
                self._send(code, json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")

            def _body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    raise CAError("Request body too large.")
                return self.rfile.read(length)

            def _authorized(self) -> bool:
                token = self.headers.get("X-Admin-Token", "")
                return hmac.compare_digest(token.encode(), service.ca.config.admin_token.encode())

            # ---------------------------------------------------------------- GET
            def do_GET(self):
                ca = service.ca
                path = urllib.parse.urlparse(self.path).path
                pem = serialization.Encoding.PEM
                if path == "/ca/root.crt":
                    return self._send(200, ca.root_cert.public_bytes(pem), "application/x-pem-file")
                if path == "/ca/issuing.crt":
                    return self._send(200, ca.issuing_cert.public_bytes(pem), "application/x-pem-file")
                if path == "/ca/chain.pem":
                    body = ca.issuing_cert.public_bytes(pem) + ca.root_cert.public_bytes(pem)
                    return self._send(200, body, "application/x-pem-file")
                if path == "/crl/root.crl":
                    return self._send(200, ca.load_crl_der(ROOT), "application/pkix-crl")
                if path == "/crl/issuing.crl":
                    return self._send(200, ca.load_crl_der(ISSUING), "application/pkix-crl")
                if path.startswith("/ocsp/"):
                    try:
                        der = base64.b64decode(urllib.parse.unquote(path[len("/ocsp/"):]))
                    except Exception:
                        der = b""
                    return self._send(200, service.ocsp.respond(der), "application/ocsp-response")
                if path == "/api/certs":
                    if not self._authorized():
                        return self._json(401, {"error": "unauthorized"})
                    return self._json(200, ca.list_certs())
                return self._json(404, {"error": "not found"})

            # ---------------------------------------------------------------- POST
            def do_POST(self):
                path = urllib.parse.urlparse(self.path).path
                try:
                    body = self._body()
                except CAError as e:
                    return self._json(413, {"error": str(e)})

                if path == "/ocsp":
                    return self._send(200, service.ocsp.respond(body), "application/ocsp-response")

                if path in ("/api/issue", "/api/revoke"):
                    if not self._authorized():
                        return self._json(401, {"error": "unauthorized"})
                    try:
                        data = json.loads(body or b"{}")
                        if path == "/api/issue":
                            csr = x509.load_pem_x509_csr(data["csr"].encode())
                            cert = service.ca.issue_from_csr(
                                csr, san=data.get("san"), days=int(data.get("days", 365)))
                            return self._json(200, {
                                "serial": serial_to_hex(cert.serial_number),
                                "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
                                "chain": service.ca.chain_pem(cert).decode(),
                            })
                        entry = service.ca.revoke(parse_serial(str(data["serial"])),
                                                  data.get("reason", "unspecified"))
                        return self._json(200, {"revoked": True, **entry})
                    except (CAError, KeyError, ValueError) as e:
                        return self._json(400, {"error": str(e)})

                return self._json(404, {"error": "not found"})

        return Handler
