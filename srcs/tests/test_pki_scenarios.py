"""End-to-end authentication scenarios for the internal PKI over real HTTPS/TLS.

    1. Valid certificate            -> TRUSTED (chain + CRL + OCSP + TLS all pass)
    2. Rogue CA with the same CN    -> REJECTED at path validation
    3. Revoked certificate          -> REJECTED by CRL and OCSP
    4. Expired certificate          -> REJECTED at path validation
    5. Hostname mismatch (SAN)      -> REJECTED at hostname verification
"""

import datetime
import os
import shutil
import socket
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from srcs.pki.ca import CertificateAuthority
from srcs.pki.ca_service import CAService
from srcs.pki.config import PKIConfig
from srcs.pki.csr import build_csr, generate_key, save_key
from srcs.pki.https_server import HTTPSServer
from srcs.pki.verifier import verify_url

MSSV = ["2313955", "2313593", "2311593", "2311681"]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _banner(title: str):
    print("\n=======================================================")
    print(f" {title}")
    print("=======================================================")


class TestPKIScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pki_e2e_")
        ca_port = find_free_port()
        cls.ca = CertificateAuthority(PKIConfig(data_dir=os.path.join(cls.tmp, "ca"), mssv=MSSV,
                                                ca_port=ca_port))
        cls.ca.initialize()
        cls.service = CAService(cls.ca, port=ca_port, verbose=False).start_background()
        cls.root_pem = os.path.join(cls.ca.config.ca_dir, "root.crt")
        cls.servers = []

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.stop()
        cls.service.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _start_https(self, name: str, ca: CertificateAuthority, cn="localhost",
                     san=("DNS:localhost", "IP:127.0.0.1"), **issue_kw) -> str:
        d = os.path.join(self.tmp, "srv", name)
        os.makedirs(d, exist_ok=True)
        key = generate_key()
        save_key(os.path.join(d, "server.key"), key)
        cert = ca.issue_from_csr(build_csr(key, cn, list(san)), san=list(san), **issue_kw)
        with open(os.path.join(d, "fullchain.pem"), "wb") as f:
            f.write(ca.chain_pem(cert))
        port = find_free_port()
        srv = HTTPSServer(os.path.join(d, "fullchain.pem"), os.path.join(d, "server.key"),
                          port=port, verbose=False).start_background()
        self.servers.append(srv)
        self._last_cert = cert
        return f"https://localhost:{port}"

    def _step(self, result, prefix):
        return next(s for s in result.steps if s.name.startswith(prefix))

    def test_scenario_1_valid_certificate(self):
        _banner("[SCENARIO 1] VALID CERTIFICATE ISSUED BY INTERNAL CA")
        url = self._start_https("valid", self.ca)
        result = verify_url(url, self.root_pem)
        print(result.report())
        self.assertTrue(result.trusted)
        self.assertIn("GOOD", self._step(result, "OCSP").detail)

    def test_scenario_2_rogue_ca_same_name(self):
        _banner("[SCENARIO 2] ROGUE CA IMPERSONATING CA-Root-<MSSV>")
        rogue = CertificateAuthority(PKIConfig(data_dir=os.path.join(self.tmp, "rogue"), mssv=MSSV,
                                               ca_port=self.ca.config.ca_port))
        rogue.initialize()
        self.assertEqual(rogue.root_cert.subject, self.ca.root_cert.subject)  # identical DN!
        url = self._start_https("rogue", rogue)
        result = verify_url(url, self.root_pem)
        print(result.report())
        self.assertFalse(result.trusted)
        self.assertFalse(self._step(result, "Chain").ok)

    def test_scenario_3_revoked_certificate(self):
        _banner("[SCENARIO 3] CERTIFICATE REVOKED (keyCompromise) -> CRL + OCSP")
        url = self._start_https("revoked", self.ca)
        self.assertTrue(verify_url(url, self.root_pem).trusted)
        self.ca.revoke(self._last_cert.serial_number, "keyCompromise")
        result = verify_url(url, self.root_pem)
        print(result.report())
        self.assertFalse(result.trusted)
        self.assertIn("REVOKED", self._step(result, "CRL (localhost)").detail)
        self.assertIn("REVOKED", self._step(result, "OCSP").detail)

    def test_scenario_4_expired_certificate(self):
        _banner("[SCENARIO 4] EXPIRED CERTIFICATE")
        now = datetime.datetime.now(datetime.timezone.utc)
        url = self._start_https("expired", self.ca,
                                not_before=now - datetime.timedelta(days=30),
                                not_after=now - datetime.timedelta(days=1))
        result = verify_url(url, self.root_pem)
        print(result.report())
        self.assertFalse(result.trusted)
        self.assertFalse(self._step(result, "Chain").ok)

    def test_scenario_5_hostname_mismatch(self):
        _banner("[SCENARIO 5] HOSTNAME MISMATCH (cert for evil.example served on localhost)")
        url = self._start_https("mismatch", self.ca, cn="evil.example", san=("DNS:evil.example",))
        result = verify_url(url, self.root_pem)
        print(result.report())
        self.assertFalse(result.trusted)
        self.assertFalse(self._step(result, "Chain").ok)


if __name__ == "__main__":
    unittest.main()
