"""Unit tests for the internal PKI (phần 1.2): subjects with MSSV, extensions, CRL, OCSP."""

import datetime
import os
import shutil
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store

from srcs.pki.ca import CertificateAuthority, CAError, ISSUING, ROOT
from srcs.pki.config import PKIConfig
from srcs.pki.csr import build_csr, generate_key
from srcs.pki.ocsp_responder import OCSPResponder

MSSV = ["2313955", "2313593", "2311593", "2311681"]
EXPECTED_CN = "CA-Root-2313955-2313593-2311593-2311681"
EXPECTED_OU = "Faculty of Computer Science and Engineer – 2313955-2313593-2311593-2311681"


def _attr(name: x509.Name, oid) -> str:
    return name.get_attributes_for_oid(oid)[0].value


class TestPKI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pki_unit_")
        cls.ca = CertificateAuthority(PKIConfig(data_dir=cls.tmp, mssv=MSSV, ca_port=18080))
        cls.ca.initialize()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _issue(self, cn="localhost", **kw):
        key = generate_key()
        csr = build_csr(key, cn, [f"DNS:{cn}", "IP:127.0.0.1"])
        return self.ca.issue_from_csr(csr, **kw)

    # ------------------------------------------------------------------ subjects (MSSV)
    def test_root_subject_contains_mssv(self):
        root = self.ca.root_cert
        self.assertEqual(_attr(root.subject, NameOID.COMMON_NAME), EXPECTED_CN)
        self.assertEqual(_attr(root.subject, NameOID.ORGANIZATIONAL_UNIT_NAME), EXPECTED_OU)
        self.assertEqual(root.subject, root.issuer)  # self-signed
        print(f"\n  Root subject: {root.subject.rfc4514_string()}")

    def test_issued_cert_has_mssv_ou_and_issuer_chain(self):
        cert = self._issue()
        self.assertEqual(_attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME), EXPECTED_OU)
        self.assertEqual(cert.issuer, self.ca.issuing_cert.subject)
        self.assertEqual(self.ca.issuing_cert.issuer, self.ca.root_cert.subject)

    # ------------------------------------------------------------------ extensions
    def test_ca_extensions(self):
        bc = self.ca.root_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(bc.critical and bc.value.ca)
        self.assertEqual(bc.value.path_length, 1)
        ibc = self.ca.issuing_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(ibc.ca)
        self.assertEqual(ibc.path_length, 0)
        ku = self.ca.root_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_cert_sign and ku.crl_sign)

    def test_leaf_extensions(self):
        cert = self._issue()
        ext = cert.extensions
        self.assertFalse(ext.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, ext.get_extension_for_class(x509.ExtendedKeyUsage).value)
        san = ext.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("localhost", san.get_values_for_type(x509.DNSName))
        cdp = ext.get_extension_for_class(x509.CRLDistributionPoints).value
        self.assertEqual(cdp[0].full_name[0].value, "http://127.0.0.1:18080/crl/issuing.crl")
        aia = ext.get_extension_for_class(x509.AuthorityInformationAccess).value
        ocsp_urls = [d.access_location.value for d in aia
                     if d.access_method == x509.AuthorityInformationAccessOID.OCSP]
        self.assertEqual(ocsp_urls, ["http://127.0.0.1:18080/ocsp"])

    def test_chain_validates_to_root(self):
        cert = self._issue()
        verifier = PolicyBuilder().store(Store([self.ca.root_cert])).build_server_verifier(
            x509.DNSName("localhost"))
        chain = verifier.verify(cert, [self.ca.issuing_cert])
        self.assertEqual(len(chain), 3)

    # ------------------------------------------------------------------ CSR policy
    def test_rejects_tampered_csr(self):
        key = generate_key()
        csr = build_csr(key, "localhost")
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-5] ^= 0xFF  # corrupt the signature
        bad = x509.load_der_x509_csr(bytes(der))
        with self.assertRaises(CAError):
            self.ca.issue_from_csr(bad)

    def test_ca_private_keys_encrypted_on_disk(self):
        with open(os.path.join(self.tmp, "private", "root.key"), "rb") as f:
            self.assertIn(b"ENCRYPTED PRIVATE KEY", f.read())
        bad = CertificateAuthority(PKIConfig(data_dir=self.tmp, mssv=MSSV, passphrase="wrong"))
        with self.assertRaises(CAError):
            bad.load()

    # ------------------------------------------------------------------ CRL
    def test_crl_lists_revoked_serial(self):
        cert = self._issue()
        before = self.ca.generate_crl(ISSUING)
        self.assertIsNone(before.get_revoked_certificate_by_serial_number(cert.serial_number))
        self.ca.revoke(cert.serial_number, "keyCompromise")
        with open(os.path.join(self.tmp, "crl", "issuing.crl"), "rb") as f:
            crl = x509.load_der_x509_crl(f.read())
        self.assertTrue(crl.is_signature_valid(self.ca.issuing_cert.public_key()))
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.extensions.get_extension_for_class(x509.CRLReason).value.reason,
                         x509.ReasonFlags.key_compromise)
        n_before = before.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        n_after = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        self.assertGreater(n_after, n_before)
        with self.assertRaises(CAError):
            self.ca.revoke(cert.serial_number)  # double revoke

    def test_root_crl_signed_by_root(self):
        crl = self.ca.generate_crl(ROOT)
        self.assertTrue(crl.is_signature_valid(self.ca.root_cert.public_key()))
        self.assertEqual(crl.issuer, self.ca.root_cert.subject)

    # ------------------------------------------------------------------ OCSP
    def _ocsp(self, cert, issuer=None):
        issuer = issuer or self.ca.issuing_cert
        nonce = os.urandom(16)
        req = (ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
               .add_extension(x509.OCSPNonce(nonce), critical=False).build())
        der = OCSPResponder(self.ca).respond(req.public_bytes(serialization.Encoding.DER))
        resp = ocsp.load_der_ocsp_response(der)
        if resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            self.assertEqual(resp.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce, nonce)
        return resp

    def test_ocsp_good_then_revoked(self):
        cert = self._issue()
        self.assertEqual(self._ocsp(cert).certificate_status, ocsp.OCSPCertStatus.GOOD)
        self.ca.revoke(cert.serial_number, "superseded")
        resp = self._ocsp(cert)
        self.assertEqual(resp.certificate_status, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(resp.revocation_reason, x509.ReasonFlags.superseded)

    def test_ocsp_unknown_serial(self):
        key = generate_key()
        now = datetime.datetime.now(datetime.timezone.utc)
        foreign = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foreign")]))
                   .issuer_name(self.ca.issuing_cert.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                   .sign(key, hashes.SHA256()))
        self.assertEqual(self._ocsp(foreign).certificate_status, ocsp.OCSPCertStatus.UNKNOWN)

    def test_ocsp_malformed_request(self):
        resp = ocsp.load_der_ocsp_response(OCSPResponder(self.ca).respond(b"garbage"))
        self.assertEqual(resp.response_status, ocsp.OCSPResponseStatus.MALFORMED_REQUEST)


if __name__ == "__main__":
    unittest.main()
