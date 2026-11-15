"""Certificate Authority: X.509 issuance, certificate database, revocation and CRL.

Hierarchy (2 tiers):
    Root CA  (self-signed, offline role: signs the Issuing CA and the Root CRL)
      └── Issuing CA  (signs end-entity certificates, the Issuing CRL, OCSP responses)
            └── Web Server certificate (serverAuth, SAN, CDP, AIA/OCSP)

Standards: RFC 5280 (X.509 v3 certificates & CRL v2), RFC 2986 (PKCS#10 CSR).
"""

import datetime
import json
import os
import threading
import ipaddress
from typing import Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from srcs.pki.config import (
    PKIConfig,
    build_name,
    root_common_name,
    issuing_common_name,
    ROOT_KEY_SIZE,
    ISSUING_KEY_SIZE,
    ROOT_VALIDITY_DAYS,
    ISSUING_VALIDITY_DAYS,
    LEAF_VALIDITY_DAYS,
    CRL_VALIDITY_HOURS,
)

ROOT = "root"
ISSUING = "issuing"

STATUS_VALID = "valid"
STATUS_REVOKED = "revoked"

REASONS: Dict[str, x509.ReasonFlags] = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
}


class CAError(Exception):
    """Raised on any CA policy / state violation."""


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def serial_to_hex(serial: int) -> str:
    return format(serial, "X")


def parse_serial(text: str) -> int:
    """Parse a serial given in hex (as displayed by `list` / openssl), with optional 0x / colons."""
    cleaned = text.strip().lower().replace(":", "")
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return int(cleaned, 16)


def parse_reason(reason: str) -> x509.ReasonFlags:
    if reason not in REASONS:
        raise CAError(f"Unknown revocation reason '{reason}'. Valid: {', '.join(REASONS)}")
    return REASONS[reason]


def parse_san(entries: Sequence[str]) -> List[x509.GeneralName]:
    """Parse SAN entries like 'DNS:localhost' or 'IP:127.0.0.1' (bare values -> DNS)."""
    names: List[x509.GeneralName] = []
    for raw in entries:
        raw = raw.strip()
        if not raw:
            continue
        kind, sep, value = raw.partition(":")
        if not sep or kind.upper() not in ("DNS", "IP"):
            kind, value = "DNS", raw
        if kind.upper() == "IP":
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        else:
            names.append(x509.DNSName(value))
    return names


def _write_atomic(path: str, data: bytes) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


class CertificateAuthority:
    """Root + Issuing CA with a JSON certificate database."""

    def __init__(self, config: Optional[PKIConfig] = None):
        self.config = config or PKIConfig()
        self._lock = threading.RLock()
        self.root_key: Optional[rsa.RSAPrivateKey] = None
        self.root_cert: Optional[x509.Certificate] = None
        self.issuing_key: Optional[rsa.RSAPrivateKey] = None
        self.issuing_cert: Optional[x509.Certificate] = None

    # ------------------------------------------------------------------ setup / load
    @property
    def is_initialized(self) -> bool:
        c = self.config
        return all(os.path.exists(p) for p in (
            os.path.join(c.ca_dir, "root.crt"),
            os.path.join(c.ca_dir, "issuing.crt"),
            os.path.join(c.private_dir, "root.key"),
            os.path.join(c.private_dir, "issuing.key"),
        ))

    def initialize(self, force: bool = False) -> None:
        """Create Root CA, Issuing CA and the initial (empty) CRLs."""
        with self._lock:
            if self.is_initialized and not force:
                raise CAError(f"CA already initialized in '{self.config.data_dir}' (use --force).")
            c = self.config
            for d in (c.data_dir, c.ca_dir, c.private_dir, c.crl_dir, c.issued_dir):
                os.makedirs(d, exist_ok=True)

            self._save_index({})
            self._save_meta({"crl_number": {ROOT: 0, ISSUING: 0}, "mssv": c.mssv})

            self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=ROOT_KEY_SIZE)
            self.root_cert = self._build_root_cert(self.root_key)
            self.issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=ISSUING_KEY_SIZE)
            self.issuing_cert = self._build_issuing_cert(self.issuing_key)

            self._save_key("root.key", self.root_key)
            self._save_key("issuing.key", self.issuing_key)
            self._save_cert(os.path.join(c.ca_dir, "root.crt"), self.root_cert)
            self._save_cert(os.path.join(c.ca_dir, "issuing.crt"), self.issuing_cert)
            with open(os.path.join(c.ca_dir, "chain.pem"), "wb") as f:
                f.write(self.issuing_cert.public_bytes(serialization.Encoding.PEM))
                f.write(self.root_cert.public_bytes(serialization.Encoding.PEM))

            self._record(self.issuing_cert, ROOT, "Issuing CA")
            self.generate_crl(ROOT)
            self.generate_crl(ISSUING)

    def load(self) -> "CertificateAuthority":
        with self._lock:
            if not self.is_initialized:
                raise CAError(f"CA not initialized in '{self.config.data_dir}'. Run `init` first.")
            c = self.config
            self.root_key = self._load_key("root.key")
            self.issuing_key = self._load_key("issuing.key")
            self.root_cert = self._load_cert(os.path.join(c.ca_dir, "root.crt"))
            self.issuing_cert = self._load_cert(os.path.join(c.ca_dir, "issuing.crt"))
            return self

    @classmethod
    def open(cls, config: Optional[PKIConfig] = None) -> "CertificateAuthority":
        return cls(config).load()

    # ------------------------------------------------------------------ CA certificates
    def _build_root_cert(self, key: rsa.RSAPrivateKey) -> x509.Certificate:
        name = build_name(root_common_name(self.config.mssv), self.config.mssv)
        now = utcnow()
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=ROOT_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(self._ca_key_usage(), critical=True)
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
            .sign(key, hashes.SHA256())
        )

    def _build_issuing_cert(self, key: rsa.RSAPrivateKey) -> x509.Certificate:
        c = self.config
        now = utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(build_name(issuing_common_name(c.mssv), c.mssv))
            .issuer_name(self.root_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=ISSUING_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(self._ca_key_usage(), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(self._aki(self.root_cert), critical=False)
            .add_extension(self._cdp(c.root_crl_url), critical=False)
            .add_extension(x509.AuthorityInformationAccess([
                x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS,
                                       x509.UniformResourceIdentifier(c.root_cert_url)),
            ]), critical=False)
            .sign(self.root_key, hashes.SHA256())
        )

    @staticmethod
    def _ca_key_usage() -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        )

    @staticmethod
    def _aki(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
        ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)

    @staticmethod
    def _cdp(url: str) -> x509.CRLDistributionPoints:
        return x509.CRLDistributionPoints([
            x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(url)],
                                   relative_name=None, reasons=None, crl_issuer=None)
        ])

    # ------------------------------------------------------------------ issuance
    def issue_from_csr(
        self,
        csr: x509.CertificateSigningRequest,
        san: Optional[Sequence[str]] = None,
        days: int = LEAF_VALIDITY_DAYS,
        not_before: Optional[datetime.datetime] = None,
        not_after: Optional[datetime.datetime] = None,
    ) -> x509.Certificate:
        """Validate a PKCS#10 CSR and issue a TLS server certificate signed by the Issuing CA.

        The CA enforces its own subject policy: only the CN is taken from the CSR; C/L/O/OU
        are set by the CA (OU carries the team MSSVs).
        """
        with self._lock:
            self._require_loaded()
            if not csr.is_signature_valid:
                raise CAError("CSR signature is invalid (proof-of-possession failed).")
            pub = csr.public_key()
            if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < 2048:
                raise CAError("CA policy requires an RSA public key of at least 2048 bits.")
            cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_attrs:
                raise CAError("CSR subject must contain a Common Name.")
            cn = str(cn_attrs[0].value)

            san_names = parse_san(san) if san else []
            if not san_names:
                try:
                    san_names = list(csr.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName).value)
                except x509.ExtensionNotFound:
                    san_names = [x509.DNSName(cn)]

            now = utcnow()
            nb = not_before or (now - datetime.timedelta(minutes=5))
            na = not_after or (now + datetime.timedelta(days=days))
            if na <= nb:
                raise CAError("notAfter must be later than notBefore.")
            na = min(na, self.issuing_cert.not_valid_after_utc)

            c = self.config
            cert = (
                x509.CertificateBuilder()
                .subject_name(build_name(cn, c.mssv))
                .issuer_name(self.issuing_cert.subject)
                .public_key(pub)
                .serial_number(x509.random_serial_number())
                .not_valid_before(nb)
                .not_valid_after(na)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
                .add_extension(self._aki(self.issuing_cert), critical=False)
                .add_extension(self._cdp(c.issuing_crl_url), critical=False)
                .add_extension(x509.AuthorityInformationAccess([
                    x509.AccessDescription(x509.AuthorityInformationAccessOID.OCSP,
                                           x509.UniformResourceIdentifier(c.ocsp_url)),
                    x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS,
                                           x509.UniformResourceIdentifier(c.issuing_cert_url)),
                ]), critical=False)
                .sign(self.issuing_key, hashes.SHA256())
            )
            self._save_cert(os.path.join(c.issued_dir, f"{serial_to_hex(cert.serial_number)}.crt"), cert)
            self._record(cert, ISSUING, cn)
            return cert

    def chain_pem(self, cert: x509.Certificate) -> bytes:
        """Leaf + Issuing CA (the Root is distributed out-of-band as trust anchor)."""
        return (cert.public_bytes(serialization.Encoding.PEM)
                + self.issuing_cert.public_bytes(serialization.Encoding.PEM))

    # ------------------------------------------------------------------ revocation / CRL
    def revoke(self, serial: int, reason: str = "unspecified") -> Dict:
        with self._lock:
            self._require_loaded()
            parse_reason(reason)
            index = self._load_index()
            key = serial_to_hex(serial)
            if key not in index:
                raise CAError(f"Serial {key} was not issued by this CA.")
            entry = index[key]
            if entry["status"] == STATUS_REVOKED:
                raise CAError(f"Serial {key} is already revoked.")
            entry["status"] = STATUS_REVOKED
            entry["revoked_at"] = utcnow().isoformat()
            entry["reason"] = reason
            self._save_index(index)
            self.generate_crl(entry["issuer"])
            return entry

    def generate_crl(self, which: str = ISSUING) -> x509.CertificateRevocationList:
        """Produce a signed CRL v2 (with CRL Number + AKI) and write it in DER and PEM."""
        with self._lock:
            self._require_loaded()
            if which == ROOT:
                cert, key = self.root_cert, self.root_key
            elif which == ISSUING:
                cert, key = self.issuing_cert, self.issuing_key
            else:
                raise CAError(f"Unknown CA '{which}'.")

            meta = self._load_meta()
            meta["crl_number"][which] = int(meta["crl_number"].get(which, 0)) + 1
            now = utcnow()
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(cert.subject)
                .last_update(now)
                .next_update(now + datetime.timedelta(hours=CRL_VALIDITY_HOURS))
                .add_extension(x509.CRLNumber(meta["crl_number"][which]), critical=False)
                .add_extension(self._aki(cert), critical=False)
            )
            for serial_hex, entry in self._load_index().items():
                if entry["issuer"] != which or entry["status"] != STATUS_REVOKED:
                    continue
                revoked = (
                    x509.RevokedCertificateBuilder()
                    .serial_number(int(serial_hex, 16))
                    .revocation_date(datetime.datetime.fromisoformat(entry["revoked_at"]))
                    .add_extension(x509.CRLReason(parse_reason(entry["reason"])), critical=False)
                    .build()
                )
                builder = builder.add_revoked_certificate(revoked)
            crl = builder.sign(key, hashes.SHA256())
            self._save_meta(meta)
            _write_atomic(os.path.join(self.config.crl_dir, f"{which}.crl"),
                          crl.public_bytes(serialization.Encoding.DER))
            _write_atomic(os.path.join(self.config.crl_dir, f"{which}.crl.pem"),
                          crl.public_bytes(serialization.Encoding.PEM))
            return crl

    def load_crl_der(self, which: str = ISSUING) -> bytes:
        """Return the current CRL, regenerating it if it is missing or past nextUpdate."""
        with self._lock:
            path = os.path.join(self.config.crl_dir, f"{which}.crl")
            if os.path.exists(path):
                with open(path, "rb") as f:
                    data = f.read()
                crl = x509.load_der_x509_crl(data)
                if crl.next_update_utc and crl.next_update_utc > utcnow() + datetime.timedelta(minutes=5):
                    return data
            return self.generate_crl(which).public_bytes(serialization.Encoding.DER)

    def get_status(self, serial: int, issuer: str = ISSUING) -> Tuple[str, Optional[Dict]]:
        """Return ('good' | 'revoked' | 'unknown', db_entry)."""
        entry = self._load_index().get(serial_to_hex(serial))
        if entry is None or entry["issuer"] != issuer:
            return "unknown", None
        return ("revoked" if entry["status"] == STATUS_REVOKED else "good"), entry

    def list_certs(self) -> List[Dict]:
        return [dict(serial=k, **v) for k, v in self._load_index().items()]

    # ------------------------------------------------------------------ persistence
    def _require_loaded(self) -> None:
        if self.issuing_key is None or self.root_key is None:
            raise CAError("CA keys are not loaded.")

    def _record(self, cert: x509.Certificate, issuer: str, label: str) -> None:
        index = self._load_index()
        index[serial_to_hex(cert.serial_number)] = {
            "issuer": issuer,
            "label": label,
            "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "status": STATUS_VALID,
            "revoked_at": None,
            "reason": None,
        }
        self._save_index(index)

    def _load_index(self) -> Dict[str, Dict]:
        with self._lock:
            if not os.path.exists(self.config.index_path):
                return {}
            with open(self.config.index_path, "r", encoding="utf-8") as f:
                return json.load(f)

    def _save_index(self, index: Dict) -> None:
        _write_atomic(self.config.index_path,
                      json.dumps(index, indent=2, ensure_ascii=False).encode("utf-8"))

    def _load_meta(self) -> Dict:
        with open(self.config.meta_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_meta(self, meta: Dict) -> None:
        _write_atomic(self.config.meta_path, json.dumps(meta, indent=2).encode("utf-8"))

    def _save_key(self, filename: str, key: rsa.RSAPrivateKey) -> None:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(self.config.passphrase.encode("utf-8")),
        )
        path = os.path.join(self.config.private_dir, filename)
        _write_atomic(path, pem)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _load_key(self, filename: str) -> rsa.RSAPrivateKey:
        with open(os.path.join(self.config.private_dir, filename), "rb") as f:
            try:
                return serialization.load_pem_private_key(
                    f.read(), password=self.config.passphrase.encode("utf-8"))
            except ValueError as e:
                raise CAError(f"Cannot decrypt CA key '{filename}' (wrong passphrase?)") from e

    @staticmethod
    def _save_cert(path: str, cert: x509.Certificate) -> None:
        _write_atomic(path, cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def _load_cert(path: str) -> x509.Certificate:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
