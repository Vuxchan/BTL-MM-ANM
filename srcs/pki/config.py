"""PKI configuration: MSSV-embedded X.509 subjects, paths, URLs and validity periods.

Subject requirements from the assignment (BTL 1 - phần 1.2):
    Common Name (CN):          CA-Root-[MSSV_1]-[MSSV_2]..
    Organizational Unit (OU):  Faculty of Computer Science and Engineer – [MSSV_1]-[MSSV_2]..
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from cryptography import x509
from cryptography.x509.oid import NameOID

DEFAULT_MSSV: List[str] = ["2313955", "2313593", "2311593", "2311681"]

# NOTE: the OU string intentionally uses the EN DASH (U+2013) exactly as written in the
# assignment. It is encoded as UTF8String. Its length (74 chars for 4 MSSVs) exceeds the
# RFC 5280 upper bound ub-organizational-unit-name = 64, but OpenSSL and `cryptography`
# both accept it; we keep the string verbatim as required by the assignment.
OU_PREFIX = "Faculty of Computer Science and Engineer – "

ORGANIZATION = "Ho Chi Minh City University of Technology - HCMUT"
COUNTRY = "VN"
LOCALITY = "Ho Chi Minh City"

ROOT_KEY_SIZE = 4096
ISSUING_KEY_SIZE = 2048
LEAF_KEY_SIZE = 2048

ROOT_VALIDITY_DAYS = 3650
ISSUING_VALIDITY_DAYS = 1825
LEAF_VALIDITY_DAYS = 365
CRL_VALIDITY_HOURS = 24
OCSP_VALIDITY_HOURS = 1

DEFAULT_CA_HOST = "127.0.0.1"
DEFAULT_CA_PORT = 8080
DEFAULT_HTTPS_PORT = 8443

DEFAULT_PASSPHRASE = "hcmut-pki-demo"
DEFAULT_ADMIN_TOKEN = "hcmut-pki-admin"


def normalize_mssv(mssv: Optional[Sequence[str]]) -> List[str]:
    if mssv is None:
        return list(DEFAULT_MSSV)
    if isinstance(mssv, str):
        mssv = mssv.split(",")
    items = [str(m).strip() for m in mssv if str(m).strip()]
    if not items:
        raise ValueError("MSSV list cannot be empty.")
    return items


def mssv_tag(mssv: Sequence[str]) -> str:
    return "-".join(mssv)


def root_common_name(mssv: Sequence[str]) -> str:
    return f"CA-Root-{mssv_tag(mssv)}"


def issuing_common_name(mssv: Sequence[str]) -> str:
    return f"CA-Issuing-{mssv_tag(mssv)}"


def organizational_unit(mssv: Sequence[str]) -> str:
    return f"{OU_PREFIX}{mssv_tag(mssv)}"


def build_name(common_name: str, mssv: Sequence[str]) -> x509.Name:
    """Build an X.509 distinguished name carrying the MSSV-based OU."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit(mssv)),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


@dataclass
class PKIConfig:
    """Runtime configuration for a CA instance."""

    data_dir: str = "pki_data"
    mssv: List[str] = field(default_factory=lambda: list(DEFAULT_MSSV))
    ca_host: str = DEFAULT_CA_HOST
    ca_port: int = DEFAULT_CA_PORT
    passphrase: str = field(
        default_factory=lambda: os.environ.get("PKI_CA_PASSPHRASE", DEFAULT_PASSPHRASE)
    )
    admin_token: str = field(
        default_factory=lambda: os.environ.get("PKI_ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN)
    )

    def __post_init__(self):
        self.mssv = normalize_mssv(self.mssv)

    # --- URLs embedded into issued certificates -----------------------------------------
    @property
    def base_url(self) -> str:
        return f"http://{self.ca_host}:{self.ca_port}"

    @property
    def root_crl_url(self) -> str:
        return f"{self.base_url}/crl/root.crl"

    @property
    def issuing_crl_url(self) -> str:
        return f"{self.base_url}/crl/issuing.crl"

    @property
    def ocsp_url(self) -> str:
        return f"{self.base_url}/ocsp"

    @property
    def root_cert_url(self) -> str:
        return f"{self.base_url}/ca/root.crt"

    @property
    def issuing_cert_url(self) -> str:
        return f"{self.base_url}/ca/issuing.crt"

    # --- Filesystem layout ---------------------------------------------------------------
    def path(self, *parts: str) -> str:
        return os.path.join(self.data_dir, *parts)

    @property
    def ca_dir(self) -> str:
        return self.path("ca")

    @property
    def private_dir(self) -> str:
        return self.path("private")

    @property
    def crl_dir(self) -> str:
        return self.path("crl")

    @property
    def issued_dir(self) -> str:
        return self.path("issued")

    @property
    def index_path(self) -> str:
        return self.path("index.json")

    @property
    def meta_path(self) -> str:
        return self.path("ca_meta.json")
