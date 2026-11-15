"""Command line interface for the internal PKI.

    python -m srcs.pki.cli init                      # create Root + Issuing CA, empty CRLs
    python -m srcs.pki.cli serve-ca                  # CA repository + CRL + OCSP + admin API (:8080)
    python -m srcs.pki.cli issue --cn localhost --san DNS:localhost,IP:127.0.0.1
    python -m srcs.pki.cli serve-https               # demo web server on :8443
    python -m srcs.pki.cli verify https://localhost:8443
    python -m srcs.pki.cli list
    python -m srcs.pki.cli revoke --serial <HEX> --reason keyCompromise
    python -m srcs.pki.cli gen-crl
"""

import argparse
import json
import os
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from srcs.pki.ca import CertificateAuthority, CAError, REASONS, ISSUING, ROOT, parse_serial, serial_to_hex
from srcs.pki.config import PKIConfig, DEFAULT_CA_HOST, DEFAULT_CA_PORT, DEFAULT_HTTPS_PORT
from srcs.pki.csr import create_key_and_csr


def _config(args) -> PKIConfig:
    return PKIConfig(data_dir=args.data_dir, mssv=args.mssv, ca_host=args.ca_host, ca_port=args.ca_port)


def _server_dir(args) -> str:
    return os.path.join(args.data_dir, "server", args.name)


def cmd_init(args):
    ca = CertificateAuthority(_config(args))
    ca.initialize(force=args.force)
    print(f"[+] Root CA     : {ca.root_cert.subject.rfc4514_string()}")
    print(f"[+] Issuing CA  : {ca.issuing_cert.subject.rfc4514_string()}")
    print(f"[+] Trust anchor: {os.path.join(ca.config.ca_dir, 'root.crt')}")
    print(f"[+] CRLs        : {ca.config.crl_dir}")


def cmd_issue(args):
    out_dir = _server_dir(args)
    os.makedirs(out_dir, exist_ok=True)
    san = [s for s in (args.san or "").split(",") if s.strip()] or [f"DNS:{args.cn}"]
    _, csr = create_key_and_csr(out_dir, args.cn, san)
    print(f"[+] Generated key + CSR in {out_dir}")

    if args.via_api:
        cfg = _config(args)
        body = json.dumps({
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "san": san, "days": args.days,
        }).encode()
        req = urllib.request.Request(f"{cfg.base_url}/api/issue", data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "X-Admin-Token": cfg.admin_token})
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
        cert_pem, chain_pem = resp["certificate"].encode(), resp["chain"].encode()
    else:
        ca = CertificateAuthority.open(_config(args))
        cert = ca.issue_from_csr(csr, san=san, days=args.days)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        chain_pem = ca.chain_pem(cert)

    with open(os.path.join(out_dir, "server.crt"), "wb") as f:
        f.write(cert_pem)
    with open(os.path.join(out_dir, "fullchain.pem"), "wb") as f:
        f.write(chain_pem)
    cert = x509.load_pem_x509_certificate(cert_pem)
    print(f"[+] Issued certificate serial={serial_to_hex(cert.serial_number)}")
    print(f"    Subject : {cert.subject.rfc4514_string()}")
    print(f"    Valid   : {cert.not_valid_before_utc} -> {cert.not_valid_after_utc}")
    print(f"    Files   : {out_dir}/server.crt, fullchain.pem, server.key")


def cmd_revoke(args):
    ca = CertificateAuthority.open(_config(args))
    serial = parse_serial(args.serial)
    entry = ca.revoke(serial, args.reason)
    print(f"[+] Revoked {serial_to_hex(serial)} ({entry['label']}) reason={args.reason}")
    print(f"[+] New CRL published: {ca.config.crl_dir}/{entry['issuer']}.crl")


def cmd_list(args):
    ca = CertificateAuthority.open(_config(args))
    print(f"{'SERIAL':<42} {'ISSUER':<8} {'STATUS':<8} {'NOT AFTER':<26} LABEL")
    for e in ca.list_certs():
        status = e["status"] + (f" ({e['reason']})" if e["reason"] else "")
        print(f"{e['serial']:<42} {e['issuer']:<8} {status:<8} {e['not_after']:<26} {e['label']}")


def cmd_gen_crl(args):
    ca = CertificateAuthority.open(_config(args))
    for which in (ROOT, ISSUING):
        crl = ca.generate_crl(which)
        num = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        print(f"[+] {which} CRL #{num}: {len(crl)} revoked, nextUpdate={crl.next_update_utc}")


def cmd_serve_ca(args):
    from srcs.pki.ca_service import CAService
    ca = CertificateAuthority.open(_config(args))
    svc = CAService(ca)
    print(f"[+] CA service on {ca.config.base_url}  (CRL: /crl/issuing.crl, OCSP: /ocsp)")
    try:
        svc.serve_forever()
    except KeyboardInterrupt:
        svc.stop()


def cmd_serve_https(args):
    from srcs.pki.https_server import HTTPSServer
    d = _server_dir(args)
    srv = HTTPSServer(os.path.join(d, "fullchain.pem"), os.path.join(d, "server.key"),
                      host=args.host, port=args.port)
    print(f"[+] HTTPS server on https://{args.host}:{srv.port}  cert serial={serial_to_hex(srv.leaf.serial_number)}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.stop()


def cmd_verify(args):
    from srcs.pki.verifier import verify_url
    root = args.root or os.path.join(args.data_dir, "ca", "root.crt")
    result = verify_url(args.url, root)
    print(result.report())
    sys.exit(0 if result.trusted else 2)


def main(argv=None):
    p = argparse.ArgumentParser(description="HCMUT Internal PKI - X.509 CA with CRL/OCSP")
    p.add_argument("--data-dir", default="pki_data", help="CA data directory (default: pki_data)")
    p.add_argument("--mssv", default=None, help="Comma-separated MSSVs (default: team MSSVs)")
    p.add_argument("--ca-host", default=DEFAULT_CA_HOST, help="Host embedded in CDP/AIA URLs")
    p.add_argument("--ca-port", type=int, default=DEFAULT_CA_PORT, help="CA service port")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="Create Root CA + Issuing CA")
    s.add_argument("--force", action="store_true", help="Overwrite an existing CA")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("issue", help="Generate server key + CSR and issue a TLS certificate")
    s.add_argument("--cn", default="localhost")
    s.add_argument("--san", default="DNS:localhost,IP:127.0.0.1", help="e.g. DNS:localhost,IP:127.0.0.1")
    s.add_argument("--days", type=int, default=365)
    s.add_argument("--name", default="web", help="Server profile directory name")
    s.add_argument("--via-api", action="store_true", help="Submit CSR to the running CA service")
    s.set_defaults(func=cmd_issue)

    s = sub.add_parser("revoke", help="Revoke a certificate and publish a new CRL")
    s.add_argument("--serial", required=True, help="Serial number in hex")
    s.add_argument("--reason", default="unspecified", choices=list(REASONS))
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("list", help="List issued certificates")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("gen-crl", help="Re-publish Root and Issuing CRLs")
    s.set_defaults(func=cmd_gen_crl)

    s = sub.add_parser("serve-ca", help="Run CA repository / CRL / OCSP / admin API")
    s.set_defaults(func=cmd_serve_ca)

    s = sub.add_parser("serve-https", help="Run the demo HTTPS web server")
    s.add_argument("--name", default="web")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=DEFAULT_HTTPS_PORT)
    s.set_defaults(func=cmd_serve_https)

    s = sub.add_parser("verify", help="Authenticate an HTTPS server (chain + CRL + OCSP + TLS)")
    s.add_argument("url")
    s.add_argument("--root", default=None, help="Trusted root PEM (default: <data-dir>/ca/root.crt)")
    s.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except CAError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
