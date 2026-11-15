#!/usr/bin/env bash
# Kịch bản demo phần 1.2 - đối chứng CA nội bộ bằng công cụ độc lập (openssl, curl).
# Chạy từ thư mục gốc dự án:  bash srcs/tests/pki_demo.sh
set -u
cd "$(dirname "$0")/../.."

PY="${PYTHON:-python3}"
[ -x .venv/bin/python ] && PY=.venv/bin/python
D="${PKI_DEMO_DIR:-pki_demo_data}"
CA_PORT="${CA_PORT:-8080}"
WEB_PORT="${WEB_PORT:-8443}"
PKI="$PY -m srcs.pki.cli --data-dir $D --ca-port $CA_PORT"
CA_PID=""; WEB_PID=""

cleanup() { [ -n "$CA_PID" ] && kill "$CA_PID" 2>/dev/null; [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null; }
trap cleanup EXIT
step() { echo; echo "================ $* ================"; }
ossl_verify() {
  openssl verify -CAfile "$D/ca/root.crt" -untrusted "$D/ca/issuing.crt" -crl_check_all \
    -CRLfile "$D/crl/root.crl.pem" -CRLfile "$D/crl/issuing.crl.pem" "$D/server/web/server.crt"
}
ossl_ocsp() {
  openssl ocsp -issuer "$D/ca/issuing.crt" -cert "$D/server/web/server.crt" \
    -url "http://127.0.0.1:$CA_PORT/ocsp" -CAfile "$D/ca/root.crt" 2>&1 | head -4
}

step "1. Khởi tạo Root CA + Issuing CA"
rm -rf "$D"
$PKI init || exit 1
openssl x509 -in "$D/ca/root.crt" -noout -subject -issuer -nameopt utf8,sep_multiline

step "2. Chạy dịch vụ CA (repository + CRL + OCSP) trên :$CA_PORT"
$PKI serve-ca > "$D.ca.log" 2>&1 & CA_PID=$!
sleep 1.5

step "3. Web Server sinh CSR, gửi lên CA qua API, nhận chứng thư"
$PKI issue --via-api --cn localhost --san DNS:localhost,IP:127.0.0.1 || exit 1
openssl x509 -in "$D/server/web/server.crt" -noout -text -nameopt utf8 \
  | grep -E "Subject:|Issuer:|Not After|DNS:|OCSP|URI|CA:"

step "4. Chạy Web Server HTTPS trên :$WEB_PORT"
$PKI serve-https --port "$WEB_PORT" > "$D.web.log" 2>&1 & WEB_PID=$!
sleep 1.5

step "5. Xác thực khi chứng thư còn hiệu lực"
$PKI verify "https://localhost:$WEB_PORT"
echo "--- openssl verify (CRL):"; ossl_verify
echo "--- openssl ocsp:";          ossl_ocsp
echo "--- curl --cacert root.crt:"; curl -s --cacert "$D/ca/root.crt" "https://localhost:$WEB_PORT" | head -c 120; echo
echo "--- curl không tin cậy Root (mặc định hệ thống):"; curl -s -o /dev/null "https://localhost:$WEB_PORT" || echo "curl từ chối (exit=$?) - đúng như mong đợi"

step "6. Thu hồi chứng thư (keyCompromise)"
SERIAL=$(openssl x509 -in "$D/server/web/server.crt" -noout -serial | cut -d= -f2)
$PKI revoke --serial "$SERIAL" --reason keyCompromise
openssl crl -in "$D/crl/issuing.crl.pem" -noout -text | grep -E "CRL Number|Serial Number|keyCompromise" -A1

step "7. Xác thực lại sau khi thu hồi"
$PKI verify "https://localhost:$WEB_PORT"
echo "--- openssl verify (CRL):"; ossl_verify
echo "--- openssl ocsp:";          ossl_ocsp

step "8. Danh sách chứng thư trong CSDL của CA"
$PKI list
