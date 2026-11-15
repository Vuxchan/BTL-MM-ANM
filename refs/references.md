# TÀI LIỆU THAM KHẢO VÀ TIÊU CHUẨN MẬT MÃ (REFERENCES)

Dưới đây là danh mục các tiêu chuẩn mật mã học quốc tế, RFC và tài liệu tham khảo được áp dụng trong hiện thực Phần 1.1:

## 1. Tiêu chuẩn Hàm dẫn xuất khóa (KDF)
- **RFC 5869:** *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
  - Tác giả: H. Krawczyk, P. Eronen (2010).
  - Ứng dụng trong hệ thống: Dẫn xuất khóa phiên $K_{\text{session}}$ 256-bit từ ECDHE Shared Secret và muối khởi tạo $K_{\text{init}} = \text{SHA256}(\text{MSSV}_1 \parallel \text{MSSV}_2 \dots)$.

## 2. Tiêu chuẩn Trao đổi Khóa Bất đối xứng (PFS)
- **RFC 7748:** *Elliptic Curves for Security (Curve25519 & X25519)*.
  - Tác giả: A. Langley, M. Hamburg, S. Turner (2016).
  - Ứng dụng trong hệ thống: Thực hiện thuật toán trao đổi khóa Diffie-Hellman trên đường cong elliptic (ECDHE) nhằm mang lại tính bí mật chuyển giao hoàn hảo (Perfect Forward Secrecy - PFS) với hiệu năng tính toán vượt trội so với RSA truyền thống.
- **RFC 8446:** *The Transport Layer Security (TLS) Protocol Version 1.3*.
  - Tác giả: E. Rescorla (2018).
  - Ứng dụng trong hệ thống: Mô hình bắt tay trao đổi khóa ephemeral kết hợp chữ ký số danh tính.

## 3. Tiêu chuẩn Mã hóa Đối xứng Xác thực (AEAD)
- **NIST Special Publication 800-38D:** *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
  - Tác giả: Morris Dworkin (NIST - 2007).
  - Ứng dụng trong hệ thống: Mã hóa dữ liệu tin nhắn văn bản và từng khối tệp tin (64KB chunks) bằng AES-256-GCM. Đảm bảo đồng thời tính Bí mật (Confidentiality via Counter Mode) và tính Toàn vẹn / Chống giả mạo (Integrity & Authenticity via Galois MAC 128-bit Tag).

## 4. Tiêu chuẩn Chữ ký Số và Xác thực Danh tính (Anti-MitM)
- **RFC 8017:** *PKCS #1: RSA Cryptography Specifications Version 2.2*.
  - Tác giả: K. Moriarty, B. Kaliski, J. Jonsson, A. Rusch (2016).
  - Ứng dụng trong hệ thống: Chữ ký số RSA 2048-bit với cơ chế đệm PSS (Probabilistic Signature Scheme) và hàm băm SHA-256. Được ký trên thông điệp bắt tay chứa chuỗi MSSV và khóa công khai tạm thời để vô hiệu hóa hoàn toàn tấn công Man-in-the-Middle (MitM).

## 5. Thư viện Mã nguồn Mở
- **Python Cryptography Library (`cryptography`):**
  - Giấy phép: Apache License 2.0 / BSD License.
  - Trang chủ: https://cryptography.io/
  - Sử dụng OpenSSL backend, đảm bảo các nguyên thủy mật mã được tối ưu hóa ở mức C và phòng chống các dạng tấn công kênh bên (Side-channel / Timing attacks).

## 6. Tiêu chuẩn Hạ tầng Khóa công khai (Phần 1.2)
- **RFC 5280:** *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile* (D. Cooper et al., 2008).
  - Ứng dụng: định dạng chứng thư X.509 v3 (BasicConstraints, KeyUsage, EKU, SAN, SKI/AKI, CRL Distribution Points, AIA), CRL v2 (CRL Number, CRLReason) và thuật toán kiểm tra đường dẫn chứng thư.
- **RFC 6960:** *X.509 Internet PKI Online Certificate Status Protocol - OCSP* (S. Santesson et al., 2013).
  - Ứng dụng: OCSP Responder do Issuing CA ký, trả trạng thái good/revoked/unknown, hỗ trợ nonce chống phát lại; truy vấn qua HTTP POST/GET.
- **RFC 2986:** *PKCS #10: Certification Request Syntax Specification v1.7* (M. Nystrom, B. Kaliski, 2000).
  - Ứng dụng: Web Server gửi CSR ký bằng khóa riêng (chứng minh sở hữu khóa) để CA cấp chứng thư.
- **RFC 6125:** *Representation and Verification of Domain-Based Application Service Identity within PKIX Certificates in TLS* (2011).
  - Ứng dụng: kiểm tra hostname với Subject Alternative Name.
- **RFC 8446:** *TLS 1.3* — Web Server HTTPS demo dùng TLS ≥ 1.2 (thực tế bắt tay TLS 1.3).
- **OpenSSL 3.x** (`openssl verify`, `openssl ocsp`) và **curl** — dùng làm công cụ đối chứng độc lập trong `srcs/tests/pki_demo.sh`.
