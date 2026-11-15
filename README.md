# BÀI TẬP LỚN SỐ 1 - MẬT MÃ VÀ AN NINH MẠNG
## PHẦN 1.1: HỆ THỐNG CHAT VÀ TRUYỀN TỆP MÃ HÓA ĐẦU CUỐI (E2EE)

---

## 1. GIỚI THIỆU TỔNG QUAN

Dự án hiện thực hoàn chỉnh **Hệ thống Chat và Truyền tệp Mã hóa Đầu cuối (End-to-End Encrypted - E2EE)** theo mô hình Client-Server phục vụ đề tài Bài tập lớn số 1, môn Mật mã và An ninh mạng.

### Các đặc tính kỹ thuật cốt lõi:
- **Kiến trúc E2EE Zero-Knowledge:** Relay Server chỉ đóng vai trò chuyển tiếp các gói tin nhị phân/JSON có độ dài định trước. Server tuyệt đối **không sở hữu** khóa bí mật hay khóa phiên của Client, hoàn toàn không thể giải mã nội dung tin nhắn hay tệp tin trên đường truyền.
- **Tính bí mật chuyển giao hoàn hảo (Perfect Forward Secrecy - PFS):** Sử dụng thuật toán trao đổi khóa vi sai đường cong Elliptic tạm thời **ECDHE (Curve25519 / X25519 - RFC 7748)**. Mỗi phiên giao dịch sinh một cặp khóa ngẫu nhiên mới, việc thỏa hiệp khóa dài hạn trong tương lai không làm lộ các phiên trò chuyện trong quá khứ.
- **Mã hóa đối xứng xác thực AEAD (AES-256-GCM):** Mã hóa toàn bộ tin nhắn và từng khối tệp tin (64KB chunks) bằng khóa 256-bit, Nonce/IV ngẫu nhiên 96-bit duy nhất cho mỗi gói, kèm Tag xác thực GMAC 128-bit chống lại mọi hành vi can thiệp hay sửa đổi dữ liệu (Bit-flipping).
- **Chống tấn công Giả mạo & Nghe lén (Anti-MitM):** Xác thực định danh hai đầu bằng chữ ký số **RSA-PSS 2048-bit (SHA-256)** trên toàn bộ gói tin bắt tay (Handshake).
- **Tuân thủ 100% yêu cầu lồng ghép MSSV của đề bài:**
  1. **Plaintext Handshake:** Thông điệp bắt tay chứa chính xác chuỗi:
     `Hello, We are [MSSV_1], [MSSV_2], ..`
  2. **Dẫn xuất khóa khởi tạo (KDF):** Khóa muối khởi tạo được tính bằng mã băm SHA-256 nối chuỗi các MSSV:
     $$K_{\text{init}} = \text{SHA256}(\text{MSSV}_1 \parallel \text{MSSV}_2 \dots)$$
     Khóa phiên AES-256 được dẫn xuất qua **HKDF-SHA256** (RFC 5869) kết hợp $K_{\text{init}}$ và ECDHE Shared Secret $S$.

---

## 2. CẤU TRÚC THƯ MỤC NỘP BÀI

Tuân thủ đúng quy định tổ chức thư mục của môn học:

```text
Assignment1/
├── README.md               # Bản hướng dẫn chi tiết định dạng Markdown
├── srcs/                   # Toàn bộ mã nguồn chương trình
│   ├── crypto/             # Thư viện động cơ mật mã
│   │   ├── __init__.py
│   │   ├── kdf.py          # K_init từ MSSV & HKDF-SHA256
│   │   ├── asymmetric.py   # ECDHE X25519 & Chữ ký RSA-PSS 2048-bit
│   │   ├── symmetric.py    # AES-256-GCM AEAD Encrypt/Decrypt
│   │   └── identity.py     # Quản lý khóa định danh và lưu trữ khóa
│   ├── protocol/           # Giao thức truyền thông và định dạng gói tin
│   │   ├── __init__.py
│   │   ├── packet.py       # Cấu trúc gói tin JSON length-prefixed (4-byte)
│   │   └── handshake.py    # Đóng gói và xác minh Handshake chứa MSSV
│   ├── server/             # Máy chủ chuyển tiếp (Relay Server)
│   │   ├── __init__.py
│   │   └── relay_server.py # Multi-threaded TCP Relay Server (E2EE Zero-Knowledge)
│   ├── client/             # Phía máy trạm (Client)
│   │   ├── __init__.py
│   │   ├── client_core.py  # Logic mật mã, kết nối mạng và quản lý phiên E2EE
│   │   ├── gui_app.py      # Giao diện đồ họa Tkinter trực quan, thanh tra Ciphertext
│   │   └── cli_client.py   # Giao diện dòng lệnh CLI linh hoạt
│   ├── pki/                # PHẦN 1.2 - Hạ tầng khóa công khai nội bộ (X.509 CA)
│   │   ├── config.py       # Subject X.509 lồng ghép MSSV (CN/OU), URL CRL/OCSP
│   │   ├── ca.py           # Root CA + Issuing CA, cấp phát từ CSR, CSDL, thu hồi, CRL v2
│   │   ├── csr.py          # Sinh khóa + CSR PKCS#10 phía Web Server
│   │   ├── ocsp_responder.py # OCSP Responder (RFC 6960)
│   │   ├── ca_service.py   # Dịch vụ HTTP: phát hành chứng thư/CRL, OCSP, API quản trị
│   │   ├── https_server.py # Web Server HTTPS (TLS >= 1.2) dùng chứng thư do CA cấp
│   │   ├── verifier.py     # Client xác thực: chuỗi + hostname + CRL + OCSP + TLS
│   │   └── cli.py          # Giao diện dòng lệnh quản trị CA
│   └── tests/              # Kịch bản kiểm thử và giả lập tấn công MitM
│       ├── __init__.py
│       ├── test_crypto.py      # Unit test 100% các hàm mật mã
│       ├── test_e2ee_flow.py   # Test tự động toàn bộ luồng E2EE Chat + File
│       ├── test_mitm.py        # Test tự động 3 kịch bản tấn công MitM
│       ├── mitm_proxy.py       # Proxy trung gian giả lập tấn công MitM thực tế
│       ├── test_pki.py         # (1.2) Unit test CA, CRL, OCSP, Subject MSSV
│       ├── test_pki_scenarios.py # (1.2) 5 kịch bản xác thực HTTPS đầu-cuối
│       └── pki_demo.sh         # (1.2) Demo + đối chứng bằng openssl / curl
└── refs/                   # Tài liệu tham khảo, tiêu chuẩn RFC mật mã
   └── references.md       # Bảng đối chiếu RFC 5869, RFC 7748, NIST SP 800-38D...
```

---

## 3. CÀI ĐẶT MÔI TRƯỜNG

### Yêu cầu tiên quyết:
- Hệ điều hành: Windows, Linux hoặc macOS.
- Python 3.10 trở lên.
- Thư viện mật mã chuẩn `cryptography` và thư viện tạo báo cáo `python-docx`.

### Lệnh cài đặt:
```bash
# 1. Cài đặt thư viện Python:
pip install cryptography python-docx

# 2. Lưu ý đặc biệt cho Ubuntu / Debian / WSL:
# Mặc định Python trên Ubuntu/Debian/WSL tách riêng Tkinter, cần cài đặt thêm:
sudo apt update && sudo apt install -y python3-tk
```

---

## 4. HƯỚNG DẪN CHẠY VÀ SỬ DỤNG CHƯƠNG TRÌNH

### 4.1. Khởi động Relay Server
Mở một cửa sổ Terminal mới và chạy:
```bash
python3 -m srcs.server.relay_server --host 127.0.0.1 --port 9000
```
Server sẽ lắng nghe trên cổng 9000 và hiển thị log các gói tin được chuyển tiếp ở dạng bản mã (Ciphertext) mà server không thể giải mã.

---

### 4.2. Khởi động Giao diện đồ họa GUI (Khuyến nghị dùng để Demo)
Mở 2 cửa sổ Terminal khác nhau để mở 2 Client (ví dụ Client Alice và Client Bob):

**Cửa sổ 1 (Alice):**
```bash
python3 -m srcs.client.gui_app
```
- Nhập **Client ID**: `Alice`
- Nhập danh sách **MSSV**: `2313955, 2313593, 2311593, 2311681` (có thể tùy chỉnh theo MSSV nhóm)
- Nhấn nút **Connect to Server**.

**Cửa sổ 2 (Bob):**
```bash
python3 -m srcs.client.gui_app
```
- Nhập **Client ID**: `Bob`
- Nhập danh sách **MSSV**: `2313955, 2313593, 2311593, 2311681`
- Nhấn nút **Connect to Server**.

**Tiến hành Bắt tay & Chat E2EE:**
1. Trên cửa sổ Alice, danh sách **Online Peers** sẽ xuất hiện `Bob`. Nhấn chọn `Bob`.
2. Nhấn nút **Start ECDHE Handshake**.
3. Cả hai Client sẽ lập tức thực hiện quy trình bắt tay:
   - Trao đổi khóa vi sai X25519 có chữ ký số RSA-PSS.
   - Hiển thị thông điệp `Hello, We are [2313955], [2313593], [2311593], [2311681]`
   - Tính toán giá trị băm $K_{\text{init}}$ và suy dẫn khóa phiên AES-256.
4. Chuyển sang Tab **Handshake & Keys** trên giao diện để xem đầy đủ các thông số mật mã (Plaintext Greeting, $K_{\text{init}}$, Ephemeral PubKeys, Shared Secret, Session Key).
5. Quay lại Tab **Chat & E2EE View**:
   - Nhập tin nhắn và nhấn **Send (AES-GCM)**.
   - Hộp bên dưới (**Packet Inspector**) sẽ lập tức hiển thị dữ liệu thô Base64 của bản mã (Ciphertext), 12-byte Nonce và 16-byte GMAC Tag được truyền trên mạng.
6. **Truyền tệp mã hóa:**
   - Nhấn nút **Send File...** và chọn một tệp tin bất kỳ (ảnh, văn bản, tệp nén zip...).
   - Chương trình tự động chia tệp thành các khối 64KB, mã hóa từng khối bằng AES-256-GCM và truyền sang Bob.
   - Phía Bob sẽ tự động nhận, giải mã, kiểm tra tính toàn vẹn băm SHA-256 và lưu vào thư mục `received_files/`.

---

### 4.3. Sử dụng Giao diện dòng lệnh CLI (Nếu không dùng GUI)
Có thể chạy Client thông qua CLI:

**Client Alice:**
```bash
python3 -m srcs.client.cli_client --id Alice --peer Bob --mssv 2313955,2313593,2311593,2311681
```

**Client Bob:**
```bash
python3 -m srcs.client.cli_client --id Bob --peer Alice --mssv 2313955,2313593,2311593,2311681
```

Các lệnh trong CLI:
- `/handshake`: Bắt đầu quá trình bắt tay trao đổi khóa.
- `/msg <nội dung>`: Gửi tin nhắn mã hóa AES-256-GCM.
- `/file <đường_dẫn_file>`: Gửi tệp mã hóa phân đoạn 64KB.
- `/info`: Xem khóa khởi tạo $K_{\text{init}}$, Shared Secret và Session Key hiện tại.
- `/quit`: Thoát chương trình.

---

## 5. KỊCH BẢN THỬ NGHIỆM VÀ ĐÁNH GIÁ AN TOÀN TRƯỚC TẤN CÔNG MitM

Dự án cung cấp bộ công cụ giả lập và kiểm thử tự động chứng minh tính an toàn tuyệt đối của hệ thống trước 3 kịch bản tấn công:

### Chạy kiểm thử tự động toàn bộ 3 kịch bản:
```bash
python3 -m unittest srcs/tests/test_mitm.py
```

### Chi tiết 3 kịch bản kiểm thử:

1. **Kịch bản 1: Nghe lén thụ động (Passive Sniffing / Eavesdropping)**
   - *Hành vi tấn công:* Kẻ tấn công Mallory bắt các gói tin trên đường truyền qua Relay Server.
   - *Kết quả thực tế:* Toàn bộ nội dung tin nhắn và tệp tin đều là bản mã ngẫu nhiên cao (Ciphertext Base64), Nonce 96-bit và Tag 128-bit. Do không có khóa phiên AES-256, Mallory hoàn toàn không thể giải mã nội dung truyền tải.

2. **Kịch bản 2: Can thiệp tráo đổi khóa trong Handshake (Active MitM Key Replacement)**
   - *Hành vi tấn công:* Mallory can thiệp vào gói tin `HANDSHAKE_INIT`, thay thế khóa công khai tạm thời của Alice bằng khóa của Mallory nhằm đánh lừa Bob thiết lập khóa phiên với Mallory.
   - *Cơ chế phòng thủ:* Bob sử dụng khóa công khai danh tính RSA của Alice để xác minh chữ ký số RSA-PSS trên toàn bộ tải tin. Do Mallory không sở hữu khóa bí mật RSA của Alice, chữ ký số không khớp.
   - *Kết quả thực tế:* Bob phát hiện giả mạo ngay lập tức, phát cảnh báo `[SECURITY ALERT] Handshake signature verification failed (MitM detected)` và hủy kết nối an toàn.

3. **Kịch bản 3: Sửa đổi dữ liệu bản mã trên đường truyền (Active Ciphertext Bit-Flipping)**
   - *Hành vi tấn công:* Mallory sửa đổi dù chỉ 1 bit trong chuỗi bản mã của tin nhắn hoặc khối tệp tin khi đang truyền.
   - *Cơ chế phòng thủ:* Thuật toán AES-256-GCM sử dụng thẻ xác thực toàn vẹn GMAC 128-bit. Bất kỳ sự thay đổi nào đối với bản mã, nonce hoặc tiêu đề (AAD) đều làm cho việc tính toán lại GMAC Tag tại phía nhận bị sai lệch.
   - *Kết quả thực tế:* Hàm giải mã ném ngoại lệ `IntegrityVerificationError: Authentication Tag mismatch`, Bob ghi nhận cảnh báo dữ liệu bị can thiệp và từ chối hiển thị tin nhắn/loại bỏ khối tệp hỏng.

---

## 6. DANH MỤC LỆNH KIỂM THỬ ĐƠN VỊ (UNIT TESTS)

Để kiểm chứng tính đúng đắn và hiệu năng của từng thành phần:

1. **Kiểm thử động cơ mật mã:**
   ```bash
   python -m unittest srcs/tests/test_crypto.py
   ```
   *(Kiểm tra hàm băm $K_{\text{init}}$, trao đổi khóa ECDHE, chữ ký RSA-PSS, mã hóa/giải mã và kiểm tra lỗi Tag AES-256-GCM)*.

2. **Kiểm thử tích hợp luồng E2EE:**
   ```bash
   python -m unittest srcs/tests/test_e2ee_flow.py
   ```
   *(Tự động khởi chạy Server, 2 Client, bắt tay, chat và truyền tệp 150KB)*.

3. **Kiểm thử phòng vệ tấn công MitM:**
   ```bash
   python -m unittest srcs/tests/test_mitm.py
   ```

---



---

# PHẦN 1.2: TRIỂN KHAI HẠ TẦNG KHÓA CÔNG KHAI NỘI BỘ (INTERNAL PKI)

## 7. KIẾN TRÚC

Dịch vụ Cấp phát & Quản lý Chứng thư số (CA) theo chuẩn **X.509 v3 (RFC 5280)**, tích hợp kiểm tra thu hồi bằng **CRL v2** và **OCSP (RFC 6960)**, cấp chứng thư cho Web Server **HTTPS/TLS**.

```text
Root CA  CN=CA-Root-2313955-2313593-2311593-2311681  (RSA-4096, tự ký, pathlen=1)
   │  ký Issuing CA + Root CRL
   ▼
Issuing CA  CN=CA-Issuing-2313955-...  (RSA-2048, pathlen=0)
   │  ký chứng thư Web Server + Issuing CRL + phản hồi OCSP
   ▼
Web Server  CN=localhost  (RSA-2048, serverAuth, SAN DNS:localhost IP:127.0.0.1,
                           CDP → /crl/issuing.crl, AIA → /ocsp + /ca/issuing.crt)
```

**Lồng ghép MSSV vào X.509 Subject** (mọi chứng thư do CA cấp đều mang OU này):
- `CN = CA-Root-2313955-2313593-2311593-2311681`
- `OU = Faculty of Computer Science and Engineer – 2313955-2313593-2311593-2311681`

Đổi MSSV bằng tham số `--mssv 2312345,2367890` khi chạy `init`.

> Ghi chú: chuỗi OU được giữ nguyên văn theo đề (kể cả dấu gạch “–” U+2013, mã hóa UTF8String). Với 4 MSSV, OU dài 74 ký tự, vượt cận trên khuyến nghị 64 ký tự của RFC 5280 (`ub-organizational-unit-name`); OpenSSL, Python `ssl`/`cryptography` và curl đều chấp nhận (đã kiểm chứng).

**Dịch vụ CA (`serve-ca`, mặc định `http://127.0.0.1:8080`):**

| Endpoint | Chức năng |
|---|---|
| `GET /ca/root.crt`, `/ca/issuing.crt`, `/ca/chain.pem` | Phát hành chứng thư CA |
| `GET /crl/root.crl`, `/crl/issuing.crl` | CRL (DER), tự động tạo lại khi gần hết hạn |
| `POST /ocsp`, `GET /ocsp/<base64>` | OCSP Responder (good / revoked / unknown, có nonce) |
| `POST /api/issue` | Nộp CSR (PEM) → nhận chứng thư + chain (cần header `X-Admin-Token`) |
| `POST /api/revoke`, `GET /api/certs` | Thu hồi / liệt kê chứng thư (cần `X-Admin-Token`) |

Khóa riêng của CA được lưu mã hóa PKCS#8 (passphrase lấy từ biến môi trường `PKI_CA_PASSPHRASE`, mặc định `hcmut-pki-demo`); token quản trị lấy từ `PKI_ADMIN_TOKEN` (mặc định `hcmut-pki-admin`). Dữ liệu CA nằm trong `pki_data/` (`ca/`, `private/`, `crl/`, `issued/`, `index.json`).

## 8. HƯỚNG DẪN CHẠY

Mỗi lệnh dưới đây chạy từ thư mục gốc dự án; mở terminal riêng cho các tiến trình server.

```bash
# 1. Khởi tạo Root CA + Issuing CA
python3 -m srcs.pki.cli init

# 2. (Terminal 1) Chạy dịch vụ CA: phát hành chứng thư, CRL, OCSP
python3 -m srcs.pki.cli serve-ca

# 3. Web Server sinh khóa + CSR, gửi CSR lên CA qua API và nhận chứng thư
python3 -m srcs.pki.cli issue --via-api --cn localhost --san DNS:localhost,IP:127.0.0.1
#    (bỏ --via-api để CA ký trực tiếp, không cần serve-ca)

# 4. (Terminal 2) Chạy Web Server HTTPS bằng chứng thư vừa cấp
python3 -m srcs.pki.cli serve-https            # https://localhost:8443

# 5. Xác thực Web Server: chuỗi chứng thư + hostname + CRL + OCSP + bắt tay TLS
python3 -m srcs.pki.cli verify https://localhost:8443          # => TRUSTED
curl --cacert pki_data/ca/root.crt https://localhost:8443

# 6. Quản lý
python3 -m srcs.pki.cli list
python3 -m srcs.pki.cli revoke --serial <SERIAL_HEX> --reason keyCompromise
python3 -m srcs.pki.cli gen-crl
python3 -m srcs.pki.cli verify https://localhost:8443          # => REJECTED (CRL + OCSP)
```

Để trình duyệt tin cậy trang HTTPS, import `pki_data/ca/root.crt` vào kho Trusted Root của hệ điều hành/trình duyệt.

## 9. KỊCH BẢN THỬ NGHIỆM XÁC THỰC

```bash
python3 -m unittest srcs/tests/test_pki.py            # 12 unit test: Subject MSSV, extension, CSR, CRL, OCSP
python3 -m unittest srcs/tests/test_pki_scenarios.py  # 5 kịch bản HTTPS đầu-cuối
bash srcs/tests/pki_demo.sh                           # demo đầy đủ + đối chứng openssl/curl
```

| # | Kịch bản | Kết quả mong đợi |
|---|---|---|
| 1 | Chứng thư hợp lệ do CA nội bộ cấp | **TRUSTED**: chuỗi Leaf → Issuing → Root hợp lệ, không có trong CRL, OCSP = GOOD, bắt tay TLS 1.3 thành công |
| 2 | CA giả mạo có **cùng** DN `CA-Root-<MSSV>` cấp chứng thư cho localhost | **REJECTED** ở bước dựng chuỗi: chữ ký không khớp khóa công khai của Root tin cậy |
| 3 | Chứng thư bị thu hồi (`keyCompromise`) | **REJECTED**: serial xuất hiện trong CRL mới (CRL Number tăng), OCSP = REVOKED |
| 4 | Chứng thư hết hạn | **REJECTED**: không hợp lệ tại thời điểm kiểm tra |
| 5 | Chứng thư cấp cho `evil.example` nhưng phục vụ trên `localhost` | **REJECTED**: SAN không khớp hostname |

`pki_demo.sh` đối chứng độc lập bằng `openssl verify -crl_check_all`, `openssl ocsp` và `curl` trước và sau khi thu hồi (đổi cổng bằng biến `CA_PORT`, `WEB_PORT`).
