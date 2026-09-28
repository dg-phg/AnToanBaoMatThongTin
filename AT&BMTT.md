# BÀI TẬP AN TOÀN VÀ BẢO MẬT THÔNG TIN 
## Thông tin sinh viên:
+ **Họ và tên:** Dương Thị Anh Phương
+ **Mã sinh viên:** K235480106056
+ **Lớp:** K235480106056
+ **Trường:** Đại học Kỹ thuật Công nghiệp Thái Nguyên
---

## PHẦN 1: TÌM HIỂU THUẬT TOÁN MÃ HÓA HIỆN ĐẠI DES VÀ AES

Mã hóa đối xứng (Symmetric Encryption) là phương pháp sử dụng **cùng một khóa (secret key)** cho cả hai quá trình mã hóa (Encryption) và giải mã (Decryption). 

### 1. Thuật toán DES (Data Encryption Standard)
DES là một trong những thuật toán mã hóa khối (block cipher) đời đầu, được IBM phát triển và NIST công nhận vào năm 1977.

*   **Cấu trúc:** Sử dụng mạng Feistel (Feistel Network).
*   **Đặc điểm:** 
    *   Kích thước khối dữ liệu (Block size): 64-bit.
    *   Độ dài khóa (Key size): 64-bit, nhưng 8 bit được dùng để kiểm tra chẵn lẻ (parity), nên khóa thực tế chỉ dài **56-bit**.
    *   Số vòng lặp (Rounds): 16 vòng.
*   **Quy trình mã hóa:**
    1.  Dữ liệu đầu vào (64-bit) đi qua phép hoán vị khởi tạo (Initial Permutation - IP).
    2.  Chia khối dữ liệu thành 2 nửa: Trái ($L_0$) và Phải ($R_0$), mỗi nửa 32-bit.
    3.  Trải qua 16 vòng lặp. Tại mỗi vòng, nửa Phải được mở rộng, kết hợp với khóa con (sub-key) bằng phép XOR, đi qua hộp thay thế (S-box) để nén lại, sau đó hoán vị và XOR với nửa Trái. Nửa Trái và nửa Phải sau đó sẽ đổi chỗ cho nhau.
    4.  Đảo ngược của phép hoán vị khởi tạo (Final Permutation - $IP^{-1}$) để tạo ra bản mã (Ciphertext).
*   **Quy trình giải mã:** Diễn ra hoàn toàn tương tự, nhưng các khóa con được sử dụng theo thứ tự ngược lại (từ khóa 16 ngược về khóa 1).
*   **Nhược điểm:** Khóa 56-bit quá ngắn so với năng lực tính toán hiện đại. DES hiện nay đã bị phá vỡ hoàn toàn bởi phương pháp tấn công vét cạn (Brute-force) và không còn an toàn.

### 2. Thuật toán AES (Advanced Encryption Standard)
AES được ra đời để thay thế DES, là tiêu chuẩn mã hóa được chính phủ Hoa Kỳ áp dụng từ năm 2001. Khác với DES, AES sử dụng mạng Thay thế - Hoán vị (Substitution-Permutation Network - SPN).

*   **Đặc điểm:**
    *   Kích thước khối dữ liệu: Cố định **128-bit**.
    *   Độ dài khóa: Hỗ trợ 3 độ dài **128-bit, 192-bit, 256-bit**.
    *   Số vòng lặp (Rounds): Tương ứng với độ dài khóa là **10, 12, hoặc 14 vòng**.
*   **Quy trình mã hóa:** Dữ liệu 128-bit được biểu diễn dưới dạng ma trận trạng thái (State) kích thước 4x4. Quá trình gồm:
    1.  **KeyExpansion:** Mở rộng khóa bí mật ban đầu thành nhiều khóa con (Round keys).
    2.  **AddRoundKey (Vòng khởi tạo):** Kết hợp ma trận trạng thái với khóa con đầu tiên (XOR).
    3.  **Các vòng lặp chính (9, 11 hoặc 13 vòng) gồm 4 bước:**
        *   `SubBytes`: Thay thế từng byte dữ liệu dựa trên bảng tra cứu (S-box) để tạo tính phi tuyến.
        *   `ShiftRows`: Dịch vòng các hàng của ma trận trạng thái (hàng 1 giữ nguyên, hàng 2 dịch 1 byte, hàng 3 dịch 2 byte...).
        *   `MixColumns`: Trộn dữ liệu theo từng cột bằng các phép toán ma trận để tăng độ khuếch tán.
        *   `AddRoundKey`: XOR ma trận trạng thái với khóa con của vòng hiện tại.
    4.  **Vòng cuối cùng:** Thực hiện `SubBytes`, `ShiftRows` và `AddRoundKey` (bỏ qua bước `MixColumns`).
*   **Quy trình giải mã:** Áp dụng các hàm ngược: `InvShiftRows`, `InvSubBytes`, `InvMixColumns` và sử dụng các khóa con theo thứ tự ngược lại.

### 3. Cài đặt thuật toán AES (Sử dụng Python)
Thuật toán (File baitap1.py)

Dưới đây là mã nguồn Python triển khai thuật toán mã hóa đối xứng AES (chế độ CBC) và mã hóa bất đối xứng RSA, kết hợp đo thời gian thực thi của cả hai thuật toán:

``` python
import os
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# 1. HAM MA HOA / GIAI MA AES
def aes_encrypt(plaintext: str, key: bytes):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv + ciphertext

def aes_decrypt(ciphertext_with_iv: bytes, key: bytes):
    iv = ciphertext_with_iv[:16]
    actual_ciphertext = ciphertext_with_iv[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted_padded, AES.block_size).decode('utf-8')

# 2. CHAY CHUONG TRINH BAI TAP
if __name__ == "__main__":
    message = "Bai tap An toan va bao mat thong tin"
    
    # AES
    aes_key = os.urandom(32)
    start_aes = time.time()
    aes_cipher = aes_encrypt(message, aes_key)
    aes_plain = aes_decrypt(aes_cipher, aes_key)
    time_aes = time.time() - start_aes
    
    print("--- MA HOA AES ---")
    print("Ban ro:", message)
    print("Ban ma:", aes_cipher.hex()[:40], "...")
    print("Giai ma:", aes_plain)
    print(f"Thoi gian AES: {time_aes:.6f} giay\n")

    # RSA
    key = RSA.generate(2048)
    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    decrypt_rsa = PKCS1_OAEP.new(key)
    
    start_rsa = time.time()
    rsa_cipher = cipher_rsa.encrypt(message.encode('utf-8'))
    rsa_plain = decrypt_rsa.decrypt(rsa_cipher).decode('utf-8')
    time_rsa = time.time() - start_rsa
    
    print("--- MA HOA RSA ---")
    print("Ban ma RSA:", rsa_cipher.hex()[:40], "...")
    print("Giai ma RSA:", rsa_plain)
    print(f"Thoi gian RSA: {time_rsa:.6f} giay")
```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/90649adf-8056-4033-b619-fda992f5c05f" />

--- 


## Phần 2. Tìm hiểu thuật toán mã hóa bất đối xứng RSA

RSA (viết tắt của Rivest, Shamir, Adleman) là nền tảng của hệ mật mã khóa bất đối xứng (Public-Key Cryptography). Phương pháp này sử dụng một **cặp khóa** có quan hệ toán học chặt chẽ với nhau:
*   **Khóa công khai (Public Key):** Được chia sẻ công khai cho tất cả mọi người, dùng để mã hóa dữ liệu hoặc kiểm chứng chữ ký.
*   **Khóa bí mật (Private Key):** Phải được người sở hữu giữ an toàn tuyệt đối, dùng để giải mã dữ liệu hoặc tạo chữ ký số.

---

### Nguyên lý sinh cặp khóa (Key Generation)

Tính bảo mật của thuật toán RSA dựa trên độ khó của bài toán phân tích một số nguyên cực lớn thành tích của hai số nguyên tố. Các bước sinh cặp khóa diễn ra như sau:

1. **Chọn số nguyên tố:** Chọn ngẫu nhiên 2 số nguyên tố độc lập và có giá trị rất lớn là $p$ và $q$.
2. **Tính Modulus ($n$):** Tính $n = p \times q$. Giá trị $n$ này được dùng làm module cho cả Khóa công khai và Khóa bí mật (độ dài bit của $n$ phổ biến hiện nay là 2048-bit hoặc 4096-bit).
3. **Tính hàm số phi Euler ($\phi(n)$):** Tính $\phi(n) = (p - 1) \times (q - 1)$.
4. **Chọn số mũ công khai ($e$):** Chọn một số nguyên $e$ thỏa mãn hai điều kiện: $1 < e < \phi(n)$ và $\text{UCLN}(e, \phi(n)) = 1$. Số $e$ thường chọn là $65537$.
5. **Tính số mũ bí mật ($d$):** Tính $d$ là nghịch đảo modulo của $e$ theo module $\phi(n)$, thỏa mãn: $(d \times e) \pmod{\phi(n)} = 1$.

**Kết quả cặp khóa thu được:**
*   **Khóa công khai (Public Key - PU):** Bao gồm cặp số $(e, n)$.
*   **Khóa bí mật (Private Key - PR):** Bao gồm cặp số $(d, n)$.

> **SƠ ĐỒ TÓM TẮT SINH KHÓA RSA:**
> 
> $$p, q \xrightarrow{\text{Nhân}} n = p \times q \xrightarrow{\text{Euler}} \phi(n) = (p-1)(q-1)$$
> $$\downarrow$$
> $$\text{Chọn } e \text{ thỏa mãn } \text{UCLN}(e, \phi(n))=1 \xrightarrow{\text{Modulo nghịch đảo}} d \cdot e \equiv 1 \pmod{\phi(n)}$$
> $$\downarrow$$
> $$\text{Public Key: } (e, n) \quad \vert{} \quad \text{Private Key: } (d, n)$$



---

## Phần 3. Các mô hình áp dụng RSA và Sự kết hợp với AES

### 3.1. Các mô hình áp dụng thuật toán RSA
Do cấu trúc có hai khóa hoạt động chéo (khóa này mã hóa thì khóa kia giải mã), RSA được ứng dụng trong 3 mô hình chính:

*   **Mô hình 1: Xác thực người nhận (Bảo mật thông điệp)**
    *   *Mục đích:* Đảm bảo chỉ người nhận đích danh mới đọc được dữ liệu (Tính bảo mật).
    *   *Quy trình:* Người gửi sử dụng **Khóa công khai của Người nhận** để mã hóa thông điệp. Khi nhận được bản mã, Người nhận sử dụng **Khóa bí mật của chính mình** để giải mã.
*   **Mô hình 2: Xác thực người gửi (Chữ ký số - Digital Signature)**
    *   *Mục đích:* Đảm bảo tính toàn vẹn của dữ liệu và chống chối bỏ (người nhận biết chắc chắn ai đã gửi).
    *   *Quy trình:* Người gửi tạo mã băm (Hash) của tài liệu, sau đó dùng **Khóa bí mật của Người gửi** để ký (mã hóa) mã băm đó. Người nhận sử dụng **Khóa công khai của Người gửi** để giải mã đối chiếu mã băm, từ đó xác minh nguồn gốc.
  
*   **Mô hình 3: Kết hợp xác thực cả hai**
    *   *Quy trình:* Người gửi ký lên tài liệu bằng **Khóa bí mật của mình**, sau đó mã hóa toàn bộ bằng **Khóa công khai của người nhận**. Mô hình này đảm bảo cả tính bảo mật tuyệt đối lẫn tính xác thực nguồn gốc.

### 3.2. So sánh hiệu năng giữa RSA và AES

| Đặc điểm | AES (Mã hóa đối xứng) | RSA (Mã hóa bất đối xứng) |
| :--- | :--- | :--- |
| **Bản chất tính toán** | Các phép biến đổi ma trận, dịch bit, XOR. | Phép toán lũy thừa với số nguyên cực lớn. |
| **Thời gian thực thi** | Rất nhanh (nhanh hơn RSA hàng nghìn lần). | Rất chậm, tiêu tốn nhiều tài nguyên CPU. |
| **Chiều dài khóa** | Ngắn (128, 192, 256 bits). | Rất dài (2048, 3072, 4096 bits). |
| **Ứng dụng tối ưu** | Mã hóa khối lượng dữ liệu lớn (File, Video, Database). | Phân phối khóa, Ký điện tử, Chứng chỉ SSL/TLS. |
| **Vấn đề tồn đọng** | Khó phân phối khóa an toàn qua Internet. | Tốc độ quá chậm để mã hóa dữ liệu thực tế. |

### 3.3. Mô hình kết hợp sức mạnh (Hybrid Encryption / Phong bì số)
Để giải quyết nhược điểm phân phối khóa của AES và nhược điểm tốc độ chậm của RSA, các hệ thống thực tế (HTTPS, PGP) sử dụng mô hình kết hợp gọi là Phong bì số (Digital Envelope):

1.  **Mã hóa Dữ liệu (Bằng AES):** Máy tính người gửi sinh ra một khóa phiên (Session Key) ngẫu nhiên bằng AES. Sử dụng khóa AES này để mã hóa toàn bộ file dữ liệu lớn cực kỳ nhanh chóng.
2.  **Mã hóa Khóa (Bằng RSA):** Dùng **Khóa công khai RSA** của người nhận để mã hóa chính cái "Khóa phiên AES" vừa sinh ra.
3.  **Truyền tải:** Gửi cả [Dữ liệu đã mã hóa bằng AES] và [Khóa AES đã mã hóa bằng RSA] qua mạng.
4.  **Giải mã:** Người nhận dùng **Khóa bí mật RSA** của mình để mở ra "Khóa phiên AES". Sau đó dùng "Khóa phiên AES" này để giải mã khối dữ liệu lớn.
   
<img width="1408" height="768" alt="ma_hoa_ket_hop" src="https://github.com/user-attachments/assets/e7e5977a-2fab-4d3b-a77f-55c52f268187" />

*HÌNH: Sơ đồ quy trình Hệ thống mã hóa kết hợp Hybrid Encryption*
