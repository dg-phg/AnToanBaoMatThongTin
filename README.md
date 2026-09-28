# BÀI TẬP AN TOÀN VÀ BẢO MẬT THÔNG TIN 
## Thông tin sinh viên:
+ **Họ và tên:** Dương Thị Anh Phương
+ **Mã sinh viên:** K235480106056
+ **Lớp:** K235480106056
+ **Trường:** Đại học Kỹ thuật Công nghiệp Thái Nguyên
---
## 1. Tìm hiểu thuật toán mã hóa hiện đại DES và AES

### Thuật toán DES (Data Encryption Standard)
- **Tổng quan:** DES là thuật toán mã hóa khối đối xứng được phát triển bởi IBM. Nó thao tác trên các khối dữ liệu có kích thước 64-bit và sử dụng một khóa 56-bit (thực chất khóa dài 64-bit nhưng 8 bit được dùng để kiểm tra chẵn lẻ).
- **Quy trình mã hóa/giải mã:** 
  - **Khởi tạo:** Khối bản rõ 64-bit ban đầu đi qua một phép hoán vị khởi tạo (Initial Permutation - IP).
  - **16 vòng lặp Feistel:** Dữ liệu sau đó được chia làm 2 nửa (Trái - L, Phải - R) mỗi nửa 32-bit. Thuật toán sẽ trải qua 16 vòng biến đổi (Round). Trong mỗi vòng, nửa phải được mở rộng lên 48-bit, XOR với khóa con 48-bit của vòng đó, đi qua các hộp S-Box để nén lại thành 32-bit, qua hộp hoán vị P-Box, và cuối cùng XOR với nửa trái.
  - **Kết thúc:** Sau 16 vòng, hai nửa được ghép lại và đi qua phép hoán vị nghịch đảo ($IP^{-1}$) để tạo ra bản mã (Ciphertext).
  - **Giải mã:** Diễn ra hoàn toàn tương tự nhưng thứ tự sử dụng các khóa con bị đảo ngược (từ $K_{16}$ về $K_1$).

### Thuật toán AES (Advanced Encryption Standard)
- **Tổng quan:** AES là tiêu chuẩn mã hóa tiên tiến hơn, được thiết kế để thay thế DES (vốn đã bị phá vỡ bởi các cuộc tấn công Brute-force do độ dài khóa quá ngắn). AES mã hóa các khối dữ liệu 128-bit và hỗ trợ ba độ dài khóa: 128-bit (10 vòng), 192-bit (12 vòng), và 256-bit (14 vòng).
- **Quy trình mã hóa:** Không sử dụng mạng Feistel như DES, AES sử dụng mạng thay thế-hoán vị (SPN - Substitution-Permutation Network) và thao tác trên một ma trận trạng thái (State matrix) $4 \times 4$. Mỗi vòng lặp của AES (ngoại trừ vòng cuối) bao gồm 4 bước chính:
  1. **SubBytes:** Thay thế phi tuyến tính các byte dữ liệu sử dụng một bảng tra cứu (S-Box) cố định, giúp chống lại các cuộc tấn công phân tích.
  2. **ShiftRows:** Dịch vòng các byte trên mỗi hàng của ma trận trạng thái, giúp xáo trộn dữ liệu.
  3. **MixColumns:** Trộn tuyến tính các cột của ma trận (sử dụng phép nhân ma trận trên trường Galois GF($2^8$)), tạo ra hiệu ứng khuếch tán cao.
  4. **AddRoundKey:** XOR ma trận trạng thái hiện tại với khóa con (Round Key) được sinh ra từ khóa chính.
- **Giải mã:** Sử dụng các hàm ngược lại theo thứ tự ngược: Inverse ShiftRows, Inverse SubBytes, AddRoundKey, và Inverse MixColumns.
- **Cài đặt:** Trong dự án này, AES được cài đặt bằng ngôn ngữ **Python** thông qua thư viện `pycryptodome` (sử dụng chế độ CBC với IV ngẫu nhiên) tại file `baitap1.py`.

---

## 2. Tìm hiểu thuật toán mã hóa bất đối xứng RSA

### Tổng quan
RSA (Rivest–Shamir–Adleman) là hệ mật mã khóa bất đối xứng phổ biến nhất hiện nay. Nó dựa trên một tính chất toán học quan trọng: *Rất dễ để nhân hai số nguyên tố lớn với nhau, nhưng cực kỳ khó (mất thời gian phi thực tế) để phân tích tích của chúng ngược lại thành hai thừa số nguyên tố đó.*

### Nguyên lý sinh cặp khóa (Bí mật & Công khai)
Để tạo ra một cặp khóa RSA, quy trình gồm các bước sau:
1. **Chọn số nguyên tố:** Chọn ngẫu nhiên 2 số nguyên tố rất lớn là $p$ và $q$.
2. **Tính n:** Tính $n = p \times q$. Số $n$ này sẽ được dùng làm module cho cả khóa công khai và khóa bí mật.
3. **Tính hàm số Euler $\phi(n)$:** $\phi(n) = (p - 1) \times (q - 1)$.
4. **Chọn khóa công khai (e):** Chọn một số nguyên $e$ thỏa mãn 2 điều kiện: $1 < e < \phi(n)$ và $e$ nguyên tố cùng nhau với $\phi(n)$ (nghĩa là ƯCLN($e, \phi(n)$) = 1).
5. **Tính khóa bí mật (d):** Tính $d$ là nghịch đảo modulo của $e$ theo modulo $\phi(n)$. Nghĩa là $(d \times e) \pmod{\phi(n)} = 1$.
6. **Kết quả cặp khóa:**
   - **Khóa công khai (Public Key - PU):** Bao gồm cặp số $(e, n)$. Khóa này được phân phối rộng rãi cho mọi người.
   - **Khóa bí mật (Private Key - PR):** Bao gồm cặp số $(d, n)$. Khóa này phải được giữ kín tuyệt đối bởi chủ sở hữu.

---

## 3. Các mô hình áp dụng RSA và Tối ưu hóa

### Các mô hình áp dụng RSA
Do có hai khóa (Public và Private) có thể mã hóa/giải mã chéo cho nhau, RSA được ứng dụng trong 3 mô hình chính:
1. **Mô hình xác thực người nhận (Bảo mật thông điệp):**
   - *Cách hoạt động:* Người gửi (A) sử dụng **Khóa công khai của người nhận (# BÁO CÁO MẬT MÃ HỌC CƠ BẢN: DES, AES VÀ RSA

Tài liệu này trình bày chi tiết về các thuật toán mã hóa đối xứng (DES, AES), thuật toán bất đối xứng (RSA), cách ứng dụng, so sánh và mô hình kết hợp sức mạnh của chúng. 

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

Dưới đây là mã nguồn Python sử dụng thư viện `pycryptodome` để mô phỏng quá trình mã hóa/giải mã AES với chế độ CBC (Cipher Block Chaining).

```python
# Yêu cầu cài đặt thư viện: pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(plaintext, key):
    # Khởi tạo vector iv ngẫu nhiên (16 bytes)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad dữ liệu để chia hết cho block_size (16 bytes)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Trả về chuỗi base64 của (IV + Ciphertext) để dễ lưu trữ
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(encrypted_data_b64, key):
    raw_data = base64.b64decode(encrypted_data_b64)
    # Tách IV (16 bytes đầu) và Ciphertext (phần còn lại)
    iv = raw_data[:AES.block_size]
    ciphertext = raw_data[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Loại bỏ padding để lấy dữ liệu gốc
    return unpad(padded_plaintext, AES.block_size).decode('utf-8')

if __name__ == "__main__":
    # Khóa AES (16 bytes = 128 bits, hoặc dùng 32 bytes = 256 bits)
    SECRET_KEY = b'16bytesecretkey!' 
    
    message = "Đây là thông điệp bí mật cần bảo vệ."
    print(f"[*] Original Message: {message}")
    
    # Mã hóa
    encrypted_msg = aes_encrypt(message, SECRET_KEY)
    print(f"[*] Encrypted (Base64): {encrypted_msg}")
    
    # Giải mã
    decrypted_msg = aes_decrypt(encrypted_msg, SECRET_KEY)
    print(f"[*] Decrypted Message: {decrypted_msg}")
```

--- 


## Phần 2. Tìm hiểu thuật toán mã hóa bất đối xứng RSA

RSA (viết tắt của Rivest, Shamir, Adleman) là nền tảng của hệ mật mã khóa bất đối xứng (Public-Key Cryptography). Phương pháp này sử dụng một **cặp khóa** có quan hệ toán học chặt chẽ với nhau:
*   **Khóa công khai (Public Key):** Được chia sẻ công khai cho tất cả mọi người, dùng để mã hóa dữ liệu hoặc kiểm chứng chữ ký.
*   **Khóa bí mật (Private Key):** Phải được người sở hữu giữ an toàn tuyệt đối, dùng để giải mã dữ liệu hoặc tạo chữ ký số.

*[Chèn Ảnh: HÌNH 1 - Minh họa khái niệm Ổ khóa (Public Key) và Chìa khóa (Private Key) trong hệ thống bất đối xứng]*

### Nguyên lý sinh cặp khóa (Key Generation)
Tính bảo mật của thuật toán RSA dựa trên độ khó của bài toán phân tích một số nguyên cực lớn thành tích của hai số nguyên tố. Các bước sinh cặp khóa diễn ra như sau:

1.  **Chọn số nguyên tố:** Chọn ngẫu nhiên 2 số nguyên tố độc lập và có giá trị rất lớn là $p$ và $q$.
2.  **Tính Modulus ($n$):** Tính $n = p \times q$. Giá trị $n$ này sẽ được sử dụng làm module cho cả Khóa công khai và Khóa bí mật. (Độ dài tính bằng bit của $n$ chính là độ dài khóa RSA, phổ biến hiện nay là 2048-bit hoặc 4096-bit).
3.  **Tính hàm số phi Euler ($\phi(n)$):** Tính $\phi(n) = (p - 1) \times (q - 1)$.
4.  **Chọn số mũ công khai ($e$):** Chọn một số nguyên $e$ thỏa mãn hai điều kiện: $1 < e < \phi(n)$ và $e$ nguyên tố cùng nhau với $\phi(n)$ (tức là $UCLN(e, \phi(n)) = 1$). Số $e$ thường được chọn là 65537 để tăng tốc độ mã hóa.
5.  **Tính số mũ bí mật ($d$):** Tính $d$ là nghịch đảo modulo của $e$ theo module $\phi(n)$. Công thức: $(d \times e) \pmod{\phi(n)} = 1$.

**Kết quả cặp khóa thu được:**
*   **Khóa công khai (PU):** Bao gồm cặp số $(e, n)$.
*   **Khóa bí mật (PR):** Bao gồm cặp số $(d, n)$.

*[Chèn Ảnh: HÌNH 2 - Sơ đồ các bước toán học sinh khóa RSA (Từ p, q tính ra n, $\phi(n)$, e và d)]*

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
    
    *[Chèn Ảnh: HÌNH 3 - Sơ đồ quy trình tạo và xác minh Chữ ký số (Digital Signature) bằng RSA]*

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

*[Chèn Ảnh: HÌNH 4 - Sơ đồ quy trình Hệ thống mã hóa kết hợp Hybrid Encryption (Dùng AES bọc dữ liệu, dùng RSA bọc khóa AES)]*
