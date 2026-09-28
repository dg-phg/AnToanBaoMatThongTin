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
    message = "Bai tap lon An toan va bao mat thong tin"
    
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