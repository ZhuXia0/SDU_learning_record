from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def encrypt_message(key, nonce, plaintext, aad):
    # 创建Cipher对象，使用AES-GCM模式
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # 更新附加数据 (AAD)
    encryptor.authenticate_additional_data(aad)

    # 填充数据到块大小（如果需要）
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # 加密数据
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # 获取标签
    tag = encryptor.tag

    return ciphertext, tag

def decrypt_message(key, nonce, ciphertext, tag, aad):
    # 创建Cipher对象，使用AES-GCM模式
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # 更新附加数据 (AAD)
    decryptor.authenticate_additional_data(aad)

    # 解密数据
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 去除填充数据
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# 示例使用
if __name__ == "__main__":
    # 生成一个随机密钥（AES-256需要32字节的密钥）
    key = os.urandom(32)

    # 生成一个随机nonce（对于AES-GCM，nonce的长度必须是12字节）
    nonce = os.urandom(12)

    # 示例消息和附加数据
    plaintext = b"Hello, this is a secret message!"
    aad = b"This is the associated authenticated data."

    # 加密消息
    ciphertext, tag = encrypt_message(key, nonce, plaintext, aad)
    print(f"Ciphertext: {ciphertext}")
    print(f"Tag: {tag}")

    # 解密消息
    decrypted_plaintext = decrypt_message(key, nonce, ciphertext, tag, aad)
    print(f"Decrypted Plaintext: {decrypted_plaintext}")