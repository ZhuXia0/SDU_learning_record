from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import os

# 生成客户端的私钥和公钥
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
public_key = private_key.public_key()

# 将公钥序列化为PEM格式，以便发送
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 创建socket并连接到服务器
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 8808))

# 发送公钥到服务器（直接发送二进制数据）
client_socket.sendall(pem_public_key)

# 接收服务器的公钥（直接接收二进制数据）
pem_data = client_socket.recv(1024)
server_public_key = serialization.load_pem_public_key(
    pem_data,
    backend=default_backend()
)

# 生成共享密钥
shared_key = private_key.exchange(ec.ECDH(), server_public_key)

# 使用HKDF派生出一个密钥
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

print(f"Client derived key: {derived_key.hex()}")

# 接收服务器发送的iv和密文
received_iv_and_ciphertext = client_socket.recv(1024)
received_iv = received_iv_and_ciphertext[:16]
received_ciphertext = received_iv_and_ciphertext[16:]

# 解密消息
decipher = Cipher(algorithms.AES(derived_key), modes.CFB(received_iv), backend=default_backend())
decryptor = decipher.decryptor()
plaintext = decryptor.update(received_ciphertext) + decryptor.finalize()

print(f"Client received message: {plaintext.decode('utf-8')}")

# 定义要发送的消息
message = "Hello, Server!"

# 准备发送相同的消息给服务器（加密）
cipher = Cipher(algorithms.AES(derived_key), modes.CFB(received_iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext_to_send = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

# 发送iv和密文给服务器（注意：这里为了简化，我们重用了服务器的iv。在实际应用中，应该为每个消息生成新的iv）
client_socket.sendall(received_iv + ciphertext_to_send)

# 关闭连接
client_socket.close()