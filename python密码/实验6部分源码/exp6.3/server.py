from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import os

# 生成服务器端的私钥和公钥
private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
public_key = private_key.public_key()

# 将公钥序列化为PEM格式，以便发送
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 创建socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8808))
server_socket.listen(1)
print("Server listening on port 8808")

# 接受客户端连接
client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address}")

# 接收客户端的公钥
pem_data = client_socket.recv(1024).decode('utf-8')
client_public_key = serialization.load_pem_public_key(
    pem_data.encode('utf-8'),
    backend=default_backend()
)

# 发送公钥到客户端（直接发送二进制数据）
client_socket.sendall(pem_public_key)

# 生成共享密钥
shared_key = private_key.exchange(ec.ECDH(), client_public_key)

# 使用HKDF派生出一个密钥
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

print(f"Server derived key: {derived_key.hex()}")

# 准备AES加密的iv（初始化向量）
iv = os.urandom(16)  # AES的块大小是16字节

# 加密消息
cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
message = b"Hello, this is a secret message!"
ciphertext = encryptor.update(message) + encryptor.finalize()

# 发送iv和密文给客户端
client_socket.sendall(iv + ciphertext)

# 接收客户端发送回来的相同消息（已加密）
received_iv_and_ciphertext = client_socket.recv(1024)
received_iv = received_iv_and_ciphertext[:16]
received_ciphertext = received_iv_and_ciphertext[16:]

# 解密消息
decipher = Cipher(algorithms.AES(derived_key), modes.CFB(received_iv), backend=default_backend())
decryptor = decipher.decryptor()
plaintext = decryptor.update(received_ciphertext) + decryptor.finalize()

print(f"Server received message: {plaintext.decode('utf-8')}")

# 关闭连接
client_socket.close()
server_socket.close()