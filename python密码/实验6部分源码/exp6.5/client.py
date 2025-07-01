import socket
import ssl

# 服务器地址和端口
HOST = '127.0.0.1'
PORT = 8443

# 服务器的自签名证书文件路径
SERVER_CERT_FILE = 'F:/python密码/exp6/server.crt'  # 请替换为实际的文件路径


def start_ssl_client():
    # 创建一个 SSL 上下文
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT_FILE)
    context.check_hostname = False  # 确保主机名验证是启用的
    context.verify_mode = ssl.CERT_REQUIRED  # 要求服务器提供证书，并且客户端会验证它

    # 创建一个套接字并连接到服务器
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        # 使用配置好的 SSL 上下文来包装套接字
        with context.wrap_socket(sock, server_hostname=HOST) as connstream:
            try:
                print("Sending data...")
                connstream.sendall(b"Hello from SSL client")
                data = connstream.recv(1024)
                print(f"Received: {data.decode()}")
            finally:
                # 关闭连接
                connstream.shutdown(socket.SHUT_RDWR)


if __name__ == "__main__":
    start_ssl_client()