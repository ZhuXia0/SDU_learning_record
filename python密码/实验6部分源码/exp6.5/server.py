import socket
import ssl

# 证书和私钥路径
CERTFILE = 'server.crt'
KEYFILE = 'server.key'


def start_ssl_server(host='127.0.0.1', port=8443):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

    bindsocket = socket.socket()
    bindsocket.bind((host, port))
    bindsocket.listen(5)

    while True:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        try:
            print(f"Connection from {fromaddr}")
            data = connstream.recv(1024)
            print(f"Received: {data.decode()}")
            connstream.sendall(b"Hello from SSL server")
        finally:
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()


if __name__ == "__main__":
    start_ssl_server()