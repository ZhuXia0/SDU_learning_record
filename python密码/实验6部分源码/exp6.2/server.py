import asyncio
import hashlib
import hmac
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

PW = b"password"

# Generate RSA key pair (for demonstration purposes only)
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_rsa_key_pair()

# Save public key to a file (or use another method to share it with clients)
with open("server_public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

class EchoServerProtocol(asyncio.Protocol):
    def __init__(self):
        self.private_key = private_key

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        # Extract encrypted key, nonce, ciphertext, and HMAC tag
        encrypted_key_length = 256  # Length of the RSA-encrypted AES key (2048 bits / 8 bytes = 256 bytes)
        encrypted_key = data[:encrypted_key_length]
        data = data[encrypted_key_length:]
        nonce, ciphertext, hmac_tag = data[:12], data[12:-32], data[-32:]
        aad = b""  # Additional Authenticated Data, not used in this example

        # Decrypt the AES key using RSA private key
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Verify HMAC
        received_hmac = hmac_tag
        expected_hmac = hmac.new(aes_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_hmac, expected_hmac):
            print("HMAC verification failed!")
            self.transport.close()
            return

        # Decrypt the ciphertext
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
        message = plaintext.decode()
        print('Decrypted message from client: {!r}'.format(message))

        # Echo back message
        print('Echo back message: {!r}'.format(message))
        reply_nonce = os.urandom(12)
        reply_ciphertext = AESGCM(aes_key).encrypt(reply_nonce, message.encode(), aad)
        reply_hmac = hmac.new(aes_key, reply_ciphertext, hashlib.sha256).digest()
        self.transport.write(reply_nonce + reply_ciphertext + reply_hmac)

        # Close the client socket
        self.transport.close()
        # FOR AUTO TESTING. Shutdown after echo
        if "--auto-test" in sys.argv:
            print("[PASS]")
            asyncio.get_event_loop().call_later(0.25, sys.exit)

loop = asyncio.get_event_loop()
coro = loop.create_server(lambda: EchoServerProtocol(), '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

server.close()
loop.run_until_complete(server.wait_closed())
loop.close()