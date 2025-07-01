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

# Load server's public key from a file
with open("server_public_key.pem", "rb") as f:
    server_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, message):
        self.message = message

        # Derive AES key using HKDF
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=32, salt=None, info=None,
            backend=default_backend()
        ).derive(PW)
        self._aes_key = key_material

    def connection_made(self, transport):
        plaintext = self.message.encode()
        nonce = os.urandom(12)
        aad = b""  # Additional Authenticated Data, not used in this example

        # Encrypt AES key using server's public key
        encrypted_aes_key = server_public_key.encrypt(
            self._aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Encrypt the message using AES-GCM
        ciphertext = AESGCM(self._aes_key).encrypt(nonce, plaintext, aad)

        # Calculate HMAC
        hmac_tag = hmac.new(self._aes_key, ciphertext, hashlib.sha256).digest()

        # Send encrypted AES key, nonce, ciphertext, and HMAC tag
        transport.write(encrypted_aes_key + nonce + ciphertext + hmac_tag)
        print('Encrypted data sent: {!r}'.format(self.message))

    def data_received(self, data):
        nonce, ciphertext, hmac_tag = data[:12], data[12:-32], data[-32:]
        aad = b""  # Additional Authenticated Data, not used in this example

        # Verify HMAC
        received_hmac = hmac_tag
        expected_hmac = hmac.new(self._aes_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_hmac, expected_hmac):
            print("HMAC verification failed!")
            return

        # Decrypt the ciphertext
        plaintext = AESGCM(self._aes_key).decrypt(nonce, ciphertext, aad)
        print('Decrypted response from server: {!r}'.format(plaintext.decode()))
        if "--auto-test" in sys.argv:
            if plaintext.decode() == self.message:
                print("[PASS]")
            else:
                print("[FAIL]")

loop = asyncio.get_event_loop()
message = sys.argv[1]
coro = loop.create_connection(lambda: EchoClientProtocol(message), '127.0.0.1', 8888)
loop.run_until_complete(coro)
loop.run_forever()
loop.close()