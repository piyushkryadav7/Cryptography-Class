import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class DESCipher:
    def __init__(self, key: bytes):
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes long.")
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode("ascii")

    def decrypt(self, ciphertext_b64: str) -> str:
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:8]
        ciphertext = raw[8:]
        cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode("utf-8")


if __name__ == "__main__":
    des_key = b"mydeskey"
    des = DESCipher(des_key)
    msg = "Secret!"
    enc = des.encrypt(msg)
    dec = des.decrypt(enc)
    print(f"Plaintext : {msg}")
    print(f"Encrypted : {enc}")
    print(f"Decrypted : {dec}")
