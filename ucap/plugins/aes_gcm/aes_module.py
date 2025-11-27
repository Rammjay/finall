import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..core.crypto_interface import CryptoInterface

class AES_GCM(CryptoInterface):

    def generate_key(self):
        return os.urandom(32)  # AES-256

    def encrypt(self, key, plaintext):
        aes = AESGCM(key)
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, plaintext, None)

    def decrypt(self, key, ciphertext):
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        aes = AESGCM(key)
        return aes.decrypt(nonce, ct, None)
