from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class ECCX25519Plugin:
    id = "ECC"

    def generate_keypair(self):
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()
        return private, public

    def derive_key(self, private_key, peer_public_key):
        shared = private_key.exchange(peer_public_key)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ucap-ecc"
        ).derive(shared)
        return derived

    def encrypt(self, plaintext: bytes, aes_key: bytes):
        nonce = os.urandom(12)
        aes = AESGCM(aes_key)
        ciphertext = aes.encrypt(nonce, plaintext, None)
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes, aes_key: bytes):
        aes = AESGCM(aes_key)
        return aes.decrypt(nonce, ciphertext, None)
