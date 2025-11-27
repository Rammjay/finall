from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from ..core.crypto_interface import CryptoInterface

class RSA_OAEP(CryptoInterface):

    def generate_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def encrypt(self, key, plaintext):
        public_key = key.public_key()
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, key, ciphertext):
        return key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
