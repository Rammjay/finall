import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ucap.core.crypto_interface import CryptoPluginBase

class AESGCMPlugin(CryptoPluginBase):
    """
    AES-GCM Plugin for Phase-2.
    Uses session.sym_key for encryption/decryption.
    """

    id = "AES"

    def generate_keypair(self):
        return {"key": AESGCM.generate_key(bit_length=256)}

    def encrypt(self, plaintext: bytes, session=None):
        if session is None:
            raise ValueError("Session required for AES encryption")

        key = session.sym_key
        aes = AESGCM(key)
        nonce = os.urandom(12)

        ciphertext = aes.encrypt(nonce, plaintext, None)

        # ✅ LOG ENCRYPTED PAYLOAD
        logger = session.metadata.get("logger")
        if logger:
            logger.log(
                "ENCRYPTED_PAYLOAD",
                "AES encryption successful",
                {
                    "algo": "AES",
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "length": len(ciphertext)
                }
            )

        return {
            "ciphertext": ciphertext,
            "nonce": nonce
        }

    def decrypt(self, payload, session=None):
        if session is None:
            raise ValueError("Session required for AES decryption")

        key = session.sym_key
        aes = AESGCM(key)

        nonce = payload["nonce"]
        ciphertext = payload["ciphertext"]

        plaintext = aes.decrypt(nonce, ciphertext, None)
        return plaintext


from ucap.core.crypto_interface import register_plugin
register_plugin(AESGCMPlugin())
