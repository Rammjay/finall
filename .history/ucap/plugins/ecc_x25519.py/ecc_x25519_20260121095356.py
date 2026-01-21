import os
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ucap.core.crypto_interface import CryptoPluginBase


class ECCX25519Plugin(CryptoPluginBase):
    """
    ECC (X25519) Plugin for Phase-2.
    Performs:
      - Key exchange using X25519
      - Symmetric encryption using AES-GCM
    """

    id = "ECC"

    # ---------------------------
    # Key Generation
    # ---------------------------
    def generate_keypair(self):
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()
        return {"priv": private, "pub": public}

    # ---------------------------
    # Key Derivation
    # ---------------------------
    def derive_key(self, private_key, peer_public_key):
        shared = private_key.exchange(peer_public_key)

        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ucap-ecc"
        ).derive(shared)

        return derived

    # ---------------------------
    # Encryption
    # ---------------------------
    def encrypt(self, plaintext: bytes, session=None):
        if session is None or "ecc_key" not in session.metadata:
            raise ValueError("ECC shared key not found in session.metadata")

        aes_key = session.metadata["ecc_key"]
        aes = AESGCM(aes_key)
        nonce = os.urandom(12)

        ciphertext = aes.encrypt(nonce, plaintext, None)

        # ✅ LOG ENCRYPTED PAYLOAD
        logger = session.metadata.get("logger")
        if logger:
            logger.log(
                "ENCRYPTED_PAYLOAD",
                "ECC encryption performed",
                {
                    "algo": "ECC",
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "length": len(ciphertext)
                }
            )

        return {
            "ciphertext": ciphertext,
            "nonce": nonce
        }

    # ---------------------------
    # Decryption
    # ---------------------------
    def decrypt(self, payload, session=None):
        if session is None or "ecc_key" not in session.metadata:
            raise ValueError("ECC shared key not found in session.metadata")

        aes_key = session.metadata["ecc_key"]
        aes = AESGCM(aes_key)

        return aes.decrypt(
            payload["nonce"],
            payload["ciphertext"],
            None
        )
