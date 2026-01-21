import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from ucap.core.crypto_interface import CryptoPluginBase

class RSAOAEPPlugin(CryptoPluginBase):
    """
    RSA OAEP Plugin for Phase-2.
    Provides:
      - generate_keypair()
      - encrypt()
      - decrypt()
    """

    id = "RSA"

    def generate_keypair(self):
        priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pub = priv.public_key()
        return {"priv": priv, "pub": pub}

    def encrypt(self, plaintext: bytes, session=None):
        if session is None or "rsa_pub" not in session.metadata:
            raise ValueError("RSA public key not set in session.metadata")

        pub = session.metadata["rsa_pub"]

        ciphertext = pub.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # ✅ LOG ENCRYPTED PAYLOAD
        logger = session.metadata.get("logger")
        if logger:
            logger.log(
                "ENCRYPTED_PAYLOAD",
                "RSA encryption performed",
                {
                    "algo": "RSA",
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "length": len(ciphertext)
                }
            )

        return {"ciphertext": ciphertext}

    def decrypt(self, payload, session=None):
        if session is None or "rsa_priv" not in session.metadata:
            raise ValueError("RSA private key not set in session.metadata")

        priv = session.metadata["rsa_priv"]
        ct = payload["ciphertext"]

        plaintext = priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext


from ucap.core.crypto_interface import register_plugin
register_plugin(RSAOAEPPlugin())
