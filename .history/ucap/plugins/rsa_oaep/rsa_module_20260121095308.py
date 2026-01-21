from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from ucap.core.crypto_interface import CryptoPluginBase

class RSAOAEPPlugin(CryptoPluginBase):
    """
    RSA OAEP Plugin for Phase-1.
    Provides:
      - generate_keypair()
      - encrypt(plaintext, session=session)
      - decrypt(payload, session=session)
    """

    id = "RSA"

    def generate_keypair(self):
        """Return a dict: { 'priv' : private_key, 'pub' : public_key }"""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        return {"priv": priv, "pub": pub}

    def encrypt(self, plaintext: bytes, session=None):
        """
        plaintext → RSA ciphertext
        Expects session.metadata['rsa_pub'] set earlier.
        """
        if session is None or "rsa_pub" not in session.metadata:
            raise ValueError("RSA public key not set in session.metadata['rsa_pub']")

        pub = session.metadata["rsa_pub"]

        ct = pub.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": ct}

    def decrypt(self, payload, session=None):
        """
        RSA ciphertext → plaintext
        Expects session.metadata['rsa_priv'] set earlier.
        """
        if session is None or "rsa_priv" not in session.metadata:
            raise ValueError("RSA private key not set in session.metadata['rsa_priv']")

        priv = session.metadata["rsa_priv"]

        ct = payload["ciphertext"]

        pt = priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return pt
from ucap.core.crypto_interface import register_plugin
register_plugin(RSAOAEPPlugin())
