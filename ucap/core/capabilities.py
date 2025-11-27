class Capabilities:
    """
    Represents what a device supports.
    Example:
        crypto = ["RSA_OAEP", "AES_GCM"]
        features = ["ENCRYPT", "DECRYPT"]
    """

    def __init__(self, crypto_list=None, features=None):
        self.crypto_list = crypto_list or []
        self.features = features or []

    def supports(self, scheme_name: str) -> bool:
        return scheme_name in self.crypto_list

    def __repr__(self):
        return f"Capabilities(crypto={self.crypto_list}, features={self.features})"


# canonical capability identifiers used across UCAP
CAP_AES_GCM = "AES"
CAP_RSA_OAEP = "RSA"
CAP_ECC_X25519 = "X25519"
CAP_CHACHA20 = "CHACHA20"

# Friendly metadata about capabilities (used by negotiation UI/logging)
CAPABILITY_META = {
    CAP_AES_GCM: {"type": "symmetric", "recommended_bits": 256, "aead": True},
    CAP_RSA_OAEP: {"type": "asymmetric", "recommended_bits": 2048, "oaep": True},
    CAP_ECC_X25519: {"type": "asymmetric", "recommended_curve": "x25519"},
    CAP_CHACHA20: {"type": "symmetric", "aead": True},
}

def normalize_cap(cap: str) -> str:
    return cap.strip().upper()
