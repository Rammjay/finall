# ucap/core/message_envelope.py

import base64
import json
from typing import Optional, Dict, Any

class UCAPEnvelope:
    """
    Standardized crypto message:
       algo:      "AES", "RSA", "X25519", ...
       ciphertext: bytes
       nonce:     optional bytes
       meta:      dict
    """

    def __init__(self, algo: str, ciphertext: bytes, nonce: Optional[bytes] = None, meta: Optional[Dict[str, Any]] = None):
        self.algo = algo
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.meta = meta or {}

    def to_json(self) -> str:
        return json.dumps({
            "algo": self.algo,
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "nonce": base64.b64encode(self.nonce).decode() if self.nonce else None,
            "meta": self.meta
        })

    @staticmethod
    def from_json(j: str):
        d = json.loads(j)
        ct = base64.b64decode(d["ciphertext"])
        nonce = base64.b64decode(d["nonce"]) if d["nonce"] else None
        return UCAPEnvelope(d["algo"], ct, nonce, d["meta"])
