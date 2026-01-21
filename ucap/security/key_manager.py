import os
import time
from typing import Dict
from ucap.core.audit_logger import AuditLogger


class KeyManager:
    """
    Simulated Key Management Service (KMS)

    Responsibilities:
    - Key generation
    - Secure in-memory storage
    - Key rotation
    - Key revocation
    - Audit logging

    This is a research-grade KMS (not production HSM).
    """

    def __init__(self, logger: AuditLogger):
        self.logger = logger
        self.keys: Dict[str, dict] = {}

    # ----------------------------
    # Create Key
    # ----------------------------
    def create_key(self, key_id: str, size: int = 32):
        key = os.urandom(size)

        self.keys[key_id] = {
            "key": key,
            "created_at": time.time(),
            "active": True
        }

        self.logger.log(
            "KMS_KEY_CREATED",
            f"Key created: {key_id}",
            {"size": size}
        )

        return key

    # ----------------------------
    # Retrieve Key
    # ----------------------------
    def get_key(self, key_id: str):
        entry = self.keys.get(key_id)

        if not entry:
            raise Exception("Key not found")

        if not entry["active"]:
            raise Exception("Key revoked")

        return entry["key"]

    # ----------------------------
    # Rotate Key
    # ----
