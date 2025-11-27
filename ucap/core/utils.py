"""
Utility helpers used across the core.
"""

import base64
import os
import secrets
from typing import Any, Dict

def b64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def random_urlsafe_token(nbytes: int = 12) -> str:
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode("utf-8").rstrip("=")

def safe_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison"""
    return secrets.compare_digest(a, b)

def ensure_keys(d: Dict[str, Any], *keys):
    for k in keys:
        if k not in d:
            raise KeyError(f"Missing required key: {k}")
