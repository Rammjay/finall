"""
Session manager: creates short-lived session contexts containing symmetric keys, nonces, metadata.
This is intentionally lightweight for Phase 1.
"""

import time
import os
from dataclasses import dataclass
from typing import Optional, Dict
from .audit_logger import AuditLogger
from .config import SESSION_KEY_BITS, SESSION_TTL_SECONDS
from .utils import random_urlsafe_token
from .errors import SessionError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

@dataclass
class SessionContext:
    session_id: str
    sym_key: bytes   # symmetric key for session (e.g., AES key)
    created_at: float
    ttl: int
    metadata: Dict

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl

class SessionManager:
    def __init__(self, logger: AuditLogger):
        self.logger = logger
        self.sessions: Dict[str, SessionContext] = {}

    def _generate_key(self, bits: int = SESSION_KEY_BITS) -> bytes:
        # AESGCM expects bytes length in bytes (e.g., 16, 32)
        if bits not in (128, 192, 256):
            # default to 256 if unusual
            bits = 256
        return AESGCM.generate_key(bit_length=bits)

    def create_session(self, chosen_algo: str, metadata: Optional[Dict] = None, ttl: int = None) -> SessionContext:
        meta = metadata or {}
        sid = random_urlsafe_token(12)
        key = self._generate_key()
        created = time.time()
        ttl_use = ttl or SESSION_TTL_SECONDS
        ctx = SessionContext(session_id=sid, sym_key=key, created_at=created, ttl=ttl_use, metadata={"algo": chosen_algo, **meta})
        self.sessions[sid] = ctx
        self.logger.log("SESSION_CREATED", f"session={sid} algo={chosen_algo}")
        return ctx

    def get_session(self, sid: str) -> SessionContext:
        ctx = self.sessions.get(sid)
        if not ctx:
            raise SessionError(f"Session not found: {sid}")
        if ctx.is_expired():
            self.logger.log("SESSION_EXPIRED", f"session={sid}")
            del self.sessions[sid]
            raise SessionError(f"Session expired: {sid}")
        return ctx

    def revoke_session(self, sid: str):
        if sid in self.sessions:
            del self.sessions[sid]
            self.logger.log("SESSION_REVOKED", f"session={sid}")
        else:
            raise SessionError(f"Session not found: {sid}")
