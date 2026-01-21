"""
Session Manager
---------------
Manages secure session lifecycle, replay protection, and key handling.

Phase-2 Enhancements:
- Replay attack detection
- Timestamp validation
- Session expiration enforcement
- Security logging
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .audit_logger import AuditLogger
from .config import (
    SESSION_KEY_BITS,
    SESSION_TTL_SECONDS,
)
from .utils import random_urlsafe_token
from .errors import SessionError


# ==============================
# Session Context
# ==============================

@dataclass
class SessionContext:
    session_id: str
    sym_key: bytes
    created_at: float
    ttl: int
    metadata: Dict

    # Replay protection
    used_nonces: Set[bytes] = field(default_factory=set)

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl


# ==============================
# Session Manager
# ==============================

class SessionManager:
    def __init__(self, logger: AuditLogger):
        self.logger = logger
        self.sessions: Dict[str, SessionContext] = {}

    # --------------------------
    # Key generation
    # --------------------------
    def _generate_key(self, bits: int = SESSION_KEY_BITS) -> bytes:
        if bits not in (128, 192, 256):
            bits = 256
        return AESGCM.generate_key(bit_length=bits)

    # --------------------------
    # Create session
    # --------------------------
    def create_session(
        self,
        chosen_algo: str,
        metadata: Optional[Dict] = None,
        ttl: Optional[int] = None
    ) -> SessionContext:

        sid = random_urlsafe_token(12)
        key = self._generate_key()
        created = time.time()

        ctx = SessionContext(
            session_id=sid,
            sym_key=key,
            created_at=created,
            ttl=ttl or SESSION_TTL_SECONDS,
            metadata={
                "algo": chosen_algo,
                **(metadata or {})
            }
        )

        self.sessions[sid] = ctx

        self.logger.log(
            "SESSION_CREATED",
            f"session={sid}, algo={chosen_algo}"
        )

        return ctx

    # --------------------------
    # Fetch session
    # --------------------------
    def get_session(self, sid: str) -> SessionContext:
        ctx = self.sessions.get(sid)

        if not ctx:
            raise SessionError(f"Session not found: {sid}")

        if ctx.is_expired():
            self.logger.log("SESSION_EXPIRED", f"session={sid}")
            del self.sessions[sid]
            raise SessionError(f"Session expired: {sid}")

        return ctx

    # --------------------------
    # Replay Protection
    # --------------------------
    def validate_message(self, session: SessionContext, nonce: bytes, timestamp: float):
        now = time.time()

        # 1. Session expiry
        if session.is_expired():
            self.logger.log("SESSION_EXPIRED", session.session_id)
            raise SessionError("Session expired")

        # 2. Replay detection
        if nonce in session.used_nonces:
            self.logger.log(
                "REPLAY_ATTACK_DETECTED",
                f"session={session.session_id}"
            )
            raise SessionError("Replay attack detected")

        # 3. Timestamp freshness (±30 sec)
        if abs(now - timestamp) > 30:
            self.logger.log(
                "STALE_MESSAGE",
                f"session={session.session_id}"
            )
            raise SessionError("Stale message detected")

        # 4. Mark nonce as used
        session.used_nonces.add(nonce)

    # --------------------------
    # Revoke session
    # --------------------------
    def revoke_session(self, sid: str):
        if sid in self.sessions:
            del self.sessions[sid]
            self.logger.log("SESSION_REVOKED", f"session={sid}")
        else:
            raise SessionError(f"Session not found: {sid}")
