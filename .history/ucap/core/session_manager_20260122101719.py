"""
Session Manager
---------------
Manages secure session lifecycle, replay protection, and key handling.

Phase-2 Enhancements:
- Replay attack detection
- Timestamp validation
- Session expiration enforcement
- Centralized Key Management (KMS)
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Set

from .audit_logger import AuditLogger
from .config import SESSION_TTL_SECONDS
from .utils import random_urlsafe_token
from .errors import SessionError
from ucap.security.key_manager import KeyManager
from .config import MIN_REQUIRED_TRUST


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
        self.kms = KeyManager(logger)  # ✅ Centralized Key Manager

    # --------------------------
    # Create session
    # --------------------------
    from .config import MIN_REQUIRED_TRUST
from ucap.security.key_manager import KeyManager


class SessionManager:
    def __init__(self, logger):
        self.logger = logger
        self.sessions = {}
        self.kms = KeyManager(logger)

    def create_session(
        self,
        chosen_algo: str,
        metadata: dict,
        ttl: int = None
    ):
        # --------------------------
        # Identity Validation
        # --------------------------
        if "client_id" not in metadata:
            self.logger.log(
                "ACCESS_DENIED",
                "Missing client identity"
            )
            raise SessionError("Unauthenticated client")

        if "trust_level" not in metadata:
            self.logger.log(
                "ACCESS_DENIED",
                f"client={metadata.get('client_id')} missing trust level"
            )
            raise SessionError("Trust level not provided")

        if metadata["trust_level"] < MIN_REQUIRED_TRUST:
            self.logger.log(
                "ACCESS_DENIED",
                f"client={metadata.get('client_id')} insufficient trust"
            )
            raise SessionError("Insufficient trust level")

        # --------------------------
        # Session Creation
        # --------------------------
        sid = random_urlsafe_token(12)

        # Generate key via KMS
        session_key = self.kms.create_key(sid)

        ctx = SessionContext(
            session_id=sid,
            sym_key=session_key,
            created_at=time.time(),
            ttl=ttl or SESSION_TTL_SECONDS,
            metadata={
                "algo": chosen_algo,
                **metadata
            }
        )

        self.sessions[sid] = ctx

        self.logger.log(
            "SESSION_CREATED",
            f"session={sid}, client={metadata['client_id']}, trust={metadata['trust_level']}"
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
            self.revoke_session(sid)
            raise SessionError("Session expired")

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

        # 3. Timestamp freshness check
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
            self.kms.revoke_key(sid)

            self.logger.log(
                "SESSION_REVOKED",
                f"session={sid}"
            )
        else:
            raise SessionError("Session not found")
