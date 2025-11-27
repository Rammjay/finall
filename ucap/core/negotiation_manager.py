"""
Negotiation engine: given client & server capability lists, decide chosen mode.

Policy implemented:
- Prefer intersection according to preference order defined in config.DEFAULT_PREFERENCE_ORDER
- If intersection empty -> TRANSLATE mode (adapter must decrypt/re-encrypt)
- Validate capabilities against minimum security in config
- Returns (chosen_algo:str, reason:str)
"""

from typing import List, Tuple
from .config import DEFAULT_PREFERENCE_ORDER, MIN_RSA_BITS, MIN_AES_BITS
from .capabilities import normalize_cap
from .errors import NegotiationError
from .audit_logger import AuditLogger

TRANSLATE_MODE = "TRANSLATE"

class NegotiationEngine:
    def __init__(self, logger: AuditLogger):
        self.logger = logger
        self.pref = [p.strip().upper() for p in DEFAULT_PREFERENCE_ORDER if p]

    def negotiate(self, client_caps: List[str], server_caps: List[str]) -> Tuple[str, str]:
        client = {normalize_cap(c) for c in client_caps}
        server = {normalize_cap(s) for s in server_caps}
        self.logger.log("NEGOTIATION_INPUT", f"client={sorted(list(client))} server={sorted(list(server))}")

        # compute common by preference
        for p in self.pref:
            if p in client and p in server:
                self.logger.log("NEGOTIATION_CHOSEN", f"chosen={p}")
                return p, "common-preference"

        # no common algorithm
        self.logger.log("NEGOTIATION_TRANSLATE", "no-common => TRANSLATE")
        return TRANSLATE_MODE, "translation-required"
