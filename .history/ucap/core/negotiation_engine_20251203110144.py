# ucap/core/negotiation_engine.py

from typing import List, Tuple
from .config import DEFAULT_PREFERENCE_ORDER
from .capabilities import normalize_cap
from .audit_logger import AuditLogger

TRANSLATE_MODE = "TRANSLATE"

class NegotiationEngine:
    """
    Phase-2:
       - compute intersection
       - follow global preference order
       - fallback: TRANSLATE
    """

    def __init__(self, logger: AuditLogger):
        self.logger = logger
        self.pref = [normalize_cap(p) for p in DEFAULT_PREFERENCE_ORDER]

    def negotiate(self, client_caps: List[str], server_caps: List[str]) -> Tuple[str, str]:

        client = {normalize_cap(c) for c in client_caps}
        server = {normalize_cap(s) for s in server_caps}

        self.logger.log("NEGOTIATION_START", f"client={client} server={server}")

        # Check for intersection in order
        for algo in self.pref:
            if algo in client and algo in server:
                self.logger.log("NEGOTIATION_MATCH", f"chosen={algo}")
                return algo, "common"

        self.logger.log("NEGOTIATION_TRANSLATE", "no-common")
        return TRANSLATE_MODE, "no-common"
