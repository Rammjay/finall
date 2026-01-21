from .config import (
    DEFAULT_PREFERENCE_ORDER,
    SECURITY_LEVEL,
    MIN_SECURITY_LEVEL
)
from .capabilities import normalize_cap
from .audit_logger import AuditLogger

TRANSLATE_MODE = "TRANSLATE"


class NegotiationEngine:
    def __init__(self, logger: AuditLogger):
        self.logger = logger
        self.pref = [normalize_cap(p) for p in DEFAULT_PREFERENCE_ORDER]

    def negotiate(self, client_caps, server_caps):
        client = {normalize_cap(c) for c in client_caps}
        server = {normalize_cap(s) for s in server_caps}

        self.logger.log(
            "NEGOTIATION_START",
            f"client={client}, server={server}"
        )

        # ------------------------------------------------
        # STEP 1: Find common algorithms
        # ------------------------------------------------
        common = [a for a in self.pref if a in client and a in server]

        if not common:
            self.logger.log(
                "NEGOTIATION_TRANSLATE",
                "No common algorithm – translation required"
            )
            return TRANSLATE_MODE, "no-common"

        chosen = common[0]

        # ------------------------------------------------
        # STEP 2: Detect downgrade attempt
        # ------------------------------------------------
        strongest_client = next(
            (a for a in self.pref if a in client),
            None
        )

        if strongest_client and chosen != strongest_client:
            self.logger.log(
                "DOWNGRADE_DETECTED",
                f"client_pref={strongest_client}, chosen={chosen}"
            )

        # ------------------------------------------------
        # STEP 3: Enforce security level
        # ------------------------------------------------
        strength = SECURITY_LEVEL.get(chosen, 0)

        if strength < MIN_SECURITY_LEVEL:
            self.logger.log(
                "NEGOTIATION_REJECTED",
                f"Rejected weak algorithm: {chosen}"
            )
            raise Exception(f"Insecure algorithm rejected: {chosen}")

        # ------------------------------------------------
        # STEP 4: Success
        # ------------------------------------------------
        self.logger.log(
            "NEGOTIATION_SUCCESS",
            f"chosen={chosen}"
        )

        return chosen, "common"
