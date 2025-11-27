"""
Simple audit logger that collects structured events and prints them.
Replace/extend with a proper logging backend in Phase 2 (e.g., structured JSON logger).
"""

import time
import json
from typing import Dict, Any, List, Optional
from .config import LOG_LEVEL

class AuditLogger:
    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def _now_iso(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def log(self, event_type: str, message: str, meta: Optional[Dict[str, Any]] = None):
        entry = {
            "ts": self._now_iso(),
            "type": event_type,
            "msg": message,
            "meta": meta or {},
        }
        self.events.append(entry)
        # Keep simple console output for prototype
        try:
            print(json.dumps(entry))
        except Exception:
            print(f"[{entry['ts']}] {event_type} - {message}")

    def query(self):
        """Return recorded events"""
        return list(self.events)
