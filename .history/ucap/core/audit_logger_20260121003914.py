"""
Audit logger with:
- In-memory structured logs
- Console JSON logs
- Per-case log files in logs/ directory
"""

import time
import json
import os
from typing import Dict, Any, List, Optional

class AuditLogger:
    def __init__(self, case_name: str = "default"):
        self.events: List[Dict[str, Any]] = []
        self.case_name = case_name

        # Create logs directory
        os.makedirs("logs", exist_ok=True)

# Sanitize filename for Windows
        safe_name = (
            case_name.replace(" ", "_")
                .replace(":", "_")
                .replace("↔", "to")
                .replace("→", "to")
                .replace("←", "from")
                .encode("ascii", "ignore")
                .decode()
)

        self.logfile = f"logs/{safe_name}.log"

# Reset old logs
        with open(self.logfile, "w", encoding="utf-8") as f:
            f.write(f"--- UCAP LOG FILE FOR {case_name} ---\n\n")


    def _now_iso(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def log(self, event_type: str, message: str, meta: Optional[Dict[str, Any]] = None):
        entry = {
            "ts": self._now_iso(),
            "type": event_type,
            "msg": message,
            "meta": meta or {}
        }

        # Store in memory
        self.events.append(entry)

        # Print JSON to console
        print(json.dumps(entry))

        # Append structured log entry to file
        with open(self.logfile, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def query(self):
        """Return recorded events."""
        return list(self.events)
