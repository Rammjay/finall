import time
from ucap.core.session_manager import SessionManager
from ucap.core.audit_logger import AuditLogger

logger = AuditLogger("replay_test")
manager = SessionManager(logger)

session = manager.create_session("AES")

nonce = b"123456789012"
timestamp = time.time()

# First message (valid)
manager.validate_message(session, nonce, timestamp)
print("First message accepted")

# Replay same message
try:
    manager.validate_message(session, nonce, timestamp)
except Exception as e:
    print("Replay detected:", e)
