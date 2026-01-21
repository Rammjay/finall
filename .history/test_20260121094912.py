from ucap.core.negotiation_engine import NegotiationEngine
from ucap.core.audit_logger import AuditLogger

logger = AuditLogger("downgrade_test")
engine = NegotiationEngine(logger)

client_caps = ["AES", "RSA"]
server_caps = ["RSA"]

engine.negotiate(client_caps, server_caps)
