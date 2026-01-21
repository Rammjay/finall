from ucap.core.negotiation_engine import NegotiationEngine
from ucap.core.audit_logger import AuditLogger

logger = AuditLogger("negotiation_test")
engine = NegotiationEngine(logger)

client_caps = ["AES", "RSA"]
server_caps = ["AES"]

algo, mode = engine.negotiate(client_caps, server_caps)

print("Chosen Algo:", algo)
print("Mode:", mode)
