from ucap.core.session_manager import SessionManager
from ucap.core.audit_logger import AuditLogger
from ucap.plugins.rsa_oaep. import RSAOAEPPlugin
from ucap.plugins.aes_gcm import AESGCMPlugin

logger = AuditLogger("rsa_to_aes_test")
session_mgr = SessionManager(logger)

# Create session
session = session_mgr.create_session("AES")

# Setup RSA
rsa = RSAOAEPPlugin()
keys = rsa.generate_keypair()
session.metadata["rsa_pub"] = keys["pub"]
session.metadata["rsa_priv"] = keys["priv"]

# Encrypt with RSA
msg = b"UCAP test message"
rsa_ct = rsa.encrypt(msg, session)

# Decrypt with RSA
pt = rsa.decrypt(rsa_ct, session)

# Encrypt with AES
aes = AESGCMPlugin()
aes_ct = aes.encrypt(pt, session)

# Decrypt AES
final = aes.decrypt(aes_ct, session)

print("Final message:", final.decode())
