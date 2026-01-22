from ucap.core.audit_logger import AuditLogger
from ucap.core.session_manager import SessionManager
from ucap.core.negotiation_engine import NegotiationEngine

from ucap.plugins.aes_gcm.aes_module import AESGCMPlugin
from ucap.plugins.rsa_oaep.rsa_module import RSAOAEPPlugin
from ucap.plugins.ecc_x25519.ecc_x25519 import ECCX25519Plugin

import time


def test_negotiation():
    print("\n=== TEST 1: Negotiation ===")
    logger = AuditLogger("negotiation_test")
    engine = NegotiationEngine(logger)

    algo, mode = engine.negotiate(
        client_caps=["AES", "RSA"],
        server_caps=["AES"]
    )

    print("Chosen:", algo)
    print("Mode:", mode)


def test_rsa_to_aes():
    print("\n=== TEST 2: RSA → AES ===")

    logger = AuditLogger("rsa_to_aes")
    sm = SessionManager(logger)
    session = sm.create_session(
    "AES",
    metadata={
        "client_id": "client_A",
        "trust_level": 2
    }
)

    session.metadata["logger"] = logger

    rsa = RSAOAEPPlugin()
    keys = rsa.generate_keypair()
    session.metadata["rsa_pub"] = keys["pub"]
    session.metadata["rsa_priv"] = keys["priv"]

    aes = AESGCMPlugin()

    msg = b"UCAP RSA TEST"
    rsa_ct = rsa.encrypt(msg, session)
    pt = rsa.decrypt(rsa_ct, session)

    aes_ct = aes.encrypt(pt, session)
    final = aes.decrypt(aes_ct, session)

    print("Final:", final.decode())


def test_replay_attack():
    print("\n=== TEST 3: Replay Attack ===")

    logger = AuditLogger("replay_test")
    sm = SessionManager(logger)
    session = sm.create_session("AES")

    nonce = b"123456789012"
    ts = time.time()

    sm.validate_message(session, nonce, ts)
    print("First message accepted")

    try:
        sm.validate_message(session, nonce, ts)
    except Exception as e:
        print("Replay detected:", e)


def test_downgrade():
    print("\n=== TEST 4: Downgrade Detection ===")

    logger = AuditLogger("downgrade_test")
    engine = NegotiationEngine(logger)

    engine.negotiate(
        client_caps=["AES", "RSA"],
        server_caps=["RSA"]
    )


def test_ecc():
    print("\n=== TEST 5: ECC Encryption ===")

    logger = AuditLogger("ecc_test")
    sm = SessionManager(logger)
    session = sm.create_session("ECC")
    session.metadata["logger"] = logger

    ecc = ECCX25519Plugin()

    keys = ecc.generate_keypair()
    shared = ecc.derive_key(keys["priv"], keys["pub"])

    session.metadata["ecc_key"] = shared

    ct = ecc.encrypt(b"Hello ECC", session)
    pt = ecc.decrypt(ct, session)

    print("ECC decrypted:", pt.decode())


if __name__ == "__main__":
    test_negotiation()
    test_rsa_to_aes()
    test_replay_attack()
    test_downgrade()
    test_ecc()
