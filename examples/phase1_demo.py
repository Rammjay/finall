from ucap.core.audit_logger import AuditLogger
from ucap.core.session_manager import SessionManager
from ucap.core.negotiation_engine import NegotiationEngine
from ucap.core.capabilities import normalize_cap
from ucap.core.translation_engine import TranslationEngine
from ucap.plugins.rsa_oaep.rsa_module import RSAOAEPPlugin
from ucap.plugins.aes_gcm.aes_module import AESGCMPlugin
from ucap.core.message_envelope import UCAPEnvelope

def main():
    print("\n=== UCAP Phase-1 Demo: RSA → AES Translation ===\n")

    # Initialize core components
    logger = AuditLogger()
    session_mgr = SessionManager(logger)
    negotiate = NegotiationEngine(logger)
    translate = TranslationEngine(logger)

    # Capabilities of client/server
    client_caps = ["RSA"]
    server_caps = ["AES"]

    # Negotiation
    chosen, reason = negotiate.negotiate(client_caps, server_caps)
    print(f"Negotiation Result: {chosen} ({reason})")

    # Create Session
    session = session_mgr.create_session(chosen_algo=chosen)

    # Initialize Plugins
    rsa = RSAOAEPPlugin()
    aes = AESGCMPlugin()

    # ----- FIXED: Generate RSA keypair and store in metadata -----
    kp = rsa.generate_keypair()
    session.metadata["rsa_priv"] = kp["priv"]
    session.metadata["rsa_pub"] = kp["pub"]
    # --------------------------------------------------------------

    # Step 1 — Client encrypts using RSA
    plaintext = b"Hello from RSA client!"
    rsa_ct = rsa.encrypt(plaintext, session=session)

    envelope_in = UCAPEnvelope("RSA", rsa_ct["ciphertext"])

    # Step 2 — UCAP translates RSA → AES
    envelope_out = translate.translate(
        src_algo="RSA",
        dst_algo="AES",
        envelope=envelope_in,
        session_ctx=session
    )

    # Step 3 — Server decrypts AES
    decrypted = aes.decrypt(
        {"ciphertext": envelope_out.ciphertext, "nonce": envelope_out.nonce},
        session=session
    )

    print("\n--- DEMO RESULTS ---")
    print("Original message:     ", plaintext)
    print("Decrypted at server:  ", decrypted)
    print("----------------------\n")

    print("=== Phase-1 Demo Completed Successfully ===\n")

if __name__ == "__main__":
    main()
