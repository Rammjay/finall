from ucap.core.plugin_loader import PluginLoader
from ucap.core.capabilities import Capabilities
from ucap.core.negotiation_engine import NegotiationEngine, TRANSLATE_MODE
from ucap.core.session_manager import SessionManager
from ucap.core.audit_logger import AuditLogger
from ucap.core.translation_engine import TranslationEngine
from ucap.core.message_envelope import UCAPEnvelope

def main():
    logger = AuditLogger()

    # Load plugins
    loader = PluginLoader(logger)
    plugins = loader.discover()
    print("Plugins:", plugins.keys())

    nego = NegotiationEngine(logger)

    client_caps = Capabilities(["RSA"])
    server_caps = Capabilities(["AES"])

    chosen, reason = nego.negotiate(client_caps.crypto_list, server_caps.crypto_list)
    print("Negotiation result:", chosen, reason)

    session_mgr = SessionManager(logger)
    session = session_mgr.create_session(chosen_algo=chosen)

    # pick real plugin objects
    rsa = plugins["RSA"]
    aes = plugins["AES"]

    # Add RSA keypair to session for decrypt
    kp = rsa.generate_keypair()
    session.metadata["rsa_priv"] = kp["priv"]
    session.metadata["rsa_pub"] = kp["pub"]

    # Client encrypts with RSA
    plaintext = b"Hello UCAP Phase 2"
    rsa_ct = rsa.encrypt(plaintext, session=session)

    env = UCAPEnvelope("RSA", rsa_ct["ciphertext"])

    engine = TranslationEngine(logger)
    env2 = engine.translate("RSA", "AES", env, session)

    # Server decrypts AES
    pt2 = aes.decrypt(
        {"ciphertext": env2.ciphertext, "nonce": env2.nonce},
        session=session
    )

    print("Original:", plaintext)
    print("After UCAP:", pt2)

if __name__ == "__main__":
    main()
