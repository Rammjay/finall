# examples/phase1_demo.py

import time
from ucap.core.audit_logger import AuditLogger
from ucap.core.session_manager import SessionManager
from ucap.core.negotiation_engine import NegotiationEngine
from ucap.core.translation_engine import TranslationEngine
from ucap.plugins.rsa_oaep.rsa_module import RSAOAEPPlugin
from ucap.plugins.aes_gcm.aes_module import AESGCMPlugin
from ucap.core.message_envelope import UCAPEnvelope


# --------------------------
# GLOBAL METRICS
# --------------------------
global_correctness = []
negotiation_correctness = []
translation_latencies = []
log_reliability = []


# --------------------------
# REQUIRED LOG EVENTS
# --------------------------
REQUIRED_EVENTS_TRANSLATE = [
    "NEGOTIATION_START",
    "NEGOTIATION_TRANSLATE",
    "SESSION_CREATED",
    "TRANSLATE_START",
    "TRANSLATE_DONE"
]

REQUIRED_EVENTS_MATCH = [
    "NEGOTIATION_START",
    "NEGOTIATION_MATCH",
    "SESSION_CREATED"
]


def check_logs(logger, expected_translate):
    """Check whether required logs are present."""
    
    # extract 'type' field from each log dict
    events = [entry["type"] for entry in logger.events]

    required = REQUIRED_EVENTS_TRANSLATE if expected_translate else REQUIRED_EVENTS_MATCH
    ok = all(req in events for req in required)

    log_reliability.append(ok)
    return ok



def run_case(title, client_caps, server_caps, plaintext):
    print(f"\n==================== {title} ====================\n")

    logger = AuditLogger(case_name=title)
    session_mgr = SessionManager(logger)
    negotiate = NegotiationEngine(logger)
    translate = TranslationEngine(logger)

    print(f"Client caps: {client_caps}")
    print(f"Server caps: {server_caps}")

    # --------------------------
    # NEGOTIATION
    # --------------------------
    chosen, reason = negotiate.negotiate(client_caps, server_caps)
    print(f"\nNegotiation Result: {chosen} ({reason})")

    expected_translate = (client_caps[0] != server_caps[0])
    negotiation_correctness.append((expected_translate and chosen == "TRANSLATE") or
                                   (not expected_translate and chosen == server_caps[0]))

    # --------------------------
    # SESSION CREATION
    # --------------------------
    session = session_mgr.create_session(chosen_algo=chosen)

    # --------------------------
    # PLUGINS
    # --------------------------
    rsa = RSAOAEPPlugin()
    aes = AESGCMPlugin()

    # RSA keypair
    kp = rsa.generate_keypair()
    session.metadata["rsa_priv"] = kp["priv"]
    session.metadata["rsa_pub"] = kp["pub"]

    # --------------------------
    # CLIENT ENCRYPTION
    # --------------------------
    if client_caps[0] == "RSA":
        ct = rsa.encrypt(plaintext, session=session)
        envelope_in = UCAPEnvelope("RSA", ct["ciphertext"])
    else:
        ct = aes.encrypt(plaintext, session=session)
        envelope_in = UCAPEnvelope("AES", ct["ciphertext"], ct["nonce"])

    # --------------------------
    # UCAP PROCESSING
    # --------------------------
    if chosen != "TRANSLATE" and client_caps[0] == server_caps[0]:
        print("\nNo translation needed → UCAP PASS-THROUGH MODE")

        if server_caps[0] == "RSA":
            decrypted = rsa.decrypt({"ciphertext": envelope_in.ciphertext}, session=session)
        else:
            decrypted = aes.decrypt(
                {"ciphertext": envelope_in.ciphertext, "nonce": envelope_in.nonce},
                session=session
            )

        translation_latencies.append(0.0)

    else:
        print("\nTranslation required → UCAP TRANSLATE MODE")

        dst_algo = server_caps[0]

        start = time.perf_counter()
        envelope_out = translate.translate(
            src_algo=envelope_in.algo,
            dst_algo=dst_algo,
            envelope=envelope_in,
            session_ctx=session
        )
        end = time.perf_counter()

        latency_ms = (end - start) * 1000
        translation_latencies.append(latency_ms)

        if dst_algo == "AES":
            decrypted = aes.decrypt(
                {"ciphertext": envelope_out.ciphertext, "nonce": envelope_out.nonce},
                session=session
            )
        else:
            decrypted = rsa.decrypt(
                {"ciphertext": envelope_out.ciphertext},
                session=session
            )

    # --------------------------
    # CORRECTNESS CHECK
    # --------------------------
    print("\n--- DEMO RESULTS ---")
    print("Original message:     ", plaintext)
    print("Decrypted at server:  ", decrypted)

    correct = (plaintext == decrypted)
    global_correctness.append(correct)

    if correct:
        print("Correctness:          ✔ PASS")
    else:
        print("Correctness:          ✘ FAIL")

    # --------------------------
    # LOGGING RELIABILITY
    # --------------------------
    logs_ok = check_logs(logger, expected_translate)
    print("Logging Reliability:  ", "✔ OK" if logs_ok else "✘ Missing logs")

    print("----------------------\n")


def main():
    plaintext = b"namah shivaya"

    run_case(
        "CASE 1: COMMON ALGORITHM (RSA ↔ RSA)",
        client_caps=["RSA"],
        server_caps=["RSA"],
        plaintext=plaintext
    )

    run_case(
        "CASE 2: MISMATCH (RSA → AES TRANSLATION)",
        client_caps=["RSA"],
        server_caps=["AES"],
        plaintext=plaintext
    )

    # --------------------------
    # FINAL RESULTS SUMMARY
    # --------------------------
    print("\n==================== PHASE-1 EVALUATION SUMMARY ====================")

    # Correctness
    print(f"Correctness Score:         {sum(global_correctness)}/{len(global_correctness)} "
          f"({(sum(global_correctness)/len(global_correctness))*100:.2f}%)")

    # Negotiation accuracy
    print(f"Negotiation Accuracy:      {sum(negotiation_correctness)}/{len(negotiation_correctness)} "
          f"({(sum(negotiation_correctness)/len(negotiation_correctness))*100:.2f}%)")

    # Translation latency
    lat_values = [x for x in translation_latencies if x > 0]
    if lat_values:
        avg_lat = sum(lat_values) / len(lat_values)
        print(f"Avg Translation Latency:   {avg_lat:.3f} ms")
    else:
        print("Avg Translation Latency:   0 ms (no translation in test)")

    # Logging reliability
    print(f"Logging Reliability:       {sum(log_reliability)}/{len(log_reliability)} "
          f"({(sum(log_reliability)/len(log_reliability))*100:.2f}%)")

    print("=====================================================================\n")


if __name__ == "__main__":
    main()
