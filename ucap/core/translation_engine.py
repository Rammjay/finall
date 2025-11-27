# ucap/core/translation_engine.py

from typing import Dict, Any
from .audit_logger import AuditLogger
from .crypto_interface import get_plugin
from .errors import TranslationError
from .message_envelope import UCAPEnvelope
from .capabilities import normalize_cap

class TranslationEngine:
    """
    Phase-2 translation:
       src plugin decrypts
       dst plugin encrypts
    Produces a UCAPEnvelope object.
    """

    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def translate(self,
                  src_algo: str,
                  dst_algo: str,
                  envelope: UCAPEnvelope,
                  session_ctx) -> UCAPEnvelope:

        src_algo = normalize_cap(src_algo)
        dst_algo = normalize_cap(dst_algo)

        self.logger.log("TRANSLATE_START", f"{src_algo} -> {dst_algo}")

        # -------- 1. Load plugins --------
        try:
            src_plugin = get_plugin(src_algo)
        except Exception:
            raise TranslationError(f"Missing source plugin: {src_algo}")

        try:
            dst_plugin = get_plugin(dst_algo)
        except Exception:
            raise TranslationError(f"Missing destination plugin: {dst_algo}")

        # -------- 2. Decrypt --------
        plaintext = src_plugin.decrypt(
            payload={"ciphertext": envelope.ciphertext, "nonce": envelope.nonce},
            session=session_ctx
        )

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TranslationError("Source decryption did not return bytes")

        # -------- 3. Encrypt into destination --------
        enc = dst_plugin.encrypt(
            plaintext=plaintext,
            session=session_ctx
        )

        ct = enc.get("ciphertext")
        nonce = enc.get("nonce")
        meta = {"src_algo": src_algo, "dst_algo": dst_algo}

        # -------- 4. New envelope --------
        out = UCAPEnvelope(
            algo=dst_algo,
            ciphertext=ct,
            nonce=nonce,
            meta=meta
        )

        self.logger.log("TRANSLATE_DONE", f"output_algo={dst_algo} ct_len={len(ct)}")

        return out
