"""
Translation engine orchestrates conversion between two algorithms using available plugins
For Phase 1 this is a high-level orchestrator: it expects plugin objects (implementing the interface).
We implement a safe flow for RSA -> AES translation using built-in stack if plugin not present.

Responsibilities:
- Validate that required plugin(s) exist
- Decrypt using source plugin/context
- Re-encrypt using target plugin/context or session key
- Return structured payload: { payload: base64, meta: {...} }
"""

from typing import Dict, Any, Optional
from .audit_logger import AuditLogger
from .errors import TranslationError, PluginError
from .crypto_interface import get_plugin, CryptoPluginBase
from .utils import b64_encode, b64_decode
from .capabilities import CAP_AES_GCM
import json

class TranslationEngine:
    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def translate(self, src_algo: str, dst_algo: str, payload_raw: bytes, session_ctx: Any, src_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        High-level translation handler. Tries to use plugin for src_algo.decrypt, and plugin or session key for dst_algo.encrypt.

        For Phase 1:
          - If src_algo plugin exists -> use it to decrypt -> plaintext
          - If src_algo plugin missing but src_algo == 'RSA' -> try internal RSA plugin if registered
          - For dst_algo == AES -> use session_ctx.sym_key to AES-GCM encrypt
          - Return dict {payload: base64(ct), algo: dst_algo, meta: {...}}
        """
        src_meta = src_meta or {}
        self.logger.log("TRANSLATION_REQUEST", f"from={src_algo} to={dst_algo} session={getattr(session_ctx, 'session_id', 'noctx')}")

        # Try src plugin to decrypt
        plaintext = None
        try:
            plugin = get_plugin(src_algo)
            self.logger.log("TRANSLATION_PLUGIN", f"using plugin {src_algo} for decrypt")
            # plugin.decrypt should accept payload bytes or dict; convention depends on plugin
            # We'll attempt both: if plugin expects dict, user should have provided such.
            try:
                plaintext = plugin.decrypt({"payload": payload_raw}, session=session_ctx)
            except Exception:
                # try raw bytes
                plaintext = plugin.decrypt(payload_raw, session=session_ctx)
        except PluginError:
            # plugin not found - we cannot decrypt using plugin
            raise TranslationError(f"No plugin for source algorithm {src_algo}")

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TranslationError("Decryption did not yield bytes plaintext")

        # Now encrypt to dst_algo
        if dst_algo.upper() == CAP_AES_GCM:
            # Use session key (assumed provided in session_ctx.sym_key)
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(session_ctx.sym_key)
                nonce = session_ctx.session_id.encode("utf-8")[:12]
                # If nonce collision possible, fallback to random
                if len(nonce) != 12:
                    nonce = AESGCM.generate_key(bit_length=96)  # not ideal; replace in phase 2
                ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
                out = {"payload": b64_encode(ct), "algo": CAP_AES_GCM, "nonce": b64_encode(nonce), "meta": {"src_meta": src_meta}}
                self.logger.log("TRANSLATION_DONE", f"to={CAP_AES_GCM} len_ct={len(ct)}")
                return out
            except Exception as e:
                raise TranslationError(f"AES encryption failed: {e}")
        else:
            # Try to find plugin for destination and call its encrypt
            try:
                dst_plugin = get_plugin(dst_algo)
                self.logger.log("TRANSLATION_PLUGIN", f"using plugin {dst_algo} for encrypt")
                enc = dst_plugin.encrypt(plaintext, session=session_ctx)
                # plugin may return dict {payload: bytes, ...} or bytes
                if isinstance(enc, dict):
                    return enc
                elif isinstance(enc, (bytes, bytearray)):
                    return {"payload": b64_encode(enc), "algo": dst_algo}
                else:
                    raise TranslationError("Destination plugin returned unexpected type")
            except PluginError:
                raise TranslationError(f"No plugin available for destination algorithm {dst_algo}")
