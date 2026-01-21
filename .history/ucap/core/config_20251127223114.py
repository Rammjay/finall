"""
Configuration and constants for UCAP core.
Modify these defaults via environment variables or config file in later phases.
"""

import os

# Logging
LOG_LEVEL = os.environ.get("UCAP_LOG_LEVEL", "INFO")

# Session defaults
SESSION_KEY_BITS = int(os.environ.get("UCAP_SESSION_KEY_BITS", "256"))  # AES-256 by default
SESSION_TTL_SECONDS = int(os.environ.get("UCAP_SESSION_TTL", str(60 * 60)))  # 1 hour

# Negotiation preferences (highest preference first)
# Allowed values should match plugin identifiers
DEFAULT_PREFERENCE_ORDER = os.environ.get(
    "UCAP_PREF_ORDER", "AES,ECC,RSA,CHACHA20"
).split(",")

# Security minimums
MIN_RSA_BITS = int(os.environ.get("UCAP_MIN_RSA_BITS", "2048"))
MIN_AES_BITS = int(os.environ.get("UCAP_MIN_AES_BITS", "128"))

# Plugin path (relative)
PLUGINS_DIR = os.environ.get("UCAP_PLUGINS_DIR", "ucap.plugins")

# Misc
RANDOM_SOURCE = "os.urandom"
