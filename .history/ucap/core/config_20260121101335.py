"""
UCAP Core Configuration
----------------------

Central configuration file for:
- Security policies
- Session handling
- Negotiation preferences
- Cryptographic limits

All values can be overridden using environment variables.
"""

import os

# =====================================================
# Logging Configuration
# =====================================================

LOG_LEVEL = os.environ.get("UCAP_LOG_LEVEL", "INFO")

# =====================================================
# Session Configuration
# =====================================================

# AES session key size (bits)
SESSION_KEY_BITS = int(os.environ.get("UCAP_SESSION_KEY_BITS", "256"))

# Session validity (seconds)
SESSION_TTL_SECONDS = int(
    os.environ.get("UCAP_SESSION_TTL", str(60 * 60))
)

# Replay protection
ENABLE_REPLAY_PROTECTION = True
MAX_NONCES_PER_SESSION = 1000

# =====================================================
# Negotiation & Security Policy
# =====================================================

# Preference order (highest → lowest)
# Must match plugin identifiers
DEFAULT_PREFERENCE_ORDER = os.environ.get(
    "UCAP_PREF_ORDER",
    "AES,ECC,CHACHA20,RSA"
).split(",")

# Security strength levels (higher = stronger)
SECURITY_LEVEL = {
    "AES": 3,
    "ECC": 3,
    "CHACHA20": 3,
    "RSA": 2
}

# Minimum acceptable strength
MIN_SECURITY_LEVEL = 2

# =====================================================
# Crypto Minimum Requirements
# =====================================================

MIN_RSA_BITS = int(os.environ.get("UCAP_MIN_RSA_BITS", "2048"))
MIN_AES_BITS = int(os.environ.get("UCAP_MIN_AES_BITS", "128"))

# =====================================================
# Plugin System
# =====================================================

# Plugin discovery path
PLUGINS_DIR = os.environ.get("UCAP_PLUGINS_DIR", "ucap.plugins")

# Allowed crypto plugins
ALLOWED_PLUGINS = {
    "AES",
    "ECC",
    "RSA",
    "CHACHA20"
}

# =====================================================
# Miscellaneous
# =====================================================

# Random source for crypto operations
RANDOM_SOURCE = "os.urandom"

# Enable strict security mode (reject weak crypto)
STRICT_SECURITY = True
# =====================================================
# Identity & Trust Model
# =====================================================

# Trust levels
TRUST_LOW = 1       # Untrusted / anonymous
TRUST_MEDIUM = 2    # Authenticated client
TRUST_HIGH = 3      # Fully trusted system

# Minimum trust required to create session
MIN_REQUIRED_TRUST = TRUST_MEDIUM

# Optional role mapping (for future extension)
ROLE_TRUST_MAP = {
    "guest": TRUST_LOW,
    "client": TRUST_MEDIUM,
    "admin": TRUST_HIGH
}
