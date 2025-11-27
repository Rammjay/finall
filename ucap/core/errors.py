class UCAPError(Exception):
    """Base exception for UCAP"""

class NegotiationError(UCAPError):
    """Raised when negotiation fails"""

class TranslationError(UCAPError):
    """Raised when translation/crypto fails"""

class SessionError(UCAPError):
    """Session management failure"""

class PluginError(UCAPError):
    """Plugin loading/compatibility error"""

class ConfigError(UCAPError):
    """Configuration problem"""
