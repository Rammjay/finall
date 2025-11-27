"""
Plugin interface for crypto modules.

Each plugin (e.g., AES GCM, RSA OAEP, X25519) should implement the following API (class):
- class CryptoPlugin:
    - id: str  # capability id, e.g. 'AES' or 'RSA'
    - def encrypt(self, plaintext: bytes, **kwargs) -> dict
    - def decrypt(self, payload: dict, **kwargs) -> bytes
    - def generate_keypair(self) -> dict  # for asymmetric, returns {priv, pub}
    - def load_private(self, raw: bytes) -> object  # optional helper
    - def load_public(self, raw: bytes) -> object
    - def info(self) -> dict

This module also contains a small plugin loader (scans module path or expects a registry).
"""

import importlib
import pkgutil
import inspect
from typing import Dict, Any, Optional
from .errors import PluginError
from .config import PLUGINS_DIR

# Simple plugin registry (explicit). We'll also allow dynamic discovery.
_PLUGIN_REGISTRY: Dict[str, Any] = {}

class CryptoPluginBase:
    """
    Base class (interface) for plugins.
    Plugins should inherit from this or implement the same methods.
    """
    id: str = "BASE"

    def encrypt(self, plaintext: bytes, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError()

    def decrypt(self, payload: Dict[str, Any], **kwargs) -> bytes:
        raise NotImplementedError()

    def generate_keypair(self) -> Dict[str, bytes]:
        raise NotImplementedError()

    def info(self) -> Dict[str, Any]:
        return {"id": self.id}

def register_plugin(plugin: CryptoPluginBase):
    pid = getattr(plugin, "id", None)
    if not pid:
        raise PluginError("Plugin missing id attribute")
    _PLUGIN_REGISTRY[pid] = plugin

def get_plugin(pid: str) -> CryptoPluginBase:
    plugin = _PLUGIN_REGISTRY.get(pid)
    if not plugin:
        raise PluginError(f"Plugin {pid} not registered")
    return plugin

def discover_plugins(package: Optional[str] = None) -> Dict[str, CryptoPluginBase]:
    """
    Discover plugins inside the PLUGINS_DIR package (if available).
    Each plugin module should call register_plugin(...) at import time.
    """
    pkg_name = package or PLUGINS_DIR
    discovered = {}
    try:
        pkg = importlib.import_module(pkg_name)
    except Exception as e:
        # no plugin package available in early prototyping
        return {}

    for finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        full_name = f"{pkg_name}.{name}"
        try:
            mod = importlib.import_module(full_name)
            # modules should register themselves
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if inspect.isclass(attr) and hasattr(attr, "id"):
                    pid = getattr(attr, "id")
                    # instantiate if necessary
                    try:
                        inst = attr()
                    except Exception:
                        continue
                    register_plugin(inst)
                    discovered[pid] = inst
        except Exception:
            continue
    return discovered
