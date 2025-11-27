# ucap/core/plugin_loader.py

import importlib
import pkgutil
import inspect
from typing import Dict
from .crypto_interface import CryptoPluginBase, register_plugin
from .config import PLUGINS_DIR
from .audit_logger import AuditLogger

class PluginLoader:
    """
    Discovers all plugin modules inside ucap.plugins and auto-registers them.
    Each plugin must call register_plugin(...) in its module.
    """

    def __init__(self, logger: AuditLogger):
        self.logger = logger

    def discover(self) -> Dict[str, CryptoPluginBase]:
        self.logger.log("PLUGIN_DISCOVERY", f"Scanning {PLUGINS_DIR}")

        try:
            pkg = importlib.import_module(PLUGINS_DIR)
        except Exception as e:
            self.logger.log("PLUGIN_DISCOVERY_ERROR", str(e))
            return {}

        for loader, module_name, is_pkg in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            try:
                mod = importlib.import_module(module_name)
                self.logger.log("PLUGIN_LOADED", f"module={module_name}")
            except Exception as e:
                self.logger.log("PLUGIN_LOAD_FAILED", f"{module_name}: {e}")

        from .crypto_interface import _PLUGIN_REGISTRY
        return dict(_PLUGIN_REGISTRY)
