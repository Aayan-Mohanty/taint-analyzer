"""Static taint analyzer for injection vulnerabilities in a Python subset."""

from .config import Config, ConfigError, SinkSpec, load_config
from .models import CFG, EMPTY_TAINT, BasicBlock, Finding, TaintSet

__all__ = [
    "BasicBlock", "CFG", "Config", "ConfigError", "EMPTY_TAINT",
    "Finding", "SinkSpec", "TaintSet", "load_config",
]
