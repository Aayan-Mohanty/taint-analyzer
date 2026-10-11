"""Load and validate the sources / sinks / sanitizers configuration.

Names are dotted call names as they appear in the source code, e.g. the
call `cursor.execute(q)` has the name "cursor.execute". Matching is purely
by this text, not by the object's real type (a documented limitation).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.json")


class ConfigError(ValueError):
    """Raised when the configuration file is missing fields or malformed."""


@dataclass(frozen=True)
class SinkSpec:
    category: str               # e.g. "sql_injection"
    args: Tuple[int, ...]       # positional argument indexes that are dangerous


@dataclass(frozen=True)
class Config:
    sources: frozenset
    sinks: Dict[str, SinkSpec]
    sanitizers: frozenset

    def is_source(self, name: Optional[str]) -> bool:
        return name is not None and name in self.sources

    def is_sanitizer(self, name: Optional[str]) -> bool:
        return name is not None and name in self.sanitizers

    def sink_spec(self, name: Optional[str]) -> Optional[SinkSpec]:
        return self.sinks.get(name) if name is not None else None


def load_config(path: Union[str, Path, None] = None) -> Config:
    """Read the JSON config; uses the bundled config.json when path is None."""
    path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid JSON in {path}: {e}") from None

    for key in ("sources", "sinks", "sanitizers"):
        if key not in raw:
            raise ConfigError(f"config is missing required key '{key}'")

    if not isinstance(raw["sources"], list) or not all(isinstance(s, str) for s in raw["sources"]):
        raise ConfigError("'sources' must be a list of strings")
    if not isinstance(raw["sanitizers"], list) or not all(isinstance(s, str) for s in raw["sanitizers"]):
        raise ConfigError("'sanitizers' must be a list of strings")
    if not isinstance(raw["sinks"], dict):
        raise ConfigError("'sinks' must be an object mapping names to specs")

    sinks: Dict[str, SinkSpec] = {}
    for name, spec in raw["sinks"].items():
        if not isinstance(spec, dict) or "category" not in spec or "args" not in spec:
            raise ConfigError(f"sink '{name}' needs 'category' and 'args'")
        args = spec["args"]
        if not isinstance(args, list) or not all(isinstance(a, int) and a >= 0 for a in args):
            raise ConfigError(f"sink '{name}': 'args' must be a list of non-negative integers")
        sinks[name] = SinkSpec(category=str(spec["category"]), args=tuple(args))

    return Config(
        sources=frozenset(raw["sources"]),
        sinks=sinks,
        sanitizers=frozenset(raw["sanitizers"]),
    )
