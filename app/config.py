"""Configuration management for PyRE Studio."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.constants import (
    APP_ORGANIZATION,
    DEFAULT_HEX_BYTES_PER_ROW,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MIN_STRING_LEN,
    DEFAULT_THEME,
)

logger = logging.getLogger(__name__)


def get_default_config_dir() -> Path:
    """Return the default configuration directory based on OS standard paths."""
    config_dir = Path.home() / f".{APP_ORGANIZATION.lower()}"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_default_config_path() -> Path:
    """Return the path to the config JSON file."""
    return get_default_config_dir() / "config.json"


@dataclass
class AppConfig:
    """Application user configuration dataclass."""

    theme: str = DEFAULT_THEME
    default_analysis_dir: str = field(default_factory=lambda: str(Path.home()))
    hex_bytes_per_row: int = DEFAULT_HEX_BYTES_PER_ROW
    min_string_len: int = DEFAULT_MIN_STRING_LEN
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    log_level: str = DEFAULT_LOG_LEVEL
    window_width: int = 1280
    window_height: int = 820
    window_maximized: bool = False
    recent_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppConfig:
        """Create AppConfig from dictionary with validation."""
        valid_keys = cls.__dataclass_fields__.keys()
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load configuration from disk, falling back to defaults if missing or corrupt."""
    path = config_path or get_default_config_path()
    if not path.is_file():
        logger.info("Config file not found at %s. Using default settings.", path)
        return AppConfig()

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        config = AppConfig.from_dict(data)
        logger.debug("Loaded configuration from %s", path)
        return config
    except Exception as exc:
        logger.warning(
            "Failed to load configuration from %s: %s. Using defaults.", path, exc
        )
        return AppConfig()


def save_config(config: AppConfig, config_path: Path | None = None) -> bool:
    """Save configuration to disk safely."""
    path = config_path or get_default_config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = config.to_dict()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.debug("Saved configuration to %s", path)
        return True
    except Exception as exc:
        logger.error("Failed to save configuration to %s: %s", path, exc)
        return False
