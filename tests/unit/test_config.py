"""Unit tests for configuration loading and persistence."""

from pathlib import Path
from app.config import AppConfig, load_config, save_config
from app.constants import DEFAULT_THEME, THEME_LIGHT


def test_default_config_initialization():
    """Verify default configuration attributes."""
    config = AppConfig()
    assert config.theme == DEFAULT_THEME
    assert config.hex_bytes_per_row == 16
    assert config.min_string_len == 4
    assert config.max_file_size_mb == 100
    assert config.log_level == "INFO"
    assert config.window_width == 1280
    assert config.window_height == 820


def test_config_save_and_load(tmp_config_path: Path):
    """Verify configuration can be saved and reloaded accurately."""
    custom_config = AppConfig(
        theme=THEME_LIGHT,
        hex_bytes_per_row=24,
        min_string_len=6,
        max_file_size_mb=250,
        log_level="DEBUG",
        window_width=1400,
        window_height=900,
    )

    success = save_config(custom_config, tmp_config_path)
    assert success is True
    assert tmp_config_path.exists()

    loaded = load_config(tmp_config_path)
    assert loaded.theme == THEME_LIGHT
    assert loaded.hex_bytes_per_row == 24
    assert loaded.min_string_len == 6
    assert loaded.max_file_size_mb == 250
    assert loaded.log_level == "DEBUG"
    assert loaded.window_width == 1400
    assert loaded.window_height == 900


def test_load_corrupt_config(tmp_config_path: Path):
    """Verify fallback to defaults if config file is corrupted."""
    tmp_config_path.write_text("{invalid_json: true", encoding="utf-8")
    loaded = load_config(tmp_config_path)
    assert loaded.theme == DEFAULT_THEME
    assert loaded.hex_bytes_per_row == 16
