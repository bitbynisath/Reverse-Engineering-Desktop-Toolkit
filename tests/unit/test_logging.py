"""Unit tests for logging configuration."""

import logging
from pathlib import Path
from app.logging_config import setup_logging
from app.constants import APP_NAME


def test_logging_initialization(tmp_path: Path):
    """Verify logging initializes file and stream handlers cleanly."""
    log_file = tmp_path / "test_exec.log"
    setup_logging(log_level="DEBUG", log_to_file=True, log_file_path=log_file)

    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG
    assert len(root_logger.handlers) >= 2

    test_logger = logging.getLogger(f"{APP_NAME}.test")
    test_logger.info("Test log line for verification")

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "Test log line for verification" in content
