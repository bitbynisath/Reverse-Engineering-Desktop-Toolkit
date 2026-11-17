"""Logging configuration for PyRE Studio."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from app.config import get_default_config_dir
from app.constants import APP_NAME, DEFAULT_LOG_FILENAME


def setup_logging(
    log_level: str = "INFO",
    log_to_file: bool = True,
    log_file_path: Path | None = None,
) -> None:
    """Configure root logger for application with console and file handlers.

    Keeps sensitive user content out of logs and standardizes format.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler
    if log_to_file:
        try:
            if log_file_path is None:
                log_file_path = get_default_config_dir() / DEFAULT_LOG_FILENAME

            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            root_logger.info("Logging initialized to file: %s", log_file_path)
        except Exception as exc:
            root_logger.warning("Could not initialize file logger: %s", exc)

    logging.getLogger(APP_NAME).info("%s logging initialized at level %s", APP_NAME, log_level)
