"""Pytest fixtures and configuration for PyRE Studio test suite."""

import os
import sys
from pathlib import Path
import pytest
from PySide6.QtWidgets import QApplication

# Ensure offscreen rendering for headless / CI / testing environments
os.environ["QT_QPA_PLATFORM"] = "offscreen"


@pytest.fixture(scope="session")
def qapp():
    """Ensure a single persistent QApplication instance across test session."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture
def tmp_config_path(tmp_path: Path) -> Path:
    """Fixture providing a temporary configuration file path."""
    return tmp_path / "test_config.json"
