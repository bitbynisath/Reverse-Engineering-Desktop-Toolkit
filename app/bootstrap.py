"""Application bootstrap and initialization routines."""

from __future__ import annotations

import logging
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.config import AppConfig, load_config
from app.constants import APP_DOMAIN, APP_NAME, APP_ORGANIZATION, APP_VERSION
from app.logging_config import setup_logging
from ui.main_window import MainWindow
from ui.themes.theme_manager import ThemeManager

logger = logging.getLogger(__name__)


def create_app(
    argv: list[str] | None = None,
    config: AppConfig | None = None,
) -> tuple[QApplication, MainWindow, AppConfig]:
    """Initialize application context, styling, and main window."""
    if argv is None:
        argv = sys.argv

    # Ensure single QApplication instance
    app = QApplication.instance()
    if app is None:
        # High-DPI attributes are enabled by default in Qt 6
        app = QApplication(argv)

    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_ORGANIZATION)
    app.setOrganizationDomain(APP_DOMAIN)

    # Load configuration if not provided
    if config is None:
        config = load_config()

    # Configure logging
    setup_logging(log_level=config.log_level)
    logger.info("Starting %s v%s...", APP_NAME, APP_VERSION)

    # Apply active theme
    theme_manager = ThemeManager(current_theme=config.theme)
    theme_manager.apply_theme(app, config.theme)

    # Create main window
    main_window = MainWindow(config=config, theme_manager=theme_manager)

    return app, main_window, config


def run(argv: list[str] | None = None) -> int:
    """Entry point for executing the PyRE Studio GUI desktop application."""
    try:
        app, main_window, _ = create_app(argv)
        main_window.show()
        return app.exec()
    except Exception as exc:
        logger.critical("Fatal error occurred during application execution: %s", exc, exc_info=True)
        return 1
