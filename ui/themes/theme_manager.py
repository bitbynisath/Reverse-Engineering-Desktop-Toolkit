"""Theme management for PyRE Studio."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtWidgets import QApplication

from app.constants import DEFAULT_THEME, THEME_DARK, THEME_LIGHT

logger = logging.getLogger(__name__)


class ThemeManager:
    """Manages application style sheets and theme switching."""

    def __init__(self, current_theme: str = DEFAULT_THEME) -> None:
        self._current_theme = current_theme
        self._themes_dir = Path(__file__).parent

    @property
    def current_theme(self) -> str:
        return self._current_theme

    def get_theme_stylesheet(self, theme_name: str) -> str:
        """Read and return stylesheet string for the requested theme."""
        theme_file = self._themes_dir / f"{theme_name}_theme.qss"
        if not theme_file.is_file():
            logger.warning(
                "Theme file '%s' not found. Falling back to dark theme.", theme_file
            )
            theme_file = self._themes_dir / "dark_theme.qss"

        try:
            return theme_file.read_text(encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to read theme stylesheet %s: %s", theme_file, exc)
            return ""

    def apply_theme(self, app: QApplication, theme_name: str) -> bool:
        """Apply the specified theme to the entire application."""
        normalized_theme = theme_name.lower().strip()
        if normalized_theme not in (THEME_DARK, THEME_LIGHT):
            normalized_theme = THEME_DARK

        stylesheet = self.get_theme_stylesheet(normalized_theme)
        if stylesheet:
            app.setStyleSheet(stylesheet)
            self._current_theme = normalized_theme
            logger.info("Applied '%s' theme successfully.", normalized_theme)
            return True

        logger.warning("Could not apply '%s' theme.", theme_name)
        return False

    def toggle_theme(self, app: QApplication) -> str:
        """Toggle between dark and light themes and return new theme name."""
        new_theme = THEME_LIGHT if self._current_theme == THEME_DARK else THEME_DARK
        self.apply_theme(app, new_theme)
        return new_theme
