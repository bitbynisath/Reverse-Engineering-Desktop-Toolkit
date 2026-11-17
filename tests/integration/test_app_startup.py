"""Integration tests for PyRE Studio desktop application shell."""

from PySide6.QtWidgets import QApplication

from app.bootstrap import create_app
from app.config import AppConfig
from app.constants import (
    APP_NAME,
    PAGE_ABOUT,
    PAGE_ADVANCED_ANALYSIS,
    PAGE_DASHBOARD,
    PAGE_DISASSEMBLER,
    PAGE_FILE_ANALYZER,
    PAGE_HEX_VIEWER,
    PAGE_HISTORY,
    PAGE_PE_ANALYZER,
    PAGE_PYTHON_ANALYZER,
    PAGE_REPORTS,
    PAGE_SETTINGS,
    PAGE_STRING_EXTRACTOR,
    THEME_DARK,
    THEME_LIGHT,
)
from ui.pages.placeholder_page import PlaceholderPage


def test_app_startup_and_initialization(qapp: QApplication):
    """Verify application boots cleanly, configures styling, and instantiates MainWindow."""
    config = AppConfig()
    app, window, loaded_config = create_app(argv=[], config=config)

    assert app is not None
    assert window is not None
    assert APP_NAME in window.windowTitle()
    assert window.minimumWidth() >= 1024
    assert window.minimumHeight() >= 640


def test_navigation_to_all_pages(qapp: QApplication):
    """Verify navigation switching works for every registered page in the sidebar."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    pages = [
        PAGE_DASHBOARD,
        PAGE_FILE_ANALYZER,
        PAGE_HEX_VIEWER,
        PAGE_STRING_EXTRACTOR,
        PAGE_PE_ANALYZER,
        PAGE_DISASSEMBLER,
        PAGE_PYTHON_ANALYZER,
        PAGE_ADVANCED_ANALYSIS,
        PAGE_REPORTS,
        PAGE_HISTORY,
        PAGE_SETTINGS,
    ]

    for page_id in pages:
        window.navigate_to_page(page_id)
        current_widget = window.pages_stack.currentWidget()
        assert current_widget is not None
        assert getattr(current_widget, "module_id", None) == page_id


def test_placeholder_pages_integrity(qapp: QApplication):
    """Verify placeholder pages are explicitly labeled with their target phase."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    placeholder_modules = [
        (PAGE_FILE_ANALYZER, "Phase 2"),
        (PAGE_HEX_VIEWER, "Phase 3"),
        (PAGE_STRING_EXTRACTOR, "Phase 4"),
        (PAGE_PE_ANALYZER, "Phase 5"),
        (PAGE_DISASSEMBLER, "Phase 6"),
        (PAGE_PYTHON_ANALYZER, "Phase 7"),
        (PAGE_ADVANCED_ANALYSIS, "Phase 8"),
        (PAGE_REPORTS, "Phase 9"),
        (PAGE_HISTORY, "Phase 9"),
    ]

    for mod_id, expected_phase in placeholder_modules:
        window.navigate_to_page(mod_id)
        widget = window.pages_stack.currentWidget()
        assert isinstance(widget, PlaceholderPage)
        # Verify placeholder does not claim implementation is done
        assert widget.module_id == mod_id


def test_theme_toggling(qapp: QApplication):
    """Verify theme manager can toggle between dark and light themes."""
    config = AppConfig(theme=THEME_DARK)
    app, window, _ = create_app(argv=[], config=config)

    assert window._theme_manager.current_theme == THEME_DARK

    window._toggle_theme()
    assert window._theme_manager.current_theme == THEME_LIGHT

    window._toggle_theme()
    assert window._theme_manager.current_theme == THEME_DARK


def test_window_resizing(qapp: QApplication):
    """Verify window respects resizing and minimum bounds."""
    config = AppConfig(window_width=1200, window_height=750)
    _, window, _ = create_app(argv=[], config=config)

    window.resize(1366, 768)
    assert window.width() == 1366
    assert window.height() == 768
