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
    """Verify remaining placeholder pages are explicitly labeled with their target phase."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    # In Phase 5, FileAnalyzer, HexViewer, StringExtractor, and PEAnalyzer are active; placeholders start from Phase 6
    placeholder_modules = [
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
        assert widget.module_id == mod_id


def test_pe_analyzer_page_active(qapp: QApplication):
    """Verify PEAnalyzerPage is fully instantiated and active in Phase 5."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    window.navigate_to_page(PAGE_PE_ANALYZER)
    widget = window.pages_stack.currentWidget()
    assert not isinstance(widget, PlaceholderPage)
    assert widget.module_id == PAGE_PE_ANALYZER
    assert hasattr(widget, "load_file")
    assert hasattr(widget, "tabs")
    assert hasattr(widget, "btn_browse")


def test_string_extractor_page_active(qapp: QApplication):
    """Verify StringExtractorPage is fully instantiated and active in Phase 4."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    window.navigate_to_page(PAGE_STRING_EXTRACTOR)
    widget = window.pages_stack.currentWidget()
    assert not isinstance(widget, PlaceholderPage)
    assert widget.module_id == PAGE_STRING_EXTRACTOR
    assert hasattr(widget, "load_file")
    assert hasattr(widget, "table")
    assert hasattr(widget, "btn_browse")


def test_hex_viewer_page_active(qapp: QApplication):
    """Verify HexViewerPage is fully instantiated and active in Phase 3."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    window.navigate_to_page(PAGE_HEX_VIEWER)
    widget = window.pages_stack.currentWidget()
    assert not isinstance(widget, PlaceholderPage)
    assert widget.module_id == PAGE_HEX_VIEWER
    assert hasattr(widget, "load_file")
    assert hasattr(widget, "hex_table")
    assert hasattr(widget, "btn_open_file")


def test_file_analyzer_page_active(qapp: QApplication):
    """Verify FileAnalyzerPage is fully instantiated and active in Phase 2."""
    config = AppConfig()
    _, window, _ = create_app(argv=[], config=config)

    window.navigate_to_page(PAGE_FILE_ANALYZER)
    widget = window.pages_stack.currentWidget()
    assert not isinstance(widget, PlaceholderPage)
    assert widget.module_id == PAGE_FILE_ANALYZER
    assert hasattr(widget, "load_file")
    assert hasattr(widget, "btn_select_file")
    assert hasattr(widget, "btn_export_json")


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
