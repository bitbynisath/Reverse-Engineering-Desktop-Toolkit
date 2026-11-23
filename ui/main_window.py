"""Main Application Window for PyRE Studio."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from app.config import AppConfig, save_config
from app.constants import (
    APP_NAME,
    APP_VERSION,
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
from core.exceptions import FileAccessError, ValidationError
from core.validators import validate_file_path
from ui.dashboard.dashboard_page import DashboardPage
from ui.dialogs.about_dialog import AboutDialog
from ui.navigation import SidebarNavigation
from ui.pages.advanced_analysis_page import AdvancedAnalysisPage
from ui.pages.disassembler_page import DisassemblerPage
from ui.pages.file_analyzer_page import FileAnalyzerPage
from ui.pages.hex_viewer_page import HexViewerPage
from ui.pages.history_page import HistoryPage
from ui.pages.pe_analyzer_page import PEAnalyzerPage
from ui.pages.python_analyzer_page import PythonAnalyzerPage
from ui.pages.reports_page import ReportsPage
from ui.pages.settings_page import SettingsPage
from ui.pages.string_extractor_page import StringExtractorPage
from ui.themes.theme_manager import ThemeManager

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main desktop application window."""

    def __init__(
        self,
        config: AppConfig,
        theme_manager: ThemeManager,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._theme_manager = theme_manager
        self._current_file: Path | None = None

        self.setWindowTitle(f"{APP_NAME} - Static Binary Analysis Toolkit")
        self.setMinimumSize(1024, 640)
        self.resize(self._config.window_width, self._config.window_height)

        self._page_indices: dict[str, int] = {}

        self._init_ui()
        self._setup_shortcuts()
        self._setup_status_bar()

    def _init_ui(self) -> None:
        # Central widget
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Top Header Bar
        top_header = self._create_top_header()
        root_layout.addWidget(top_header)

        # Main splitter (Sidebar + Stacked pages)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)

        # Navigation Sidebar
        self.sidebar = SidebarNavigation(self)
        self.sidebar.page_selected.connect(self.navigate_to_page)
        splitter.addWidget(self.sidebar)

        # Stacked Pages
        self.pages_stack = QStackedWidget(self)
        self._register_pages()
        splitter.addWidget(self.pages_stack)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        root_layout.addWidget(splitter)

    def _create_top_header(self) -> QWidget:
        header = QWidget(self)
        header.setObjectName("topHeaderBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 8, 16, 8)
        header_layout.setSpacing(12)

        lbl_header_title = QLabel(f"<b>{APP_NAME}</b> &nbsp;<span style='color: #6c7086;'>|</span>&nbsp; Desktop Toolkit")
        lbl_header_title.setStyleSheet("font-size: 13px; color: #cdd6f4;")
        header_layout.addWidget(lbl_header_title)

        header_layout.addStretch()

        # Search / Quick Filter Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Quick search modules, offsets, or symbols...")
        self.search_input.setFixedWidth(280)
        self.search_input.returnPressed.connect(self._on_search_submitted)
        header_layout.addWidget(self.search_input)

        # Theme toggle button
        self.btn_theme_toggle = QPushButton("Theme")
        self.btn_theme_toggle.setToolTip("Toggle Dark/Light Interface Theme")
        self.btn_theme_toggle.setCursor(Qt.PointingHandCursor)
        self.btn_theme_toggle.clicked.connect(self._toggle_theme)
        header_layout.addWidget(self.btn_theme_toggle)

        # Settings button
        btn_settings = QPushButton("Settings")
        btn_settings.setCursor(Qt.PointingHandCursor)
        btn_settings.clicked.connect(lambda: self.navigate_to_page(PAGE_SETTINGS))
        header_layout.addWidget(btn_settings)

        # Help / About button
        btn_about = QPushButton("Help")
        btn_about.setCursor(Qt.PointingHandCursor)
        btn_about.clicked.connect(self.show_about_dialog)
        header_layout.addWidget(btn_about)

        return header

    def _register_pages(self) -> None:
        """Instantiate and register all application module pages into the stack."""
        self.dashboard_page = DashboardPage(self)
        self.dashboard_page.open_file_requested.connect(self.open_file_dialog)
        self.dashboard_page.navigate_requested.connect(self.navigate_to_page)
        self._add_page(PAGE_DASHBOARD, self.dashboard_page)

        self.file_analyzer_page = FileAnalyzerPage(self)
        self.file_analyzer_page.file_analyzed.connect(self._on_file_analyzed)
        self.file_analyzer_page.file_analyzed.connect(self._on_file_analyzed)
        self._add_page(PAGE_FILE_ANALYZER, self.file_analyzer_page)

        self.hex_viewer_page = HexViewerPage(self)
        self.hex_viewer_page.file_loaded.connect(self._on_file_analyzed)
        self._add_page(PAGE_HEX_VIEWER, self.hex_viewer_page)

        self.string_extractor_page = StringExtractorPage(self)
        self.string_extractor_page.file_loaded.connect(self._on_file_analyzed)
        self._add_page(PAGE_STRING_EXTRACTOR, self.string_extractor_page)

        self.pe_analyzer_page = PEAnalyzerPage(self)
        self.pe_analyzer_page.file_loaded.connect(self._on_file_analyzed)
        self._add_page(PAGE_PE_ANALYZER, self.pe_analyzer_page)

        self.disassembler_page = DisassemblerPage(self)
        self.disassembler_page.file_loaded.connect(self._on_file_analyzed)
        self._add_page(PAGE_DISASSEMBLER, self.disassembler_page)

        self.python_analyzer_page = PythonAnalyzerPage(self)
        self._add_page(PAGE_PYTHON_ANALYZER, self.python_analyzer_page)

        self.advanced_analysis_page = AdvancedAnalysisPage(self)
        self._add_page(PAGE_ADVANCED_ANALYSIS, self.advanced_analysis_page)

        self.reports_page = ReportsPage(self)
        self._add_page(PAGE_REPORTS, self.reports_page)

        self.history_page = HistoryPage(self)
        self._add_page(PAGE_HISTORY, self.history_page)

        self.settings_page = SettingsPage(self._config, self)
        self.settings_page.theme_changed.connect(self._on_theme_changed_from_settings)
        self._add_page(PAGE_SETTINGS, self.settings_page)

    def _add_page(self, page_id: str, widget: QWidget) -> None:
        idx = self.pages_stack.addWidget(widget)
        self._page_indices[page_id] = idx

    def _setup_status_bar(self) -> None:
        status_bar = QStatusBar(self)
        self.setStatusBar(status_bar)

        self.lbl_status_msg = QLabel("Ready")
        self.lbl_status_msg.setStyleSheet("margin-left: 12px; color: #a6adc8;")

        self.lbl_current_file = QLabel("Current file: None")
        self.lbl_current_file.setStyleSheet("color: #89b4fa; font-weight: 500;")

        self.lbl_version_status = QLabel(f"v{APP_VERSION}  |  Static Mode")
        self.lbl_version_status.setStyleSheet("margin-right: 12px; color: #6c7086;")

        status_bar.addWidget(self.lbl_status_msg, 1)
        status_bar.addPermanentWidget(self.lbl_current_file, 2)
        status_bar.addPermanentWidget(self.lbl_version_status, 0)

    def _setup_shortcuts(self) -> None:
        # Ctrl+O: Open file
        open_action = QAction("Open File", self)
        open_action.setShortcut(QKeySequence.Open)
        open_action.triggered.connect(self.open_file_dialog)
        self.addAction(open_action)

        # Ctrl+,: Settings
        settings_action = QAction("Settings", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(lambda: self.navigate_to_page(PAGE_SETTINGS))
        self.addAction(settings_action)

        # F1: Help / About
        help_action = QAction("Help", self)
        help_action.setShortcut(QKeySequence.HelpContents)
        help_action.triggered.connect(self.show_about_dialog)
        self.addAction(help_action)

    def navigate_to_page(self, page_id: str) -> None:
        """Switch current view to the specified module page."""
        if page_id == PAGE_ABOUT:
            self.show_about_dialog()
            return

        idx = self._page_indices.get(page_id)
        if idx is not None:
            self.pages_stack.setCurrentIndex(idx)
            self.sidebar.select_page(page_id)
            self.lbl_status_msg.setText(f"Viewing {page_id.replace('_', ' ').title()}")
            logger.debug("Navigated to page: %s", page_id)

            # Auto-sync currently analyzed file into Hex Viewer, String Extractor, or PE Analyzer if opened
            if page_id == PAGE_HEX_VIEWER and self._current_file:
                if self.hex_viewer_page._current_file != self._current_file:
                    self.hex_viewer_page.load_file(self._current_file)
            elif page_id == PAGE_STRING_EXTRACTOR and self._current_file:
                if self.string_extractor_page._current_file != self._current_file:
                    self.string_extractor_page.load_file(self._current_file)
            elif page_id == PAGE_PE_ANALYZER and self._current_file:
                if self.pe_analyzer_page._current_file != self._current_file:
                    self.pe_analyzer_page.load_file(self._current_file)
            elif page_id == PAGE_DISASSEMBLER and self._current_file:
                if self.disassembler_page._current_file != self._current_file:
                    self.disassembler_page.load_file(self._current_file)
        else:
            logger.warning("Attempted to navigate to unknown page id: %s", page_id)

    def open_file_dialog(self) -> None:
        """Prompt user for a binary file to inspect."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Target File for Static Analysis",
            self._config.default_analysis_dir,
            "All Files (*.*);;Executables (*.exe *.dll *.sys *.bin);;Documents (*.pdf *.docx);;Archives (*.zip *.7z *.tar)",
            "All Files (*.*);;Executables (*.exe *.dll *.sys *.bin);;Documents (*.pdf *.docx);;Archives (*.zip *.7z *.tar)",
        )

        if not file_path:
            return

        try:
            validated_path = validate_file_path(file_path)
            self._current_file = validated_path
            self.lbl_current_file.setText(f"Current file: {validated_path.name}")
            self.lbl_status_msg.setText(f"Target selected: {validated_path.name}")
            self.lbl_status_msg.setText(f"Target selected: {validated_path.name}")
            logger.info("File selected for analysis: %s", validated_path)

            # Navigate to File Analyzer and start background analysis
            self.navigate_to_page(PAGE_FILE_ANALYZER)
            self.file_analyzer_page.load_file(validated_path)

            # Navigate to File Analyzer and start background analysis
            self.navigate_to_page(PAGE_FILE_ANALYZER)
            self.file_analyzer_page.load_file(validated_path)

        except (ValidationError, FileAccessError) as exc:
            logger.error("Failed to select file %s: %s", file_path, exc)
            QMessageBox.warning(self, "Invalid File", str(exc))

    def _on_file_analyzed(self, file_name: str, file_size: int) -> None:
        """Callback when FileAnalyzer completes an analysis."""
        self.lbl_current_file.setText(f"Current file: {file_name}")
        self.lbl_status_msg.setText(f"Analysis complete: {file_name} ({file_size} bytes)")

    def _on_file_analyzed(self, file_name: str, file_size: int) -> None:
        """Callback when FileAnalyzer completes an analysis."""
        self.lbl_current_file.setText(f"Current file: {file_name}")
        self.lbl_status_msg.setText(f"Analysis complete: {file_name} ({file_size} bytes)")

    def show_about_dialog(self) -> None:
        """Open the About dialog."""
        dialog = AboutDialog(self)
        dialog.exec()

    def _toggle_theme(self) -> None:
        app = QApplication.instance()
        if app:
            new_theme = self._theme_manager.toggle_theme(app)
            self._config.theme = new_theme
            save_config(self._config)
            self.lbl_status_msg.setText(f"Switched theme to {new_theme.title()}")

    def _on_theme_changed_from_settings(self, new_theme: str) -> None:
        app = QApplication.instance()
        if app:
            self._theme_manager.apply_theme(app, new_theme)
            self._config.theme = new_theme
            self.lbl_status_msg.setText(f"Theme updated to {new_theme.title()}")

    def _on_search_submitted(self) -> None:
        query = self.search_input.text().strip().lower()
        if not query:
            return

        # Basic router based on search query in Phase 1
        if "file" in query or "hash" in query:
            self.navigate_to_page(PAGE_FILE_ANALYZER)
        elif "hex" in query or "byte" in query:
            self.navigate_to_page(PAGE_HEX_VIEWER)
        elif "string" in query or "text" in query:
            self.navigate_to_page(PAGE_STRING_EXTRACTOR)
        elif "pe" in query or "dll" in query or "exe" in query:
            self.navigate_to_page(PAGE_PE_ANALYZER)
        elif "disasm" in query or "asm" in query or "capstone" in query:
            self.navigate_to_page(PAGE_DISASSEMBLER)
        elif "pyc" in query or "bytecode" in query or "python" in query:
            self.navigate_to_page(PAGE_PYTHON_ANALYZER)
        elif "setting" in query or "theme" in query:
            self.navigate_to_page(PAGE_SETTINGS)
        else:
            self.lbl_status_msg.setText(f"No specific module matched query: '{query}'")

    def closeEvent(self, event) -> None:
        """Persist window state before exiting."""
        self._config.window_width = self.width()
        self._config.window_height = self.height()
        save_config(self._config)
        logger.info("PyRE Studio main window closed cleanly.")
        super().closeEvent(event)
