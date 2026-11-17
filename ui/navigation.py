"""Sidebar Navigation Widget."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

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
)


class SidebarNavigation(QWidget):
    """Sidebar navigation bar with structured categories and active indicators."""

    page_selected = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebarWidget")
        self.setFixedWidth(230)

        self._buttons: dict[str, QPushButton] = {}
        self._button_group = QButtonGroup(self)
        self._button_group.setExclusive(True)

        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top branding header
        header_widget = QWidget()
        header_widget.setObjectName("sidebarHeader")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(16, 16, 16, 16)
        header_layout.setSpacing(8)

        lbl_logo = QLabel(APP_NAME)
        lbl_logo.setObjectName("appLogoTitle")

        lbl_ver = QLabel(f"v{APP_VERSION}")
        lbl_ver.setObjectName("appLogoBadge")

        header_layout.addWidget(lbl_logo)
        header_layout.addWidget(lbl_ver)
        header_layout.addStretch()

        main_layout.addWidget(header_widget)

        # Nav items container with scroll
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        nav_container = QWidget()
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 10, 0, 10)
        nav_layout.setSpacing(2)

        # 1. Main
        self._add_nav_btn(nav_layout, PAGE_DASHBOARD, "Dashboard", is_checked=True)

        # 2. ANALYSIS Section
        self._add_section_header(nav_layout, "ANALYSIS")
        self._add_nav_btn(nav_layout, PAGE_FILE_ANALYZER, "File Analyzer")
        self._add_nav_btn(nav_layout, PAGE_HEX_VIEWER, "Hex Viewer")
        self._add_nav_btn(nav_layout, PAGE_STRING_EXTRACTOR, "String Extractor")
        self._add_nav_btn(nav_layout, PAGE_PE_ANALYZER, "PE Analyzer")
        self._add_nav_btn(nav_layout, PAGE_DISASSEMBLER, "Disassembler")
        self._add_nav_btn(nav_layout, PAGE_PYTHON_ANALYZER, "Python Analyzer")
        self._add_nav_btn(nav_layout, PAGE_ADVANCED_ANALYSIS, "Advanced Analysis")

        # 3. MANAGEMENT Section
        self._add_section_header(nav_layout, "MANAGEMENT")
        self._add_nav_btn(nav_layout, PAGE_REPORTS, "Reports")
        self._add_nav_btn(nav_layout, PAGE_HISTORY, "Analysis History")
        self._add_nav_btn(nav_layout, PAGE_SETTINGS, "Settings")
        self._add_nav_btn(nav_layout, PAGE_ABOUT, "About")

        nav_layout.addStretch()
        scroll.setWidget(nav_container)
        main_layout.addWidget(scroll)

    def _add_section_header(self, layout: QVBoxLayout, text: str) -> None:
        lbl = QLabel(text)
        lbl.setObjectName("navSectionLabel")
        layout.addWidget(lbl)

    def _add_nav_btn(
        self, layout: QVBoxLayout, page_id: str, label: str, is_checked: bool = False
    ) -> None:
        btn = QPushButton(label)
        btn.setCheckable(True)
        btn.setChecked(is_checked)
        btn.setProperty("class", "nav-btn")
        btn.setCursor(Qt.PointingHandCursor)

        btn.clicked.connect(lambda: self.page_selected.emit(page_id))

        self._button_group.addButton(btn)
        self._buttons[page_id] = btn
        layout.addWidget(btn)

    def select_page(self, page_id: str) -> None:
        """Programmatically select a navigation button."""
        btn = self._buttons.get(page_id)
        if btn:
            btn.setChecked(True)
