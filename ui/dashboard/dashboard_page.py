"""Dashboard Page for PyRE Studio."""

from __future__ import annotations

import platform
import sys

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.constants import (
    APP_NAME,
    APP_SUBTITLE,
    APP_VERSION,
    DISCLAIMER_TEXT,
    PAGE_DASHBOARD,
    PAGE_DISASSEMBLER,
    PAGE_FILE_ANALYZER,
    PAGE_HEX_VIEWER,
    PAGE_PE_ANALYZER,
    PAGE_PYTHON_ANALYZER,
    PAGE_STRING_EXTRACTOR,
)
from core.dependency_checker import check_module_installed
from ui.widgets.quick_action_card import QuickActionCard
from ui.widgets.stat_card import StatCard
from ui.widgets.status_banner import StatusBanner


class DashboardPage(QWidget):
    """Main overview dashboard with quick actions, real stats, and empty states."""

    open_file_requested = Signal()
    navigate_requested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_DASHBOARD

        self._init_ui()

    def _init_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(24)

        # Welcome Header Banner
        header_layout = QHBoxLayout()
        header_layout.setSpacing(16)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(4)

        app_title_lbl = QLabel(f"{APP_NAME} <span style='font-size: 14px; color: #89b4fa;'>v{APP_VERSION}</span>")
        app_title_lbl.setProperty("class", "page-title")

        app_desc_lbl = QLabel(APP_SUBTITLE)
        app_desc_lbl.setProperty("class", "page-subtitle")

        title_layout.addWidget(app_title_lbl)
        title_layout.addWidget(app_desc_lbl)

        header_layout.addLayout(title_layout, 1)

        # Primary Open File Action
        self._btn_open_file = QPushButton("Open File for Analysis")
        self._btn_open_file.setProperty("class", "primary-btn")
        self._btn_open_file.setCursor(Qt.PointingHandCursor)
        self._btn_open_file.setMinimumHeight(38)
        self._btn_open_file.clicked.connect(self.open_file_requested.emit)
        header_layout.addWidget(self._btn_open_file)

        layout.addLayout(header_layout)

        # Security Disclaimer Banner
        security_banner = StatusBanner(
            title="Safe Static Analysis Guarantee",
            message=DISCLAIMER_TEXT,
            banner_type="info",
        )
        layout.addWidget(security_banner)

        # Stat Cards (Honest baseline in Phase 1 before SQLite persistence)
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(16)

        self._stat_files = StatCard(
            title="Total Files Analyzed",
            value="0",
            subtitle="Session history activates in Phase 9",
        )
        self._stat_engines = StatCard(
            title="Analysis Modules",
            value="7 Modules",
            subtitle="Phase 1 Foundation active",
        )
        self._stat_status = StatCard(
            title="Core Engine Mode",
            value="Static Only",
            subtitle="Non-executing, read-only inspection",
        )

        stats_layout.addWidget(self._stat_files)
        stats_layout.addWidget(self._stat_engines)
        stats_layout.addWidget(self._stat_status)

        layout.addLayout(stats_layout)

        # Quick Access Grid
        qa_header = QLabel("Core Analysis Modules")
        qa_header.setProperty("class", "section-header")
        layout.addWidget(qa_header)

        grid = QGridLayout()
        grid.setSpacing(14)

        cards_info = [
            (
                PAGE_FILE_ANALYZER,
                "File Analyzer",
                "Inspect file signatures, metadata, magic bytes, and chunked cryptographic hashes.",
                "Phase 2",
            ),
            (
                PAGE_HEX_VIEWER,
                "Hexadecimal Viewer",
                "Paged hex and ASCII inspection with bounded reads and pattern searching.",
                "Phase 3",
            ),
            (
                PAGE_STRING_EXTRACTOR,
                "String Extractor",
                "Extract printable ASCII, UTF-8, and UTF-16LE strings with file offsets.",
                "Phase 4",
            ),
            (
                PAGE_PE_ANALYZER,
                "Windows PE Analyzer",
                "Deep inspection of DOS, COFF, Optional headers, imports, exports, and sections.",
                "Phase 5",
            ),
            (
                PAGE_DISASSEMBLER,
                "Disassembler",
                "Static machine code disassembly for x86 and x86-64 using the Capstone engine.",
                "Phase 6",
            ),
            (
                PAGE_PYTHON_ANALYZER,
                "Python Bytecode Analyzer",
                "Inspect .pyc headers, code objects, names, constants, and dis bytecode.",
                "Phase 7",
            ),
        ]

        for idx, (mod_id, title, desc, badge) in enumerate(cards_info):
            card = QuickActionCard(
                module_id=mod_id,
                title=title,
                description=desc,
                badge_text=badge,
            )
            card.clicked.connect(self.navigate_requested.emit)
            row = idx // 3
            col = idx % 3
            grid.addWidget(card, row, col)

        layout.addLayout(grid)

        # Recent Sessions Section (Honest empty state)
        recent_hdr = QLabel("Recent Analysis Sessions")
        recent_hdr.setProperty("class", "section-header")
        layout.addWidget(recent_hdr)

        empty_frame = QFrame()
        empty_frame.setProperty("class", "card")
        empty_layout = QVBoxLayout(empty_frame)
        empty_layout.setContentsMargins(24, 20, 24, 20)
        empty_layout.setSpacing(8)

        empty_title = QLabel("No Recent Analysis Sessions")
        empty_title.setStyleSheet("font-weight: 600; font-size: 13px; color: #a6adc8;")
        empty_desc = QLabel(
            "Select 'Open File for Analysis' above or choose a module from the sidebar to inspect a binary. "
            "Session history and database persistence will be integrated in Phase 9."
        )
        empty_desc.setStyleSheet("color: #6c7086; font-size: 12px;")
        empty_desc.setWordWrap(True)

        empty_layout.addWidget(empty_title)
        empty_layout.addWidget(empty_desc)
        layout.addWidget(empty_frame)

        # Environment & System Status Card
        sys_frame = QFrame()
        sys_frame.setProperty("class", "card")
        sys_layout = QHBoxLayout(sys_frame)
        sys_layout.setContentsMargins(16, 12, 16, 12)

        py_ver = sys.version.split()[0]
        os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"

        _, pyside_ver = check_module_installed("PySide6")
        pyside_str = pyside_ver or "Installed"

        env_label = QLabel(
            f"<b>Environment:</b> Python {py_ver} &nbsp;|&nbsp; "
            f"<b>Qt:</b> PySide6 {pyside_str} &nbsp;|&nbsp; "
            f"<b>OS:</b> {os_name}"
        )
        env_label.setStyleSheet("color: #a6adc8; font-size: 11px;")
        sys_layout.addWidget(env_label)
        sys_layout.addStretch()

        layout.addWidget(sys_frame)
        layout.addStretch()

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(scroll)
        scroll.setWidget(container)
