"""Windows Portable Executable (PE) Analyzer Page."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.constants import PAGE_PE_ANALYZER
from core.models.pe_models import ImportedLibrary, PEAnalysisResult
from core.services.file_service import format_file_size
from core.validators import validate_file_path
from ui.widgets.status_banner import StatusBanner
from workers.pe_worker import PEWorker

logger = logging.getLogger(__name__)


class PEAnalyzerPage(QWidget):
    """Full-featured Windows PE inspection screen for headers, sections, imports, and exports."""

    file_loaded = Signal(str, int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_PE_ANALYZER
        self._current_file: Path | None = None
        self._current_result: PEAnalysisResult | None = None

        self._thread: QThread | None = None
        self._worker: PEWorker | None = None

        self.setAcceptDrops(True)
        self._init_ui()

    def _init_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(24, 20, 24, 20)
        root_layout.setSpacing(12)

        # 1. Header Bar
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        lbl_title = QLabel("Windows PE Analyzer")
        lbl_title.setProperty("class", "page-title")
        self.lbl_file_info = QLabel("No PE file loaded.")
        self.lbl_file_info.setStyleSheet("color: #a6adc8; font-size: 12px;")
        title_col.addWidget(lbl_title)
        title_col.addWidget(self.lbl_file_info)
        header_layout.addLayout(title_col, 1)

        self.btn_browse = QPushButton("Select PE File...")
        self.btn_browse.setProperty("class", "primary-btn")
        self.btn_browse.setCursor(Qt.PointingHandCursor)
        self.btn_browse.clicked.connect(self._on_browse_file)
        header_layout.addWidget(self.btn_browse)

        root_layout.addLayout(header_layout)

        # 2. Progress Card (Hidden by default)
        self.progress_frame = QFrame()
        self.progress_frame.setProperty("class", "card")
        self.progress_frame.setVisible(False)
        prog_layout = QVBoxLayout(self.progress_frame)
        self.lbl_progress = QLabel("Parsing PE structures...")
        self.lbl_progress.setStyleSheet("color: #89b4fa; font-weight: 500;")
        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)
        btn_cancel_row = QHBoxLayout()
        btn_cancel_row.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self._on_cancel)
        btn_cancel_row.addWidget(self.btn_cancel)
        prog_layout.addWidget(self.lbl_progress)
        prog_layout.addWidget(self.prog_bar)
        prog_layout.addLayout(btn_cancel_row)
        root_layout.addWidget(self.progress_frame)

        # 3. Empty State Card
        self.empty_card = QFrame()
        self.empty_card.setProperty("class", "card")
        empty_layout = QVBoxLayout(self.empty_card)
        empty_layout.setContentsMargins(40, 48, 40, 48)
        empty_layout.setSpacing(12)
        lbl_empty_title = QLabel("No Windows Executable Loaded")
        lbl_empty_title.setAlignment(Qt.AlignCenter)
        lbl_empty_title.setStyleSheet("font-size: 16px; font-weight: 600; color: #a6adc8;")
        lbl_empty_sub = QLabel(
            "Select an EXE, DLL, or SYS file to inspect headers, section tables, imports, and exports.\n"
            "PyRE Studio inspects PE files through static parsing and never executes target binaries."
        )
        lbl_empty_sub.setAlignment(Qt.AlignCenter)
        lbl_empty_sub.setStyleSheet("color: #6c7086; font-size: 12px; line-height: 1.5;")
        empty_layout.addWidget(lbl_empty_title)
        empty_layout.addWidget(lbl_empty_sub)
        root_layout.addWidget(self.empty_card)

        # 4. Content Area (Tabbed)
        self.tabs = QTabWidget()
        self.tabs.setVisible(False)

        # Tab 1: Overview & Headers
        self.tab_headers = self._create_headers_tab()
        self.tabs.addTab(self.tab_headers, "Headers & Flags")

        # Tab 2: Sections Table
        self.tab_sections = self._create_sections_tab()
        self.tabs.addTab(self.tab_sections, "Section Table")

        # Tab 3: Imports (IAT)
        self.tab_imports = self._create_imports_tab()
        self.tabs.addTab(self.tab_imports, "Imports (IAT)")

        # Tab 4: Exports (EAT)
        self.tab_exports = self._create_exports_tab()
        self.tabs.addTab(self.tab_exports, "Exports (EAT)")

        # Tab 5: Resources & Security
        self.tab_resources = self._create_resources_tab()
        self.tabs.addTab(self.tab_resources, "Resources & Security")

        root_layout.addWidget(self.tabs, 1)

    def _create_headers_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Warning banner for suspicious attributes (if any)
        self.banner_pe_warn = StatusBanner(title="PE Analysis Observations", message="", banner_type="warning")
        self.banner_pe_warn.setVisible(False)
        layout.addWidget(self.banner_pe_warn)

        # Overview Card
        card_overview = QFrame()
        card_overview.setProperty("class", "card")
        ov_layout = QVBoxLayout(card_overview)
        lbl_ov_title = QLabel("Core PE Properties")
        lbl_ov_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        ov_layout.addWidget(lbl_ov_title)

        self.grid_overview = QGridLayout()
        self.grid_overview.setHorizontalSpacing(24)
        self.grid_overview.setVerticalSpacing(8)

        self.grid_overview.addWidget(QLabel("<b>Format:</b>"), 0, 0)
        self.lbl_pe_format = QLabel("---")
        self.lbl_pe_format.setStyleSheet("color: #89b4fa; font-weight: 600;")
        self.grid_overview.addWidget(self.lbl_pe_format, 0, 1)

        self.grid_overview.addWidget(QLabel("<b>Target Architecture:</b>"), 0, 2)
        self.lbl_pe_machine = QLabel("---")
        self.grid_overview.addWidget(self.lbl_pe_machine, 0, 3)

        self.grid_overview.addWidget(QLabel("<b>Entry Point RVA:</b>"), 1, 0)
        self.lbl_pe_entry = QLabel("---")
        self.lbl_pe_entry.setStyleSheet("font-family: Consolas; color: #a6e3a1;")
        self.grid_overview.addWidget(self.lbl_pe_entry, 1, 1)

        self.grid_overview.addWidget(QLabel("<b>Image Base:</b>"), 1, 2)
        self.lbl_pe_image_base = QLabel("---")
        self.lbl_pe_image_base.setStyleSheet("font-family: Consolas;")
        self.grid_overview.addWidget(self.lbl_pe_image_base, 1, 3)

        self.grid_overview.addWidget(QLabel("<b>Subsystem:</b>"), 2, 0)
        self.lbl_pe_subsystem = QLabel("---")
        self.grid_overview.addWidget(self.lbl_pe_subsystem, 2, 1)

        self.grid_overview.addWidget(QLabel("<b>Number of Sections:</b>"), 2, 2)
        self.lbl_pe_sections_count = QLabel("---")
        self.grid_overview.addWidget(self.lbl_pe_sections_count, 2, 3)

        self.grid_overview.addWidget(QLabel("<b>Checksum:</b>"), 3, 0)
        self.lbl_pe_checksum = QLabel("---")
        self.grid_overview.addWidget(self.lbl_pe_checksum, 3, 1)

        self.grid_overview.addWidget(QLabel("<b>Header Timestamp:</b>"), 3, 2)
        self.lbl_pe_timestamp = QLabel("---")
        self.grid_overview.addWidget(self.lbl_pe_timestamp, 3, 3)

        ov_layout.addLayout(self.grid_overview)
        layout.addWidget(card_overview)

        # Characteristics & Security Mitigations Card
        card_security = QFrame()
        card_security.setProperty("class", "card")
        sec_layout = QVBoxLayout(card_security)
        lbl_sec_title = QLabel("Security Mitigations & DLL Characteristics")
        lbl_sec_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        sec_layout.addWidget(lbl_sec_title)

        self.lbl_dll_chars = QLabel("---")
        self.lbl_dll_chars.setWordWrap(True)
        self.lbl_dll_chars.setStyleSheet("color: #a6adc8; line-height: 1.4;")
        sec_layout.addWidget(self.lbl_dll_chars)

        lbl_chars_hdr = QLabel("File Characteristics:")
        lbl_chars_hdr.setStyleSheet("font-weight: 600; margin-top: 8px; color: #cdd6f4;")
        sec_layout.addWidget(lbl_chars_hdr)

        self.lbl_file_chars = QLabel("---")
        self.lbl_file_chars.setWordWrap(True)
        self.lbl_file_chars.setStyleSheet("color: #a6adc8; line-height: 1.4;")
        sec_layout.addWidget(self.lbl_file_chars)

        layout.addWidget(card_security)

        # Timestamp Disclaimer Note
        ts_banner = StatusBanner(
            title="Compilation Timestamp Disclaimer",
            message="PE header timestamps represent values recorded by the linker and cannot verify the exact compile date. Timestamps are easily modified, zeroed out, or replaced with deterministic reproducible hashes.",
            banner_type="info",
        )
        layout.addWidget(ts_banner)
        layout.addStretch()

        scroll.setWidget(container)
        return scroll

    def _create_sections_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.sections_table = QTableWidget()
        self.sections_table.setColumnCount(7)
        self.sections_table.setHorizontalHeaderLabels(
            ["Name", "Virtual Address", "Virtual Size", "Raw Size", "Entropy", "Permissions", "Characteristics"]
        )
        self.sections_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.sections_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.sections_table.verticalHeader().setVisible(False)
        self.sections_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.sections_table.setSelectionBehavior(QTableWidget.SelectRows)

        mono_font = QFont("Consolas", 10)
        self.sections_table.setFont(mono_font)
        layout.addWidget(self.sections_table)
        return container

    def _create_imports_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Filter bar
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter Imported Symbols:"))
        self.input_import_filter = QLineEdit()
        self.input_import_filter.setPlaceholderText("Filter by DLL name or function API...")
        self.input_import_filter.textChanged.connect(self._filter_imports)
        filter_row.addWidget(self.input_import_filter, 1)
        layout.addLayout(filter_row)

        splitter = QSplitter(Qt.Horizontal)

        # Left list: DLLs
        left_box = QFrame()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("<b>Imported Libraries (DLLs)</b>"))
        self.dll_list = QListWidget()
        self.dll_list.currentRowChanged.connect(self._on_dll_selected)
        left_layout.addWidget(self.dll_list)
        splitter.addWidget(left_box)

        # Right table: Functions
        right_box = QFrame()
        right_layout = QVBoxLayout(right_box)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.lbl_selected_dll = QLabel("<b>Imported Functions</b>")
        right_layout.addWidget(self.lbl_selected_dll)

        self.imports_table = QTableWidget()
        self.imports_table.setColumnCount(3)
        self.imports_table.setHorizontalHeaderLabels(["Function Name", "Ordinal", "Address (RVA)"])
        self.imports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.imports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.imports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.imports_table.verticalHeader().setVisible(False)
        self.imports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.imports_table.setSelectionBehavior(QTableWidget.SelectRows)

        mono_font = QFont("Consolas", 10)
        self.imports_table.setFont(mono_font)
        right_layout.addWidget(self.imports_table)

        splitter.addWidget(right_box)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)
        return container

    def _create_exports_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter Exports:"))
        self.input_export_filter = QLineEdit()
        self.input_export_filter.setPlaceholderText("Filter by exported function name...")
        self.input_export_filter.textChanged.connect(self._filter_exports)
        filter_row.addWidget(self.input_export_filter, 1)
        layout.addLayout(filter_row)

        self.exports_table = QTableWidget()
        self.exports_table.setColumnCount(4)
        self.exports_table.setHorizontalHeaderLabels(["Function Name", "Ordinal", "Address (RVA)", "Forwarder"])
        self.exports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.exports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.exports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.exports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.exports_table.verticalHeader().setVisible(False)
        self.exports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.exports_table.setSelectionBehavior(QTableWidget.SelectRows)

        mono_font = QFont("Consolas", 10)
        self.exports_table.setFont(mono_font)
        layout.addWidget(self.exports_table)
        return container

    def _create_resources_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # 1. Resources Breakdown
        card_res = QFrame()
        card_res.setProperty("class", "card")
        res_layout = QVBoxLayout(card_res)
        self.lbl_res_summary = QLabel("Resource Directory Summary")
        self.lbl_res_summary.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        res_layout.addWidget(self.lbl_res_summary)

        self.res_table = QTableWidget()
        self.res_table.setColumnCount(2)
        self.res_table.setHorizontalHeaderLabels(["Resource Type", "Count"])
        self.res_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.res_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.res_table.verticalHeader().setVisible(False)
        self.res_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.res_table.setFixedHeight(160)
        res_layout.addWidget(self.res_table)
        layout.addWidget(card_res)

        # 2. Debug Directory
        card_dbg = QFrame()
        card_dbg.setProperty("class", "card")
        dbg_layout = QVBoxLayout(card_dbg)
        lbl_dbg_title = QLabel("Debug Directory & Symbols")
        lbl_dbg_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        dbg_layout.addWidget(lbl_dbg_title)

        self.lbl_debug_info = QLabel("No debug entries present.")
        self.lbl_debug_info.setWordWrap(True)
        self.lbl_debug_info.setStyleSheet("color: #a6adc8; font-family: Consolas; line-height: 1.4;")
        dbg_layout.addWidget(self.lbl_debug_info)
        layout.addWidget(card_dbg)

        # 3. Security & Authenticode
        card_cert = QFrame()
        card_cert.setProperty("class", "card")
        cert_layout = QVBoxLayout(card_cert)
        lbl_cert_title = QLabel("Authenticode Digital Signature / Security Directory")
        lbl_cert_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        cert_layout.addWidget(lbl_cert_title)

        self.lbl_cert_info = QLabel("Not signed / Security directory empty.")
        self.lbl_cert_info.setStyleSheet("color: #a6adc8;")
        cert_layout.addWidget(self.lbl_cert_info)
        layout.addWidget(card_cert)

        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    # Drag & Drop
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if file_path:
                self.load_file(file_path)
                event.acceptProposedAction()
        super().dropEvent(event)

    def _on_browse_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Windows Executable for PE Analysis",
            "",
            "Windows Executables (*.exe *.dll *.sys *.scr *.ocx);;All Files (*.*)",
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str | Path) -> None:
        """Begin static PE analysis in background thread."""
        try:
            validated = validate_file_path(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid File", str(exc))
            return

        self._current_file = validated
        size = validated.stat().st_size
        self.lbl_file_info.setText(f"<b>{validated.name}</b> &nbsp;|&nbsp; {format_file_size(size)}")

        self.empty_card.setVisible(False)
        self.tabs.setVisible(False)
        self.progress_frame.setVisible(True)
        self.prog_bar.setValue(0)
        self.lbl_progress.setText(f"Analyzing {validated.name}...")
        self.btn_browse.setEnabled(False)

        self._thread = QThread(self)
        self._worker = PEWorker(validated)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)

        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _on_progress(self, percent: int, msg: str) -> None:
        self.prog_bar.setValue(percent)
        self.lbl_progress.setText(msg)

    def _on_finished(self, result: PEAnalysisResult) -> None:
        self.progress_frame.setVisible(False)
        self.btn_browse.setEnabled(True)

        self._current_result = result
        self._display_results(result)
        self.tabs.setVisible(True)
        self.file_loaded.emit(self._current_file.name, self._current_file.stat().st_size)

    def _on_error(self, err_msg: str) -> None:
        self.progress_frame.setVisible(False)
        self.btn_browse.setEnabled(True)
        self.empty_card.setVisible(True)
        QMessageBox.warning(self, "PE Analysis Notice", f"Could not parse file as Windows PE:\n\n{err_msg}")

    def _on_cancel(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.lbl_progress.setText("Cancelling analysis...")

    def _display_results(self, result: PEAnalysisResult) -> None:
        hdr = result.header

        # 1. Headers Tab
        self.lbl_pe_format.setText(hdr.format_type)
        self.lbl_pe_machine.setText(hdr.machine)
        self.lbl_pe_entry.setText(hdr.entry_point_hex)
        self.lbl_pe_image_base.setText(hdr.image_base_hex)
        self.lbl_pe_subsystem.setText(hdr.subsystem)
        self.lbl_pe_sections_count.setText(str(hdr.number_of_sections))
        self.lbl_pe_checksum.setText(hdr.checksum)
        self.lbl_pe_timestamp.setText(f"{hdr.timestamp_iso} ({hdr.timestamp})")

        self.lbl_dll_chars.setText(
            " &bull; ".join(hdr.dll_characteristics) if hdr.dll_characteristics else "None / Legacy"
        )
        self.lbl_file_chars.setText(
            " &bull; ".join(hdr.characteristics) if hdr.characteristics else "None"
        )

        if result.warnings:
            self.banner_pe_warn.setVisible(True)
            warn_msg = "<br>• ".join([""] + result.warnings)
            self.banner_pe_warn.findChild(QLabel, "").setText(f"<b>PE Anomalies & Warnings:</b>{warn_msg}")
        else:
            self.banner_pe_warn.setVisible(False)

        # 2. Sections Tab
        self.sections_table.setRowCount(len(result.sections))
        for row_idx, sec in enumerate(result.sections):
            self.sections_table.setItem(row_idx, 0, QTableWidgetItem(sec.name))
            self.sections_table.setItem(row_idx, 1, QTableWidgetItem(sec.virtual_address_hex))
            self.sections_table.setItem(row_idx, 2, QTableWidgetItem(f"{sec.virtual_size:,} bytes"))
            self.sections_table.setItem(row_idx, 3, QTableWidgetItem(f"{sec.raw_size:,} bytes"))

            ent_item = QTableWidgetItem(f"{sec.entropy:.2f} / 8.0")
            if sec.entropy > 7.0:
                ent_item.setForeground(Qt.yellow)
            self.sections_table.setItem(row_idx, 4, ent_item)

            perm_item = QTableWidgetItem(sec.permissions)
            if sec.permissions == "RWX":
                perm_item.setForeground(Qt.red)
            elif "X" in sec.permissions:
                perm_item.setForeground(Qt.cyan)
            self.sections_table.setItem(row_idx, 5, perm_item)

            self.sections_table.setItem(row_idx, 6, QTableWidgetItem(sec.characteristics_hex))

        # 3. Imports Tab
        self.dll_list.clear()
        for lib in result.imports:
            item = QListWidgetItem(f"{lib.name} ({lib.symbol_count})")
            item.setData(Qt.UserRole, lib)
            self.dll_list.addItem(item)

        if result.imports:
            self.dll_list.setCurrentRow(0)
        else:
            self.imports_table.setRowCount(0)
            self.lbl_selected_dll.setText("<b>No imports found</b>")

        # 4. Exports Tab
        self._populate_exports(result.exports)

        # 5. Resources & Security Tab
        res = result.resources
        self.lbl_res_summary.setText(f"Resource Directory Summary (Total Resources: {res.total_resources})")
        self.res_table.setRowCount(len(res.type_counts))
        for row_idx, (r_type, r_count) in enumerate(res.type_counts.items()):
            self.res_table.setItem(row_idx, 0, QTableWidgetItem(r_type))
            self.res_table.setItem(row_idx, 1, QTableWidgetItem(str(r_count)))

        # Debug
        if result.debug_entries:
            dbg_lines = []
            for dbg in result.debug_entries:
                dbg_lines.append(f"<b>Type:</b> {dbg.type_name} &bull; <b>Timestamp:</b> {dbg.timestamp_iso}")
                if dbg.pdb_path:
                    dbg_lines.append(f"<b>PDB File:</b> <code>{dbg.pdb_path}</code>")
                if dbg.guid:
                    dbg_lines.append(f"<b>GUID:</b> {dbg.guid}")
                dbg_lines.append("")
            self.lbl_debug_info.setText("<br>".join(dbg_lines))
        else:
            self.lbl_debug_info.setText("No Debug Directory records found.")

        # Certificate
        cert = result.certificate
        if cert.has_certificate:
            self.lbl_cert_info.setText(
                f"<b style='color: #a6e3a1;'>Signed:</b> {cert.certificate_type} &bull; "
                f"Length: {cert.length:,} bytes &bull; Revision: {cert.revision}"
            )
        else:
            self.lbl_cert_info.setText("<span style='color: #a6adc8;'>No Authenticode signature found.</span>")

    def _on_dll_selected(self, row: int) -> None:
        item = self.dll_list.item(row)
        if not item:
            return
        lib: ImportedLibrary = item.data(Qt.UserRole)
        self.lbl_selected_dll.setText(f"<b>Imported Functions from {lib.name} ({lib.symbol_count})</b>")
        self._display_imported_symbols(lib.symbols)

    def _display_imported_symbols(self, symbols) -> None:
        filter_text = self.input_import_filter.text().strip().lower()
        filtered = [
            s for s in symbols
            if not filter_text or (s.name and filter_text in s.name.lower()) or filter_text in s.address_rva_hex.lower()
        ]

        self.imports_table.setRowCount(len(filtered))
        for row_idx, s in enumerate(filtered):
            name_str = s.name if s.name else f"<Ordinal #{s.ordinal}>"
            self.imports_table.setItem(row_idx, 0, QTableWidgetItem(name_str))
            ord_str = str(s.ordinal) if s.ordinal is not None else "---"
            self.imports_table.setItem(row_idx, 1, QTableWidgetItem(ord_str))
            self.imports_table.setItem(row_idx, 2, QTableWidgetItem(s.address_rva_hex))

    def _filter_imports(self) -> None:
        curr_row = self.dll_list.currentRow()
        if curr_row >= 0:
            self._on_dll_selected(curr_row)

    def _populate_exports(self, exports) -> None:
        filter_text = self.input_export_filter.text().strip().lower()
        filtered = [
            e for e in exports
            if not filter_text or (e.name and filter_text in e.name.lower()) or filter_text in e.address_rva_hex.lower()
        ]

        self.exports_table.setRowCount(len(filtered))
        for row_idx, e in enumerate(filtered):
            name_str = e.name if e.name else f"<Ordinal #{e.ordinal}>"
            self.exports_table.setItem(row_idx, 0, QTableWidgetItem(name_str))
            self.exports_table.setItem(row_idx, 1, QTableWidgetItem(str(e.ordinal)))
            self.exports_table.setItem(row_idx, 2, QTableWidgetItem(e.address_rva_hex))
            fwd_str = e.forwarder if e.forwarder else "---"
            self.exports_table.setItem(row_idx, 3, QTableWidgetItem(fwd_str))

    def _filter_exports(self) -> None:
        if self._current_result:
            self._populate_exports(self._current_result.exports)
