"""Disassembler Page — Capstone x86 / x86-64 Static Disassembly View."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.constants import PAGE_DISASSEMBLER
from core.exceptions import AnalysisError, ConfigurationError, UnsupportedFormatError
from core.models.disasm_models import DisassemblyResult
from workers.disasm_worker import DisasmWorker

logger = logging.getLogger(__name__)

# Colour palette (matches dark theme)
_COL_JUMP = "#f38ba8"       # rose — jumps
_COL_CALL = "#89b4fa"       # sky blue — calls
_COL_RET = "#a6e3a1"        # green — rets
_COL_PRIV = "#fab387"       # peach — privileged
_COL_DEFAULT = "#cdd6f4"    # text default
_COL_MNEMONIC_NORMAL = "#89dceb"   # teal for regular mnemonics
_COL_MNEMONIC_JUMP = _COL_JUMP
_COL_MNEMONIC_CALL = _COL_CALL
_COL_MNEMONIC_RET = _COL_RET

_MONO_FONT = QFont("Consolas", 9)
_MONO_FONT.setStyleHint(QFont.StyleHint.Monospace)

_TABLE_HEADERS = ["Offset", "Virtual Address", "Raw Bytes", "Mnemonic", "Operands"]
_COL_OFFSET = 0
_COL_VA = 1
_COL_BYTES = 2
_COL_MNEMONIC = 3
_COL_OPERANDS = 4


class DisassemblerPage(QWidget):
    """Active Disassembler module page (Phase 6).

    Provides:
      - File browse / drag-drop.
      - Architecture mode override (auto / 32-bit / 64-bit).
      - PE section selector (populated after PE parse).
      - Progress bar + cancel.
      - Searchable, colour-coded instruction table (Offset | VA | Bytes | Mnemonic | Operands).
      - Jump/call target navigation.
      - Export to plain text.
    """

    file_loaded = Signal(str, int)
    module_id: str = PAGE_DISASSEMBLER

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_DISASSEMBLER
        self._current_file: Path | None = None
        self._current_result: DisassemblyResult | None = None
        self._pe_result = None
        self._worker: DisasmWorker | None = None
        self._thread: QThread | None = None
        self._all_rows: list[tuple] = []

        self._build_ui()
        self.setAcceptDrops(True)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        # Page heading
        heading = QLabel("Disassembler")
        heading.setStyleSheet("font-size: 22px; font-weight: 700; color: #cdd6f4;")
        root.addWidget(heading)

        sub = QLabel(
            "Static x86 / x86-64 machine-code disassembly via Capstone. "
            "Target files are never executed."
        )
        sub.setStyleSheet("font-size: 11px; color: #6c7086;")
        sub.setWordWrap(True)
        root.addWidget(sub)

        root.addWidget(self._separator())
        root.addLayout(self._build_toolbar())
        root.addWidget(self._separator())

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(14)
        root.addWidget(self.progress_bar)

        # Stats label
        self.lbl_stats = QLabel("No file loaded.")
        self.lbl_stats.setStyleSheet("font-size: 11px; color: #6c7086;")
        root.addWidget(self.lbl_stats)

        # Search bar
        search_bar = QHBoxLayout()
        search_bar.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search mnemonics, operands, or addresses...")
        self.search_input.textChanged.connect(self._apply_filter)
        search_bar.addWidget(self.search_input)

        self.btn_clear_search = QPushButton("Clear")
        self.btn_clear_search.setFixedWidth(60)
        self.btn_clear_search.clicked.connect(self._clear_search)
        search_bar.addWidget(self.btn_clear_search)
        root.addLayout(search_bar)

        # Instruction table
        self.table = QTableWidget()
        self.table.setColumnCount(len(_TABLE_HEADERS))
        self.table.setHorizontalHeaderLabels(_TABLE_HEADERS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setFont(_MONO_FONT)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        root.addWidget(self.table, 1)

        # Detail row
        detail_row = QHBoxLayout()
        self.lbl_selection = QLabel("Double-click a jump or call instruction to navigate to its target.")
        self.lbl_selection.setStyleSheet("font-size: 10px; color: #585b70;")
        detail_row.addWidget(self.lbl_selection, 1)

        self.btn_export = QPushButton("Export TXT")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._export_txt)
        detail_row.addWidget(self.btn_export)
        root.addLayout(detail_row)

        self.table.setColumnWidth(_COL_OFFSET, 110)
        self.table.setColumnWidth(_COL_VA, 110)
        self.table.setColumnWidth(_COL_BYTES, 180)
        self.table.setColumnWidth(_COL_MNEMONIC, 90)

    def _build_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.lbl_file_path = QLabel("No file selected.")
        self.lbl_file_path.setStyleSheet("color: #a6adc8; font-size: 11px;")
        self.lbl_file_path.setWordWrap(False)
        toolbar.addWidget(self.lbl_file_path, 1)

        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setToolTip("Select a binary file for disassembly")
        self.btn_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse.clicked.connect(self._browse_file)
        toolbar.addWidget(self.btn_browse)

        lbl_mode = QLabel("Mode:")
        lbl_mode.setStyleSheet("color: #a6adc8;")
        toolbar.addWidget(lbl_mode)

        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["Auto (from PE header)", "x86 32-bit", "x86 64-bit"])
        self.combo_mode.setToolTip("Override architecture detection (Auto reads from PE header)")
        self.combo_mode.setFixedWidth(170)
        toolbar.addWidget(self.combo_mode)

        lbl_section = QLabel("Section:")
        lbl_section.setStyleSheet("color: #a6adc8;")
        toolbar.addWidget(lbl_section)

        self.combo_section = QComboBox()
        self.combo_section.addItem(".text")
        self.combo_section.setToolTip("PE section to disassemble (populated after PE parse)")
        self.combo_section.setFixedWidth(110)
        toolbar.addWidget(self.combo_section)

        self.btn_raw_mode = QPushButton("Raw File")
        self.btn_raw_mode.setCheckable(True)
        self.btn_raw_mode.setToolTip("Disassemble entire file as raw bytes (no PE parsing)")
        self.btn_raw_mode.setFixedWidth(80)
        toolbar.addWidget(self.btn_raw_mode)

        self.btn_disassemble = QPushButton("⚙  Disassemble")
        self.btn_disassemble.setEnabled(False)
        self.btn_disassemble.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_disassemble.setStyleSheet(
            "QPushButton { background-color: #313244; color: #89b4fa; "
            "border: 1px solid #45475a; padding: 5px 12px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #45475a; }"
            "QPushButton:disabled { color: #585b70; }"
        )
        self.btn_disassemble.clicked.connect(self._start_disassembly)
        toolbar.addWidget(self.btn_disassemble)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_disassembly)
        toolbar.addWidget(self.btn_cancel)

        return toolbar

    @staticmethod
    def _separator() -> QWidget:
        line = QWidget()
        line.setFixedHeight(1)
        line.setStyleSheet("background-color: #313244;")
        return line

    def load_file(self, path: Path) -> None:
        """Load a file into the disassembler (called by MainWindow auto-sync)."""
        self._current_file = path
        self.lbl_file_path.setText(str(path))
        self.lbl_file_path.setToolTip(str(path))
        self.btn_disassemble.setEnabled(True)
        self.lbl_stats.setText(f"File loaded: {path.name}  —  click Disassemble to begin.")
        logger.info("DisassemblerPage: file loaded: %s", path)

    def set_pe_result(self, pe_result) -> None:
        """Inject a pre-parsed PEAnalysisResult so the page can populate section choices."""
        self._pe_result = pe_result
        from analyzers.disasm_analyzer import list_disassemblable_sections
        sections = list_disassemblable_sections(pe_result)
        self._populate_sections(sections)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if urls:
            path = Path(urls[0].toLocalFile())
            if path.is_file():
                self.load_file(path)

    def _browse_file(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File for Disassembly",
            "",
            "All Files (*.*);;Executables (*.exe *.dll *.sys *.bin);;Object Files (*.o *.obj)",
        )
        if path_str:
            self.load_file(Path(path_str))

    def _start_disassembly(self) -> None:
        if self._current_file is None:
            return

        self._cancel_disassembly()

        self.table.setRowCount(0)
        self._all_rows = []
        self.search_input.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.btn_disassemble.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.lbl_stats.setText("Disassembling...")

        mode_text = self.combo_mode.currentText()
        if "32-bit" in mode_text:
            mode = "32-bit"
        elif "64-bit" in mode_text:
            mode = "64-bit"
        else:
            mode = "auto"

        raw_mode = self.btn_raw_mode.isChecked()
        section = self.combo_section.currentText()

        self._worker = DisasmWorker(
            file_path=self._current_file,
            mode=mode,
            section_name=section,
            raw_mode=raw_mode,
            pe_result=self._pe_result if not raw_mode else None,
        )

        self._thread = QThread(self)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_disassembly_finished)
        self._worker.error.connect(self._on_disassembly_error)
        self._worker.progress.connect(self._on_progress)
        self._worker.status_message.connect(self.lbl_stats.setText)
        self._worker.sections_available.connect(self._populate_sections)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.error.connect(self._worker.deleteLater)

        self._thread.start()

    def _cancel_disassembly(self) -> None:
        if self._worker:
            self._worker.cancel()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(2000)
        self._worker = None
        self._thread = None
        self.btn_disassemble.setEnabled(self._current_file is not None)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setVisible(False)

    def _on_progress(self, pct: int) -> None:
        self.progress_bar.setValue(pct)

    def _on_disassembly_finished(self, result: DisassemblyResult) -> None:
        self._current_result = result
        self.progress_bar.setVisible(False)
        self.btn_disassemble.setEnabled(True)
        self.btn_cancel.setEnabled(False)

        self._populate_table(result)
        self.btn_export.setEnabled(True)

        stats = (
            f"{result.instruction_count:,} instructions  |  "
            f"section: {result.section_name}  |  "
            f"mode: {result.mode}  |  "
            f"coverage: {result.coverage_percent}%"
        )
        if result.truncated:
            stats += "  ⚠ truncated (limit reached)"
        self.lbl_stats.setText(stats)

        for warning in result.warnings:
            logger.warning("Disassembly warning: %s", warning)

        self.file_loaded.emit(
            self._current_file.name if self._current_file else "",
            result.instruction_count,
        )

    def _on_disassembly_error(self, msg: str) -> None:
        self.progress_bar.setVisible(False)
        self.btn_disassemble.setEnabled(self._current_file is not None)
        self.btn_cancel.setEnabled(False)
        self.lbl_stats.setText(f"Error: {msg}")
        logger.error("DisassemblerPage error: %s", msg)

    def _populate_sections(self, sections: list[str]) -> None:
        current = self.combo_section.currentText()
        self.combo_section.blockSignals(True)
        self.combo_section.clear()
        self.combo_section.addItems(sections if sections else [".text"])
        idx = self.combo_section.findText(current)
        if idx >= 0:
            self.combo_section.setCurrentIndex(idx)
        self.combo_section.blockSignals(False)

    def _populate_table(self, result: DisassemblyResult) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self._all_rows = []

        self.table.setRowCount(len(result.instructions))

        for row_idx, insn in enumerate(result.instructions):
            row_data = (
                insn.offset_hex,
                insn.rva_hex,
                insn.raw_bytes_hex,
                insn.mnemonic,
                insn.op_str,
            )
            self._all_rows.append(row_data)

            if insn.is_ret:
                fg = _COL_RET
                mnemonic_fg = _COL_MNEMONIC_RET
            elif insn.is_call:
                fg = _COL_CALL
                mnemonic_fg = _COL_MNEMONIC_CALL
            elif insn.is_jump:
                fg = _COL_JUMP
                mnemonic_fg = _COL_MNEMONIC_JUMP
            elif insn.is_privileged:
                fg = _COL_PRIV
                mnemonic_fg = _COL_PRIV
            else:
                fg = _COL_DEFAULT
                mnemonic_fg = _COL_MNEMONIC_NORMAL

            fg_color = QColor(fg)
            mnemonic_color = QColor(mnemonic_fg)

            for col_idx, text in enumerate(row_data):
                item = QTableWidgetItem(text)
                item.setFont(_MONO_FONT)
                if col_idx == _COL_MNEMONIC:
                    item.setForeground(mnemonic_color)
                else:
                    item.setForeground(fg_color)
                item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                self.table.setItem(row_idx, col_idx, item)

        self.table.resizeRowsToContents()
        self.table.setSortingEnabled(True)

    def _apply_filter(self, query: str) -> None:
        q = query.strip().lower()
        if not q:
            for row in range(self.table.rowCount()):
                self.table.setRowHidden(row, False)
            return

        for row_idx, row_data in enumerate(self._all_rows):
            match = any(q in cell.lower() for cell in row_data)
            self.table.setRowHidden(row_idx, not match)

    def _clear_search(self) -> None:
        self.search_input.clear()
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, False)

    def _on_cell_double_clicked(self, row: int, _col: int) -> None:
        if self._current_result is None:
            return
        visible_rows = [r for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]
        if row not in visible_rows:
            return

        insn = self._current_result.instructions[row]
        if not (insn.is_jump or insn.is_call):
            return

        target_str = insn.op_str.strip()
        try:
            if target_str.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in target_str):
                target_va = int(target_str, 16)
                self._navigate_to_va(target_va)
        except ValueError:
            pass

    def _navigate_to_va(self, target_va: int) -> None:
        if self._current_result is None:
            return
        for row_idx, insn in enumerate(self._current_result.instructions):
            if insn.rva == target_va:
                self.table.scrollToItem(self.table.item(row_idx, 0))
                self.table.selectRow(row_idx)
                self.lbl_selection.setText(
                    f"Jumped to: {insn.rva_hex}  {insn.mnemonic} {insn.op_str}"
                )
                return
        self.lbl_selection.setText(
            f"Target address {target_va:#010x} not found in disassembly "
            "(may be an external or indirect target)."
        )

    def _export_txt(self) -> None:
        if self._current_result is None:
            return
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            "Export Disassembly",
            f"{self._current_file.stem}_disasm.txt" if self._current_file else "disasm.txt",
            "Text Files (*.txt);;All Files (*.*)",
        )
        if not path_str:
            return
        try:
            with open(path_str, "w", encoding="utf-8") as fh:
                fh.write(
                    f"# PyRE Studio — Disassembly Export\n"
                    f"# File:         {self._current_file}\n"
                    f"# Architecture: {self._current_result.architecture} {self._current_result.mode}\n"
                    f"# Section:      {self._current_result.section_name}\n"
                    f"# Instructions: {self._current_result.instruction_count:,}\n\n"
                )
                for insn in self._current_result.instructions:
                    fh.write(f"{insn.full_text}\n")
            self.lbl_stats.setText(f"Exported to: {Path(path_str).name}")
        except OSError as exc:
            self.lbl_stats.setText(f"Export failed: {exc}")
            logger.error("Export failed: %s", exc)
