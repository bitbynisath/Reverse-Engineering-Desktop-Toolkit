"""String Extractor Page --- Multilingual String Extraction, Filtering & Export."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.constants import DEFAULT_MIN_STRING_LEN, PAGE_STRING_EXTRACTOR
from core.models.string_models import ExtractedString
from core.services.file_service import format_file_size
from core.services.string_service import (
    export_strings_to_csv,
    export_strings_to_txt,
    filter_strings,
)
from core.validators import validate_file_path
from ui.widgets.status_banner import StatusBanner
from workers.string_worker import StringWorker

logger = logging.getLogger(__name__)


class NumericTableWidgetItem(QTableWidgetItem):
    """Table item that sorts numerically based on stored data."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        self_val = self.data(Qt.UserRole)
        other_val = other.data(Qt.UserRole)
        if self_val is not None and other_val is not None:
            return self_val < other_val
        return super().__lt__(other)


class StringExtractorPage(QWidget):
    """Full-featured string extraction screen with filtering and text/CSV export."""

    file_loaded = Signal(str, int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_STRING_EXTRACTOR
        self._current_file: Path | None = None
        self._all_strings: list[ExtractedString] = []
        self._displayed_strings: list[ExtractedString] = []

        self._thread: QThread | None = None
        self._worker: StringWorker | None = None

        self.setAcceptDrops(True)
        self._init_ui()

    def _init_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(24, 20, 24, 20)
        root_layout.setSpacing(12)

        # 1. Header Row
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        lbl_title = QLabel("String Extractor")
        lbl_title.setProperty("class", "page-title")
        self.lbl_file_info = QLabel("No file loaded.")
        self.lbl_file_info.setStyleSheet("color: #a6adc8; font-size: 12px;")
        title_col.addWidget(lbl_title)
        title_col.addWidget(self.lbl_file_info)
        header_layout.addLayout(title_col, 1)

        self.btn_browse = QPushButton("Select File...")
        self.btn_browse.setProperty("class", "primary-btn")
        self.btn_browse.setCursor(Qt.PointingHandCursor)
        self.btn_browse.clicked.connect(self._on_browse_file)
        header_layout.addWidget(self.btn_browse)

        self.btn_export_txt = QPushButton("Export TXT")
        self.btn_export_txt.setCursor(Qt.PointingHandCursor)
        self.btn_export_txt.setEnabled(False)
        self.btn_export_txt.clicked.connect(self._on_export_txt)
        header_layout.addWidget(self.btn_export_txt)

        self.btn_export_csv = QPushButton("Export CSV")
        self.btn_export_csv.setCursor(Qt.PointingHandCursor)
        self.btn_export_csv.setEnabled(False)
        self.btn_export_csv.clicked.connect(self._on_export_csv)
        header_layout.addWidget(self.btn_export_csv)

        root_layout.addLayout(header_layout)

        # 2. Options Toolbar
        opts_card = QFrame()
        opts_card.setProperty("class", "card")
        opts_layout = QHBoxLayout(opts_card)
        opts_layout.setContentsMargins(12, 8, 12, 8)
        opts_layout.setSpacing(14)

        opts_layout.addWidget(QLabel("Min Length:"))
        self.spin_min_len = QSpinBox()
        self.spin_min_len.setRange(3, 64)
        self.spin_min_len.setValue(DEFAULT_MIN_STRING_LEN)
        self.spin_min_len.setFixedWidth(80)
        opts_layout.addWidget(self.spin_min_len)

        opts_layout.addSpacing(8)

        self.chk_ascii = QCheckBox("ASCII")
        self.chk_ascii.setChecked(True)
        self.chk_utf16 = QCheckBox("UTF-16LE")
        self.chk_utf16.setChecked(True)
        self.chk_utf8 = QCheckBox("UTF-8 (Multibyte)")
        self.chk_utf8.setChecked(False)

        opts_layout.addWidget(self.chk_ascii)
        opts_layout.addWidget(self.chk_utf16)
        opts_layout.addWidget(self.chk_utf8)

        opts_layout.addSpacing(12)

        self.btn_extract = QPushButton("Extract Strings")
        self.btn_extract.setProperty("class", "primary-btn")
        self.btn_extract.setCursor(Qt.PointingHandCursor)
        self.btn_extract.clicked.connect(self._start_extraction)
        opts_layout.addWidget(self.btn_extract)

        opts_layout.addStretch()
        root_layout.addWidget(opts_card)

        # 3. Progress Card (Hidden by default)
        self.progress_frame = QFrame()
        self.progress_frame.setProperty("class", "card")
        self.progress_frame.setVisible(False)
        prog_layout = QVBoxLayout(self.progress_frame)
        self.lbl_progress = QLabel("Extracting strings...")
        self.lbl_progress.setStyleSheet("color: #89b4fa; font-weight: 500;")
        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)

        cancel_row = QHBoxLayout()
        cancel_row.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self._on_cancel_extraction)
        cancel_row.addWidget(self.btn_cancel)

        prog_layout.addWidget(self.lbl_progress)
        prog_layout.addWidget(self.prog_bar)
        prog_layout.addLayout(cancel_row)
        root_layout.addWidget(self.progress_frame)

        # 4. Filter Toolbar
        filter_card = QFrame()
        filter_card.setProperty("class", "card")
        flt_layout = QHBoxLayout(filter_card)
        flt_layout.setContentsMargins(12, 6, 12, 6)
        flt_layout.setSpacing(10)

        flt_layout.addWidget(QLabel("Filter:"))
        self.input_filter = QLineEdit()
        self.input_filter.setPlaceholderText("Filter by string content or offset...")
        self.input_filter.textChanged.connect(self._apply_filter)
        flt_layout.addWidget(self.input_filter, 1)

        flt_layout.addWidget(QLabel("Encoding:"))
        self.combo_encoding = QComboBox()
        self.combo_encoding.addItems(["All", "ASCII", "UTF-16LE", "UTF-8"])
        self.combo_encoding.currentIndexChanged.connect(self._apply_filter)
        flt_layout.addWidget(self.combo_encoding)

        self.lbl_stats = QLabel("No strings extracted yet.")
        self.lbl_stats.setStyleSheet("color: #89b4fa; font-size: 11px; font-weight: 600;")
        flt_layout.addWidget(self.lbl_stats)

        root_layout.addWidget(filter_card)

        # 5. Strings Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Offset", "Length", "Encoding", "String Value"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)

        mono_font = QFont("Consolas", 10)
        mono_font.setStyleHint(QFont.Monospace)
        self.table.setFont(mono_font)

        self.table.doubleClicked.connect(self._on_row_double_clicked)
        root_layout.addWidget(self.table, 1)

        # 6. Safety Notice Banner
        sec_banner = StatusBanner(
            title="Analysis Limitation & Untrusted Content Notice",
            message="Extracted strings are raw binary artifacts rendered safely as plain text. Some sequences may represent noise, random byte collisions, or packed code rather than human-readable text.",
            banner_type="info",
        )
        root_layout.addWidget(sec_banner)

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
            "Select Target File for String Extraction",
            "",
            "All Files (*.*);;Executables (*.exe *.dll *.sys *.bin)",
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str | Path) -> None:
        """Load target file and automatically launch string extraction."""
        try:
            validated = validate_file_path(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid File", str(exc))
            return

        self._current_file = validated
        size = validated.stat().st_size
        self.lbl_file_info.setText(f"<b>{validated.name}</b> &nbsp;|&nbsp; {format_file_size(size)} ({size:,} bytes)")
        self.file_loaded.emit(validated.name, size)

        # Trigger extraction
        self._start_extraction()

    def _start_extraction(self) -> None:
        if not self._current_file:
            QMessageBox.information(self, "No File", "Please select a target file first.")
            return

        if not (self.chk_ascii.isChecked() or self.chk_utf16.isChecked() or self.chk_utf8.isChecked()):
            QMessageBox.warning(self, "Selection Required", "Select at least one encoding (ASCII, UTF-16LE, or UTF-8).")
            return

        self.btn_extract.setEnabled(False)
        self.btn_browse.setEnabled(False)
        self.btn_export_txt.setEnabled(False)
        self.btn_export_csv.setEnabled(False)

        self.progress_frame.setVisible(True)
        self.prog_bar.setValue(0)
        self.lbl_progress.setText(f"Scanning {self._current_file.name}...")

        self._thread = QThread(self)
        self._worker = StringWorker(
            file_path=self._current_file,
            min_length=self.spin_min_len.value(),
            extract_ascii=self.chk_ascii.isChecked(),
            extract_utf16=self.chk_utf16.isChecked(),
            extract_utf8=self.chk_utf8.isChecked(),
        )
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.error.connect(self._on_worker_error)

        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _on_worker_progress(self, percent: int, msg: str) -> None:
        self.prog_bar.setValue(percent)
        self.lbl_progress.setText(msg)

    def _on_worker_finished(self, strings: list[ExtractedString]) -> None:
        self.progress_frame.setVisible(False)
        self.btn_extract.setEnabled(True)
        self.btn_browse.setEnabled(True)

        self._all_strings = strings
        has_strings = len(strings) > 0
        self.btn_export_txt.setEnabled(has_strings)
        self.btn_export_csv.setEnabled(has_strings)

        self._apply_filter()

    def _on_worker_error(self, err_msg: str) -> None:
        self.progress_frame.setVisible(False)
        self.btn_extract.setEnabled(True)
        self.btn_browse.setEnabled(True)
        QMessageBox.warning(self, "Extraction Error", f"String extraction failed:\n{err_msg}")

    def _on_cancel_extraction(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.lbl_progress.setText("Cancelling extraction...")

    def _apply_filter(self) -> None:
        query = self.input_filter.text().strip()
        enc_filter = self.combo_encoding.currentText()

        filtered = filter_strings(
            self._all_strings,
            query=query,
            encoding=enc_filter,
            min_len=0,
        )
        self._displayed_strings = filtered
        self._populate_table(filtered)

        ascii_count = sum(1 for s in self._all_strings if s.encoding == "ASCII")
        utf16_count = sum(1 for s in self._all_strings if s.encoding == "UTF-16LE")
        utf8_count = sum(1 for s in self._all_strings if s.encoding == "UTF-8")

        self.lbl_stats.setText(
            f"Showing {len(filtered):,} of {len(self._all_strings):,} strings "
            f"(ASCII: {ascii_count:,}, UTF-16LE: {utf16_count:,}, UTF-8: {utf8_count:,})"
        )

    def _populate_table(self, strings: list[ExtractedString]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(strings))

        for row_idx, s in enumerate(strings):
            item_offset = NumericTableWidgetItem(s.offset_hex)
            item_offset.setData(Qt.UserRole, s.offset)
            item_offset.setForeground(Qt.cyan)

            item_len = NumericTableWidgetItem(str(s.length))
            item_len.setData(Qt.UserRole, s.length)
            item_len.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            item_enc = QTableWidgetItem(s.encoding)
            item_enc.setData(Qt.UserRole, s.encoding)
            if s.encoding == "ASCII":
                item_enc.setForeground(Qt.green)
            elif s.encoding == "UTF-16LE":
                item_enc.setForeground(Qt.yellow)
            else:
                item_enc.setForeground(Qt.magenta)

            item_val = QTableWidgetItem(s.value)
            item_val.setData(Qt.UserRole, s.value)

            self.table.setItem(row_idx, 0, item_offset)
            self.table.setItem(row_idx, 1, item_len)
            self.table.setItem(row_idx, 2, item_enc)
            self.table.setItem(row_idx, 3, item_val)

        self.table.setSortingEnabled(True)

    def _on_row_double_clicked(self) -> None:
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        val_item = self.table.item(row, 3)
        if val_item:
            text = val_item.text()
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(text)
                QMessageBox.information(self, "Copied", f"Copied string to clipboard:\n{text[:100]}")

    def _on_export_txt(self) -> None:
        if not self._displayed_strings:
            return

        default_name = f"{self._current_file.stem}_strings.txt" if self._current_file else "strings.txt"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Strings to Plain Text", default_name, "Text Files (*.txt);;All Files (*.*)"
        )
        if not file_path:
            return

        success = export_strings_to_txt(self._displayed_strings, Path(file_path))
        if success:
            QMessageBox.information(self, "Export Successful", f"Exported {len(self._displayed_strings):,} strings to TXT.")
        else:
            QMessageBox.critical(self, "Export Failed", "Could not write TXT file.")

    def _on_export_csv(self) -> None:
        if not self._displayed_strings:
            return

        default_name = f"{self._current_file.stem}_strings.csv" if self._current_file else "strings.csv"
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Strings to CSV", default_name, "CSV Files (*.csv);;All Files (*.*)"
        )
        if not file_path:
            return

        success = export_strings_to_csv(self._displayed_strings, Path(file_path))
        if success:
            QMessageBox.information(self, "Export Successful", f"Exported {len(self._displayed_strings):,} strings to CSV.")
        else:
            QMessageBox.critical(self, "Export Failed", "Could not write CSV file.")
