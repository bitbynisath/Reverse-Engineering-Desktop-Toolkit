"""Hexadecimal Viewer Page --- Paged Binary Inspection, Search & Byte Inspector."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.constants import DEFAULT_HEX_BYTES_PER_ROW, PAGE_HEX_VIEWER
from core.exceptions import ValidationError
from core.models.hex_models import ByteSelection, HexRow
from core.services.binary_reader import BinaryReader
from core.services.file_service import format_file_size
from core.services.hex_service import (
    calculate_total_pages,
    get_hex_page,
    inspect_byte,
    offset_to_page,
)
from core.validators import validate_file_path
from workers.hex_search_worker import HexSearchWorker

logger = logging.getLogger(__name__)


class HexViewerPage(QWidget):
    """Memory-bounded Hexadecimal Viewer with paging, searching, and byte inspection."""

    file_loaded = Signal(str, int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_HEX_VIEWER
        self._reader: BinaryReader | None = None
        self._current_file: Path | None = None

        self._bytes_per_row = DEFAULT_HEX_BYTES_PER_ROW
        self._rows_per_page = 32
        self._current_page = 0
        self._total_pages = 1

        self._search_thread: QThread | None = None
        self._search_worker: HexSearchWorker | None = None
        self._search_matches: list[int] = []
        self._current_match_idx = -1

        self.setAcceptDrops(True)
        self._init_ui()

    def _init_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(24, 20, 24, 20)
        root_layout.setSpacing(12)

        # 1. Top Header Bar (Title, Browse, and File Info)
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        lbl_title = QLabel("Hexadecimal Viewer")
        lbl_title.setProperty("class", "page-title")
        self.lbl_file_info = QLabel("No file loaded.")
        self.lbl_file_info.setStyleSheet("color: #a6adc8; font-size: 12px;")
        title_col.addWidget(lbl_title)
        title_col.addWidget(self.lbl_file_info)
        header_layout.addLayout(title_col, 1)

        self.btn_open_file = QPushButton("Browse File...")
        self.btn_open_file.setProperty("class", "primary-btn")
        self.btn_open_file.setCursor(Qt.PointingHandCursor)
        self.btn_open_file.clicked.connect(self._on_browse_file)
        header_layout.addWidget(self.btn_open_file)

        root_layout.addLayout(header_layout)

        # 2. Control Toolbar (Paging, Go to Offset, Bytes per Row)
        toolbar = QFrame()
        toolbar.setProperty("class", "card")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(12, 8, 12, 8)
        tb_layout.setSpacing(10)

        # Paging Buttons
        self.btn_first_page = QPushButton("<<")
        self.btn_first_page.setToolTip("First Page")
        self.btn_first_page.setFixedWidth(36)
        self.btn_first_page.clicked.connect(self._go_first_page)

        self.btn_prev_page = QPushButton("<")
        self.btn_prev_page.setToolTip("Previous Page")
        self.btn_prev_page.setFixedWidth(36)
        self.btn_prev_page.clicked.connect(self._go_prev_page)

        self.spin_page = QSpinBox()
        self.spin_page.setRange(1, 1)
        self.spin_page.setValue(1)
        self.spin_page.setFixedWidth(70)
        self.spin_page.valueChanged.connect(self._on_page_spin_changed)

        self.lbl_total_pages = QLabel("/ 1")
        self.lbl_total_pages.setStyleSheet("color: #a6adc8; font-weight: 500;")

        self.btn_next_page = QPushButton(">")
        self.btn_next_page.setToolTip("Next Page")
        self.btn_next_page.setFixedWidth(36)
        self.btn_next_page.clicked.connect(self._go_next_page)

        self.btn_last_page = QPushButton(">>")
        self.btn_last_page.setToolTip("Last Page")
        self.btn_last_page.setFixedWidth(36)
        self.btn_last_page.clicked.connect(self._go_last_page)

        tb_layout.addWidget(QLabel("Page:"))
        tb_layout.addWidget(self.btn_first_page)
        tb_layout.addWidget(self.btn_prev_page)
        tb_layout.addWidget(self.spin_page)
        tb_layout.addWidget(self.lbl_total_pages)
        tb_layout.addWidget(self.btn_next_page)
        tb_layout.addWidget(self.btn_last_page)

        tb_layout.addSpacing(16)

        # Go to Offset
        tb_layout.addWidget(QLabel("Go to Offset:"))
        self.input_goto_offset = QLineEdit()
        self.input_goto_offset.setPlaceholderText("Hex (0x100) or Dec")
        self.input_goto_offset.setFixedWidth(140)
        self.input_goto_offset.returnPressed.connect(self._on_goto_offset)
        btn_goto = QPushButton("Go")
        btn_goto.clicked.connect(self._on_goto_offset)

        tb_layout.addWidget(self.input_goto_offset)
        tb_layout.addWidget(btn_goto)

        tb_layout.addSpacing(16)

        # Bytes Per Row Selector
        tb_layout.addWidget(QLabel("Bytes / Row:"))
        self.combo_bytes_row = QComboBox()
        self.combo_bytes_row.addItems(["8", "16", "24", "32"])
        self.combo_bytes_row.setCurrentText(str(self._bytes_per_row))
        self.combo_bytes_row.currentIndexChanged.connect(self._on_bytes_row_changed)
        tb_layout.addWidget(self.combo_bytes_row)

        tb_layout.addStretch()
        root_layout.addWidget(toolbar)

        # 3. Search Bar
        search_card = QFrame()
        search_card.setProperty("class", "card")
        sc_layout = QHBoxLayout(search_card)
        sc_layout.setContentsMargins(12, 6, 12, 6)
        sc_layout.setSpacing(10)

        sc_layout.addWidget(QLabel("Search Pattern:"))
        self.input_search = QLineEdit()
        self.input_search.setPlaceholderText("e.g. 4D 5A 90 or text string")
        self.input_search.returnPressed.connect(self._on_search)
        sc_layout.addWidget(self.input_search, 1)

        self.combo_search_mode = QComboBox()
        self.combo_search_mode.addItems(["Hex Bytes", "Text (UTF-8)"])
        sc_layout.addWidget(self.combo_search_mode)

        self.btn_search = QPushButton("Find All")
        self.btn_search.clicked.connect(self._on_search)
        sc_layout.addWidget(self.btn_search)

        self.btn_prev_match = QPushButton("▲ Prev")
        self.btn_prev_match.setEnabled(False)
        self.btn_prev_match.clicked.connect(self._prev_match)
        sc_layout.addWidget(self.btn_prev_match)

        self.btn_next_match = QPushButton("▼ Next")
        self.btn_next_match.setEnabled(False)
        self.btn_next_match.clicked.connect(self._next_match)
        sc_layout.addWidget(self.btn_next_match)

        self.lbl_search_count = QLabel("")
        self.lbl_search_count.setStyleSheet("color: #89b4fa; font-size: 11px; font-weight: 600;")
        sc_layout.addWidget(self.lbl_search_count)

        root_layout.addWidget(search_card)

        # 4. Hex Table Display
        self.hex_table = QTableWidget()
        self.hex_table.setColumnCount(3)
        self.hex_table.setHorizontalHeaderLabels(["Offset", "Hexadecimal Bytes", "Printable ASCII"])
        self.hex_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.hex_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.hex_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.hex_table.verticalHeader().setVisible(False)
        self.hex_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.hex_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hex_table.setSelectionMode(QTableWidget.SingleSelection)

        # Monospace font for aligned byte columns
        mono_font = QFont("Consolas", 10)
        mono_font.setStyleHint(QFont.Monospace)
        self.hex_table.setFont(mono_font)

        self.hex_table.itemSelectionChanged.connect(self._on_table_row_selected)
        root_layout.addWidget(self.hex_table, 1)

        # 5. Byte Inspector Panel
        self.inspector_card = self._create_inspector_panel()
        root_layout.addWidget(self.inspector_card)

        self._update_paging_controls()

    def _create_inspector_panel(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(6)

        hdr_row = QHBoxLayout()
        lbl_hdr = QLabel("Byte Inspector")
        lbl_hdr.setStyleSheet("font-weight: 600; font-size: 13px; color: #cdd6f4;")
        hdr_row.addWidget(lbl_hdr)
        hdr_row.addStretch()
        self.lbl_inspector_status = QLabel("Select a row in the table to inspect data values.")
        self.lbl_inspector_status.setStyleSheet("color: #6c7086; font-size: 11px;")
        hdr_row.addWidget(self.lbl_inspector_status)
        layout.addLayout(hdr_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(4)

        grid.addWidget(QLabel("Offset:"), 0, 0)
        self.lbl_insp_offset = QLabel("---")
        self.lbl_insp_offset.setStyleSheet("color: #89b4fa; font-weight: 600; font-family: Consolas;")
        grid.addWidget(self.lbl_insp_offset, 0, 1)

        grid.addWidget(QLabel("Byte Value:"), 0, 2)
        self.lbl_insp_byte = QLabel("---")
        self.lbl_insp_byte.setStyleSheet("color: #f9e2af; font-weight: 600; font-family: Consolas;")
        grid.addWidget(self.lbl_insp_byte, 0, 3)

        grid.addWidget(QLabel("Binary (8-bit):"), 0, 4)
        self.lbl_insp_bin = QLabel("---")
        self.lbl_insp_bin.setStyleSheet("color: #a6e3a1; font-family: Consolas;")
        grid.addWidget(self.lbl_insp_bin, 0, 5)

        grid.addWidget(QLabel("Character:"), 1, 0)
        self.lbl_insp_char = QLabel("---")
        self.lbl_insp_char.setStyleSheet("font-weight: 600; font-family: Consolas;")
        grid.addWidget(self.lbl_insp_char, 1, 1)

        grid.addWidget(QLabel("UInt16 (LE):"), 1, 2)
        self.lbl_insp_u16 = QLabel("---")
        self.lbl_insp_u16.setStyleSheet("font-family: Consolas;")
        grid.addWidget(self.lbl_insp_u16, 1, 3)

        grid.addWidget(QLabel("UInt32 (LE):"), 1, 4)
        self.lbl_insp_u32 = QLabel("---")
        self.lbl_insp_u32.setStyleSheet("font-family: Consolas;")
        grid.addWidget(self.lbl_insp_u32, 1, 5)

        layout.addLayout(grid)
        return card

    # Drag and drop support
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
            "Select Binary File for Hex Inspection",
            "",
            "All Files (*.*);;Executables (*.exe *.dll *.sys *.bin)",
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str | Path) -> None:
        """Open binary file with bounded memory reader and display first page."""
        try:
            validated = validate_file_path(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Cannot Open File", str(exc))
            return

        # Close existing reader if any
        if self._reader is not None:
            self._reader.close()
            self._reader = None

        try:
            self._reader = BinaryReader(validated)
            self._current_file = validated

            file_size = self._reader.file_size
            human_size = format_file_size(file_size)
            self.lbl_file_info.setText(f"<b>{validated.name}</b> &nbsp;|&nbsp; {human_size} ({file_size:,} bytes)")

            self._total_pages = calculate_total_pages(file_size, self._rows_per_page, self._bytes_per_row)
            self._current_page = 0

            self.spin_page.blockSignals(True)
            self.spin_page.setRange(1, max(1, self._total_pages))
            self.spin_page.setValue(1)
            self.spin_page.blockSignals(False)

            self.lbl_total_pages.setText(f"/ {self._total_pages:,}")

            # Reset search results
            self._search_matches.clear()
            self._current_match_idx = -1
            self.lbl_search_count.setText("")
            self.btn_next_match.setEnabled(False)
            self.btn_prev_match.setEnabled(False)

            self._load_current_page()
            self._update_paging_controls()

            self.file_loaded.emit(validated.name, file_size)
            logger.info("Loaded '%s' into Hex Viewer (%s)", validated.name, human_size)

        except Exception as exc:
            logger.error("Failed to load binary '%s' in Hex Viewer: %s", validated, exc, exc_info=True)
            QMessageBox.critical(self, "Hex Viewer Error", f"Failed to read binary file:\n{exc}")

    def _load_current_page(self) -> None:
        if self._reader is None:
            self.hex_table.setRowCount(0)
            return

        rows = get_hex_page(
            self._reader,
            page_index=self._current_page,
            rows_per_page=self._rows_per_page,
            bytes_per_row=self._bytes_per_row,
        )

        self.hex_table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            # 0. Offset column
            item_offset = QTableWidgetItem(f"{row.offset_hex}:")
            item_offset.setForeground(Qt.cyan)
            item_offset.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            item_offset.setData(Qt.UserRole, row.offset)

            # 1. Hex Bytes column
            item_hex = QTableWidgetItem(row.hex_representation)
            item_hex.setData(Qt.UserRole, row.offset)

            # 2. ASCII column
            item_ascii = QTableWidgetItem(row.ascii_representation)
            item_ascii.setData(Qt.UserRole, row.offset)

            self.hex_table.setItem(row_idx, 0, item_offset)
            self.hex_table.setItem(row_idx, 1, item_hex)
            self.hex_table.setItem(row_idx, 2, item_ascii)

        # Select first row by default if available
        if len(rows) > 0:
            self.hex_table.selectRow(0)

    def _update_paging_controls(self) -> None:
        has_file = self._reader is not None
        can_prev = has_file and self._current_page > 0
        can_next = has_file and self._current_page < self._total_pages - 1

        self.btn_first_page.setEnabled(can_prev)
        self.btn_prev_page.setEnabled(can_prev)
        self.btn_next_page.setEnabled(can_next)
        self.btn_last_page.setEnabled(can_next)
        self.spin_page.setEnabled(has_file and self._total_pages > 1)

    def _go_first_page(self) -> None:
        if self._current_page != 0:
            self._current_page = 0
            self.spin_page.setValue(1)
            self._load_current_page()
            self._update_paging_controls()

    def _go_prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self.spin_page.setValue(self._current_page + 1)
            self._load_current_page()
            self._update_paging_controls()

    def _go_next_page(self) -> None:
        if self._current_page < self._total_pages - 1:
            self._current_page += 1
            self.spin_page.setValue(self._current_page + 1)
            self._load_current_page()
            self._update_paging_controls()

    def _go_last_page(self) -> None:
        last_page = max(0, self._total_pages - 1)
        if self._current_page != last_page:
            self._current_page = last_page
            self.spin_page.setValue(self._total_pages)
            self._load_current_page()
            self._update_paging_controls()

    def _on_page_spin_changed(self, page_num: int) -> None:
        new_page = page_num - 1
        if new_page != self._current_page and 0 <= new_page < self._total_pages:
            self._current_page = new_page
            self._load_current_page()
            self._update_paging_controls()

    def _on_bytes_row_changed(self) -> None:
        self._bytes_per_row = int(self.combo_bytes_row.currentText())
        if self._reader is not None:
            self._total_pages = calculate_total_pages(
                self._reader.file_size, self._rows_per_page, self._bytes_per_row
            )
            self.spin_page.blockSignals(True)
            self.spin_page.setRange(1, max(1, self._total_pages))
            self.spin_page.setValue(min(self._current_page + 1, self._total_pages))
            self.spin_page.blockSignals(False)
            self.lbl_total_pages.setText(f"/ {self._total_pages:,}")
            self._current_page = min(self._current_page, max(0, self._total_pages - 1))
            self._load_current_page()
            self._update_paging_controls()

    def _on_goto_offset(self) -> None:
        if self._reader is None:
            return

        text = self.input_goto_offset.text().strip()
        if not text:
            return

        try:
            if text.lower().startswith("0x") or any(c in "abcdefABCDEF" for c in text):
                target_offset = int(text, 16)
            else:
                target_offset = int(text, 10)
        except ValueError:
            QMessageBox.warning(self, "Invalid Offset", f"'{text}' is not a valid decimal or hex offset.")
            return

        if target_offset < 0 or target_offset >= self._reader.file_size:
            QMessageBox.warning(
                self,
                "Offset Out of Bounds",
                f"Offset {target_offset} (0x{target_offset:X}) is outside file range (0 - {self._reader.file_size - 1}).",
            )
            return

        target_page = offset_to_page(target_offset, self._rows_per_page, self._bytes_per_row)
        self._current_page = target_page
        self.spin_page.setValue(target_page + 1)
        self._load_current_page()
        self._update_paging_controls()

        # Highlight the specific row containing the offset
        bytes_per_page = self._rows_per_page * self._bytes_per_row
        offset_in_page = target_offset - (target_page * bytes_per_page)
        row_in_page = offset_in_page // self._bytes_per_row

        if 0 <= row_in_page < self.hex_table.rowCount():
            self.hex_table.selectRow(row_in_page)

    def _on_table_row_selected(self) -> None:
        selected_rows = self.hex_table.selectionModel().selectedRows()
        if not selected_rows or self._reader is None:
            return

        row_idx = selected_rows[0].row()
        item = self.hex_table.item(row_idx, 0)
        if item is None:
            return

        row_offset = item.data(Qt.UserRole)
        try:
            info: ByteSelection = inspect_byte(self._reader, row_offset)
            self.lbl_insp_offset.setText(f"{info.offset_hex} ({info.offset:,})")
            self.lbl_insp_byte.setText(f"{info.byte_hex} ({info.byte_value})")
            self.lbl_insp_bin.setText(info.byte_bin)
            self.lbl_insp_char.setText(f"'{info.byte_char}'")
            self.lbl_insp_u16.setText(f"0x{info.uint16_le:04X} ({info.uint16_le})" if info.uint16_le is not None else "---")
            self.lbl_insp_u32.setText(f"0x{info.uint32_le:08X} ({info.uint32_le})" if info.uint32_le is not None else "---")
            self.lbl_inspector_status.setText(f"Selected row base offset: {info.offset_hex}")
        except Exception as exc:
            logger.debug("Byte inspection failed: %s", exc)

    def _on_search(self) -> None:
        if self._reader is None:
            return

        query = self.input_search.text().strip()
        if not query:
            return

        mode = "hex" if self.combo_search_mode.currentIndex() == 0 else "text"

        self.btn_search.setEnabled(False)
        self.lbl_search_count.setText("Searching...")

        self._search_thread = QThread(self)
        self._search_worker = HexSearchWorker(
            file_path=self._current_file,
            query=query,
            search_mode=mode,
        )
        self._search_worker.moveToThread(self._search_thread)

        self._search_thread.started.connect(self._search_worker.run)
        self._search_worker.matches_found.connect(self._on_search_matches_found)
        self._search_worker.error.connect(self._on_search_error)
        self._search_worker.search_finished.connect(self._search_thread.quit)
        self._search_worker.error.connect(self._search_thread.quit)
        self._search_thread.finished.connect(self._search_thread.deleteLater)

        self._search_thread.start()

    def _on_search_matches_found(self, matches: list[int]) -> None:
        self.btn_search.setEnabled(True)
        self._search_matches = matches

        if not matches:
            self.lbl_search_count.setText("No matches found.")
            self.btn_prev_match.setEnabled(False)
            self.btn_next_match.setEnabled(False)
            return

        self._current_match_idx = 0
        self.lbl_search_count.setText(f"Match 1 of {len(matches)}")
        self.btn_prev_match.setEnabled(len(matches) > 1)
        self.btn_next_match.setEnabled(len(matches) > 1)

        self._jump_to_match(matches[0])

    def _on_search_error(self, err_msg: str) -> None:
        self.btn_search.setEnabled(True)
        self.lbl_search_count.setText("Search error.")
        QMessageBox.warning(self, "Search Error", f"Failed to execute search:\n{err_msg}")

    def _next_match(self) -> None:
        if not self._search_matches:
            return
        self._current_match_idx = (self._current_match_idx + 1) % len(self._search_matches)
        self.lbl_search_count.setText(f"Match {self._current_match_idx + 1} of {len(self._search_matches)}")
        self._jump_to_match(self._search_matches[self._current_match_idx])

    def _prev_match(self) -> None:
        if not self._search_matches:
            return
        self._current_match_idx = (self._current_match_idx - 1) % len(self._search_matches)
        self.lbl_search_count.setText(f"Match {self._current_match_idx + 1} of {len(self._search_matches)}")
        self._jump_to_match(self._search_matches[self._current_match_idx])

    def _jump_to_match(self, match_offset: int) -> None:
        target_page = offset_to_page(match_offset, self._rows_per_page, self._bytes_per_row)
        if target_page != self._current_page:
            self._current_page = target_page
            self.spin_page.setValue(target_page + 1)
            self._load_current_page()
            self._update_paging_controls()

        bytes_per_page = self._rows_per_page * self._bytes_per_row
        offset_in_page = match_offset - (target_page * bytes_per_page)
        row_in_page = offset_in_page // self._bytes_per_row

        if 0 <= row_in_page < self.hex_table.rowCount():
            self.hex_table.selectRow(row_in_page)

    def closeEvent(self, event) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None
        super().closeEvent(event)
