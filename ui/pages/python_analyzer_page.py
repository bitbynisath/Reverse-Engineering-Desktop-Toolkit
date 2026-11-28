"""Python Bytecode Analyzer Page --- Structural inspection, constants, flags & disassembly."""

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

from app.constants import PAGE_PYTHON_ANALYZER
from core.models.python_models import (
    CodeObjectSummary,
    PythonAnalysisResult,
    PythonInstruction,
)
from core.services.file_service import format_file_size
from core.validators import validate_file_path
from ui.widgets.status_banner import StatusBanner
from workers.python_worker import PythonWorker

logger = logging.getLogger(__name__)


class PythonAnalyzerPage(QWidget):
    """Full-featured Python bytecode analyzer inspecting .pyc headers, code objects, and dis."""

    file_loaded = Signal(str, int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_PYTHON_ANALYZER
        self._current_file: Path | None = None
        self._current_result: PythonAnalysisResult | None = None
        self._current_code_object: CodeObjectSummary | None = None

        self._thread: QThread | None = None
        self._worker: PythonWorker | None = None

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
        lbl_title = QLabel("Python Bytecode Analyzer")
        lbl_title.setProperty("class", "page-title")
        self.lbl_file_info = QLabel("No Python bytecode (.pyc) or source (.py) file loaded.")
        self.lbl_file_info.setStyleSheet("color: #a6adc8; font-size: 12px;")
        title_col.addWidget(lbl_title)
        title_col.addWidget(self.lbl_file_info)
        header_layout.addLayout(title_col, 1)

        self.btn_export_txt = QPushButton("Export Disassembly")
        self.btn_export_txt.setCursor(Qt.PointingHandCursor)
        self.btn_export_txt.setEnabled(False)
        self.btn_export_txt.clicked.connect(self._on_export_txt)
        header_layout.addWidget(self.btn_export_txt)

        self.btn_browse = QPushButton("Select Python File...")
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
        self.lbl_progress = QLabel("Parsing Python bytecode structures...")
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

        # 3. Status & Compatibility Banner
        self.status_banner = StatusBanner()
        self.status_banner.setVisible(False)
        root_layout.addWidget(self.status_banner)

        # 4. Summary Metric Cards Row
        self.cards_frame = QFrame()
        self.cards_frame.setProperty("class", "card")
        cards_layout = QHBoxLayout(self.cards_frame)
        cards_layout.setContentsMargins(16, 12, 16, 12)
        cards_layout.setSpacing(20)

        self.card_version = self._create_metric_card("Python Target", "—")
        self.card_magic = self._create_metric_card("Magic / Validation", "—")
        self.card_code_objs = self._create_metric_card("Code Objects", "0")
        self.card_instructions = self._create_metric_card("Total Instructions", "0")

        cards_layout.addWidget(self.card_version, 1)
        cards_layout.addWidget(self.card_magic, 1)
        cards_layout.addWidget(self.card_code_objs, 1)
        cards_layout.addWidget(self.card_instructions, 1)
        root_layout.addWidget(self.cards_frame)

        # 5. Code Object Navigation Selector
        selector_card = QFrame()
        selector_card.setProperty("class", "card")
        selector_layout = QHBoxLayout(selector_card)
        selector_layout.setContentsMargins(16, 10, 16, 10)
        selector_layout.setSpacing(12)

        lbl_selector = QLabel("Target Code Object:")
        lbl_selector.setStyleSheet("font-weight: 600; color: #cdd6f4;")
        self.combo_code_objects = QComboBox()
        self.combo_code_objects.setMinimumWidth(380)
        self.combo_code_objects.currentIndexChanged.connect(self._on_code_object_selected)

        self.lbl_code_location = QLabel("")
        self.lbl_code_location.setStyleSheet("color: #a6adc8; font-size: 11px;")

        selector_layout.addWidget(lbl_selector)
        selector_layout.addWidget(self.combo_code_objects)
        selector_layout.addWidget(self.lbl_code_location, 1)
        root_layout.addWidget(selector_card)

        # 6. Tabbed Notebook
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Tab 1: Disassembly
        self.tab_disasm = QWidget()
        self._init_disasm_tab()
        self.tabs.addTab(self.tab_disasm, "Bytecode Disassembly")

        # Tab 2: Properties & Flags
        self.tab_props = QWidget()
        self._init_props_tab()
        self.tabs.addTab(self.tab_props, "Code Object Properties & Flags")

        # Tab 3: Constants (co_consts)
        self.tab_consts = QWidget()
        self._init_consts_tab()
        self.tabs.addTab(self.tab_consts, "Constants (co_consts)")

        # Tab 4: Names & Variables
        self.tab_names = QWidget()
        self._init_names_tab()
        self.tabs.addTab(self.tab_names, "Names & Variables")

        root_layout.addWidget(self.tabs, 1)

    def _create_metric_card(self, title: str, default_val: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        lbl_t = QLabel(title.upper())
        lbl_t.setStyleSheet("font-size: 10px; font-weight: 700; color: #6c7086; letter-spacing: 0.5px;")
        lbl_v = QLabel(default_val)
        lbl_v.setStyleSheet("font-size: 14px; font-weight: 600; color: #cdd6f4;")
        lbl_v.setObjectName("metricValue")

        layout.addWidget(lbl_t)
        layout.addWidget(lbl_v)
        return container

    def _update_card_val(self, card_widget: QWidget, new_text: str) -> None:
        lbl = card_widget.findChild(QLabel, "metricValue")
        if lbl:
            lbl.setText(new_text)

    # --------------------------------------------------------------------------
    # Tab 1: Disassembly
    # --------------------------------------------------------------------------
    def _init_disasm_tab(self) -> None:
        layout = QVBoxLayout(self.tab_disasm)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        # Search Bar
        search_row = QHBoxLayout()
        search_row.setSpacing(8)

        self.input_search = QLineEdit()
        self.input_search.setPlaceholderText("Filter instructions by opcode, offset, argument, or line...")
        self.input_search.textChanged.connect(self._on_filter_changed)
        search_row.addWidget(self.input_search, 1)

        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self.input_search.clear)
        search_row.addWidget(btn_clear)

        self.lbl_disasm_count = QLabel("0 instructions")
        self.lbl_disasm_count.setStyleSheet("color: #a6adc8; font-size: 11px; margin-left: 8px;")
        search_row.addWidget(self.lbl_disasm_count)

        layout.addLayout(search_row)

        # Instruction Table
        self.table_disasm = QTableWidget(0, 6)
        self.table_disasm.setHorizontalHeaderLabels([
            "Line", "Offset", "Opcode", "Arg", "Argument Details", "Jump Target"
        ])
        header = self.table_disasm.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.table_disasm.setAlternatingRowColors(True)
        self.table_disasm.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_disasm.setEditTriggers(QTableWidget.NoEditTriggers)

        mono_font = QFont("Consolas", 9)
        mono_font.setStyleHint(QFont.Monospace)
        self.table_disasm.setFont(mono_font)

        layout.addWidget(self.table_disasm)

    # --------------------------------------------------------------------------
    # Tab 2: Properties & Flags
    # --------------------------------------------------------------------------
    def _init_props_tab(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(16)

        # Grid of General Attributes
        attr_card = QFrame()
        attr_card.setProperty("class", "card")
        attr_layout = QGridLayout(attr_card)
        attr_layout.setContentsMargins(16, 14, 16, 14)
        attr_layout.setHorizontalSpacing(24)
        attr_layout.setVerticalSpacing(10)

        self.lbl_prop_name = QLabel("—")
        self.lbl_prop_filename = QLabel("—")
        self.lbl_prop_firstlineno = QLabel("—")
        self.lbl_prop_argcount = QLabel("—")
        self.lbl_prop_posonly = QLabel("—")
        self.lbl_prop_kwonly = QLabel("—")
        self.lbl_prop_nlocals = QLabel("—")
        self.lbl_prop_stacksize = QLabel("—")

        row = 0
        self._add_grid_row(attr_layout, row, "Code Name:", self.lbl_prop_name, "Source File:", self.lbl_prop_filename)
        row += 1
        self._add_grid_row(attr_layout, row, "First Line #:", self.lbl_prop_firstlineno, "Stack Size:", self.lbl_prop_stacksize)
        row += 1
        self._add_grid_row(attr_layout, row, "Total Args:", self.lbl_prop_argcount, "Local Variables:", self.lbl_prop_nlocals)
        row += 1
        self._add_grid_row(attr_layout, row, "Pos-Only Args:", self.lbl_prop_posonly, "Kw-Only Args:", self.lbl_prop_kwonly)

        layout.addWidget(attr_card)

        # Flags Card
        flags_card = QFrame()
        flags_card.setProperty("class", "card")
        flags_vbox = QVBoxLayout(flags_card)
        flags_vbox.setContentsMargins(16, 14, 16, 14)
        flags_vbox.setSpacing(8)

        lbl_flags_title = QLabel("Code Object Flags (co_flags)")
        lbl_flags_title.setStyleSheet("font-weight: 600; color: #cdd6f4;")
        flags_vbox.addWidget(lbl_flags_title)

        self.lbl_flags_raw = QLabel("Raw Value: 0x0")
        self.lbl_flags_raw.setStyleSheet("color: #a6adc8; font-size: 11px;")
        flags_vbox.addWidget(self.lbl_flags_raw)

        self.flags_container = QWidget()
        self.flags_layout = QVBoxLayout(self.flags_container)
        self.flags_layout.setContentsMargins(0, 4, 0, 0)
        self.flags_layout.setSpacing(4)
        flags_vbox.addWidget(self.flags_container)

        layout.addWidget(flags_card)
        layout.addStretch()

        scroll.setWidget(container)
        outer_layout = QVBoxLayout(self.tab_props)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)

    def _add_grid_row(self, layout: QGridLayout, row: int, l1: str, v1: QLabel, l2: str, v2: QLabel) -> None:
        lbl1 = QLabel(l1)
        lbl1.setStyleSheet("color: #6c7086; font-size: 12px; font-weight: 500;")
        v1.setStyleSheet("color: #cdd6f4; font-size: 12px; font-weight: 600;")
        layout.addWidget(lbl1, row, 0)
        layout.addWidget(v1, row, 1)

        lbl2 = QLabel(l2)
        lbl2.setStyleSheet("color: #6c7086; font-size: 12px; font-weight: 500;")
        v2.setStyleSheet("color: #cdd6f4; font-size: 12px; font-weight: 600;")
        layout.addWidget(lbl2, row, 2)
        layout.addWidget(v2, row, 3)

    # --------------------------------------------------------------------------
    # Tab 3: Constants (co_consts)
    # --------------------------------------------------------------------------
    def _init_consts_tab(self) -> None:
        layout = QVBoxLayout(self.tab_consts)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        self.table_consts = QTableWidget(0, 4)
        self.table_consts.setHorizontalHeaderLabels(["Index", "Type", "Constant Representation", "Inner Code Object"])
        header = self.table_consts.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.table_consts.setAlternatingRowColors(True)
        self.table_consts.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_consts.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addWidget(self.table_consts)

    # --------------------------------------------------------------------------
    # Tab 4: Names & Variables
    # --------------------------------------------------------------------------
    def _init_names_tab(self) -> None:
        layout = QVBoxLayout(self.tab_names)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Horizontal)

        # Left: Global Names & Locals
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        lbl_names = QLabel("Global & Attribute Names (co_names)")
        lbl_names.setStyleSheet("font-weight: 600; color: #cdd6f4;")
        self.table_names = self._create_simple_table(["#", "Name"])
        left_layout.addWidget(lbl_names)
        left_layout.addWidget(self.table_names, 1)

        lbl_varnames = QLabel("Local Variables (co_varnames)")
        lbl_varnames.setStyleSheet("font-weight: 600; color: #cdd6f4; margin-top: 8px;")
        self.table_varnames = self._create_simple_table(["#", "Variable Name"])
        left_layout.addWidget(lbl_varnames)
        left_layout.addWidget(self.table_varnames, 1)

        # Right: Free & Cell Variables (Closures)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        lbl_freevars = QLabel("Free Variables / Outer Scope (co_freevars)")
        lbl_freevars.setStyleSheet("font-weight: 600; color: #cdd6f4;")
        self.table_freevars = self._create_simple_table(["#", "Free Variable"])
        right_layout.addWidget(lbl_freevars)
        right_layout.addWidget(self.table_freevars, 1)

        lbl_cellvars = QLabel("Cell Variables / Enclosed Locals (co_cellvars)")
        lbl_cellvars.setStyleSheet("font-weight: 600; color: #cdd6f4; margin-top: 8px;")
        self.table_cellvars = self._create_simple_table(["#", "Cell Variable"])
        right_layout.addWidget(lbl_cellvars)
        right_layout.addWidget(self.table_cellvars, 1)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def _create_simple_table(self, headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        h = t.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        t.setAlternatingRowColors(True)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        return t

    # --------------------------------------------------------------------------
    # Public & File Loading Methods
    # --------------------------------------------------------------------------
    def load_file(self, file_path: str | Path) -> None:
        """Load and initiate background parsing of a Python bytecode or source file."""
        try:
            validated = validate_file_path(file_path)
            self._current_file = validated
            self.lbl_file_info.setText(f"{validated.name} ({format_file_size(validated.stat().st_size)})")

            self._start_worker(validated)
        except Exception as exc:
            logger.error("Failed to load python file %s: %s", file_path, exc)
            QMessageBox.warning(self, "Load Error", str(exc))

    def _on_browse_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Python Bytecode or Source File",
            "",
            "Python Files (*.pyc *.py);;Compiled Python (*.pyc);;Python Source (*.py);;All Files (*.*)",
        )
        if file_path:
            self.load_file(file_path)

    def _start_worker(self, path: Path) -> None:
        self.progress_frame.setVisible(True)
        self.btn_browse.setEnabled(False)
        self.btn_export_txt.setEnabled(False)
        self.status_banner.setVisible(False)
        self.lbl_progress.setText(f"Analyzing {path.name}...")
        self.prog_bar.setValue(10)

        self._thread = QThread()
        self._worker = PythonWorker(path)
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

    def _on_worker_finished(self, result: PythonAnalysisResult) -> None:
        self.progress_frame.setVisible(False)
        self.btn_browse.setEnabled(True)
        self._current_result = result

        has_code = len(result.code_objects) > 0
        self.btn_export_txt.setEnabled(has_code)

        # Update Summary Cards
        if result.header:
            self._update_card_val(self.card_version, result.header.python_version_detected)
            self._update_card_val(self.card_magic, f"0x{result.header.magic_bytes_hex} ({result.header.hash_check_mode})")
        else:
            self._update_card_val(self.card_version, "Source (.py) Compiled")
            self._update_card_val(self.card_magic, "Native In-Memory")

        self._update_card_val(self.card_code_objs, str(len(result.code_objects)))
        total_ins = sum(co.instruction_count for co in result.code_objects)
        self._update_card_val(self.card_instructions, f"{total_ins:,}")

        # Update Status Banner (warnings or errors)
        if result.errors:
            self.status_banner.set_error("\n".join(result.errors))
            self.status_banner.setVisible(True)
        elif result.warnings:
            self.status_banner.set_warning("\n".join(result.warnings))
            self.status_banner.setVisible(True)
        else:
            self.status_banner.setVisible(False)

        # Populate Code Object Dropdown
        self.combo_code_objects.blockSignals(True)
        self.combo_code_objects.clear()
        for co in result.code_objects:
            label = f"{co.qualified_name} (Line {co.firstlineno}, {co.instruction_count} ins)"
            self.combo_code_objects.addItem(label, co.id)
        self.combo_code_objects.blockSignals(False)

        if result.code_objects:
            self._display_code_object(result.code_objects[0])

        self.file_loaded.emit(result.file_name, result.file_size)

    def _on_worker_error(self, err_msg: str) -> None:
        self.progress_frame.setVisible(False)
        self.btn_browse.setEnabled(True)
        if "cancel" not in err_msg.lower():
            QMessageBox.warning(self, "Analysis Error", f"Python analysis failed:\n{err_msg}")

    def _on_cancel(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.lbl_progress.setText("Cancelling analysis...")

    def _on_code_object_selected(self, index: int) -> None:
        if not self._current_result or index < 0 or index >= len(self._current_result.code_objects):
            return
        co = self._current_result.code_objects[index]
        self._display_code_object(co)

    def _display_code_object(self, co: CodeObjectSummary) -> None:
        self._current_code_object = co
        self.lbl_code_location.setText(f"File: {co.filename} | First Line: {co.firstlineno}")

        # 1. Update Disassembly Tab
        self._populate_disassembly_table(co.instructions)

        # 2. Update Properties & Flags
        self.lbl_prop_name.setText(co.name)
        self.lbl_prop_filename.setText(co.filename)
        self.lbl_prop_firstlineno.setText(str(co.firstlineno))
        self.lbl_prop_argcount.setText(str(co.argcount))
        self.lbl_prop_posonly.setText(str(co.posonlyargcount))
        self.lbl_prop_kwonly.setText(str(co.kwonlyargcount))
        self.lbl_prop_nlocals.setText(str(co.nlocals))
        self.lbl_prop_stacksize.setText(str(co.stacksize))
        self.lbl_flags_raw.setText(f"Raw co_flags: 0x{co.flags_int:04X} ({co.flags_int})")

        # Clear flags container
        while self.flags_layout.count():
            item = self.flags_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if co.flags_names:
            for flag_str in co.flags_names:
                lbl_f = QLabel(f"✔  {flag_str}")
                lbl_f.setStyleSheet("color: #a6e3a1; font-size: 11px; font-weight: 500;")
                self.flags_layout.addWidget(lbl_f)
        else:
            lbl_none = QLabel("No active flags (0x0)")
            lbl_none.setStyleSheet("color: #6c7086; font-size: 11px;")
            self.flags_layout.addWidget(lbl_none)

        # 3. Update Constants Table
        self.table_consts.setRowCount(len(co.consts))
        for r, c in enumerate(co.consts):
            self.table_consts.setItem(r, 0, QTableWidgetItem(str(c["index"])))
            self.table_consts.setItem(r, 1, QTableWidgetItem(c["type"]))
            self.table_consts.setItem(r, 2, QTableWidgetItem(c["repr"]))
            tag = "YES (Code Object)" if c["is_code"] else "—"
            item_tag = QTableWidgetItem(tag)
            if c["is_code"]:
                item_tag.setForeground(Qt.cyan)
            self.table_consts.setItem(r, 3, item_tag)

        # 4. Update Names Tables
        self._populate_names_table(self.table_names, co.names)
        self._populate_names_table(self.table_varnames, co.varnames)
        self._populate_names_table(self.table_freevars, co.freevars)
        self._populate_names_table(self.table_cellvars, co.cellvars)

    def _populate_disassembly_table(self, instructions: list[PythonInstruction]) -> None:
        self.table_disasm.setRowCount(len(instructions))
        for r, ins in enumerate(instructions):
            line_str = str(ins.starts_line) if ins.starts_line is not None else ""
            arg_str = str(ins.arg) if ins.arg is not None else ""
            jump_str = str(ins.jump_target) if ins.jump_target is not None else ""
            details = ins.argrepr if ins.argrepr else ins.argval

            item_line = QTableWidgetItem(line_str)
            item_offset = QTableWidgetItem(f"{ins.offset:>5}")
            item_op = QTableWidgetItem(ins.opname)
            item_arg = QTableWidgetItem(arg_str)
            item_details = QTableWidgetItem(details)
            item_jump = QTableWidgetItem(jump_str)

            # Style opcodes
            op = ins.opname.upper()
            if "JUMP" in op or "FOR_ITER" in op:
                item_op.setForeground(Qt.magenta)  # Rose / Magenta for jumps
            elif "RETURN" in op or "YIELD" in op:
                item_op.setForeground(Qt.green)    # Green for returns
            elif "CALL" in op:
                item_op.setForeground(Qt.cyan)     # Cyan / Blue for calls
            elif "LOAD" in op or "STORE" in op:
                item_op.setForeground(Qt.yellow)   # Yellow / Peach for load/store

            if ins.is_jump_target:
                item_offset.setText(f"▶ {ins.offset}")
                item_offset.setForeground(Qt.magenta)

            self.table_disasm.setItem(r, 0, item_line)
            self.table_disasm.setItem(r, 1, item_offset)
            self.table_disasm.setItem(r, 2, item_op)
            self.table_disasm.setItem(r, 3, item_arg)
            self.table_disasm.setItem(r, 4, item_details)
            self.table_disasm.setItem(r, 5, item_jump)

        self.lbl_disasm_count.setText(f"{len(instructions):,} instructions")
        self._on_filter_changed(self.input_search.text())

    def _populate_names_table(self, table: QTableWidget, names: list[str]) -> None:
        table.setRowCount(len(names))
        for r, n in enumerate(names):
            table.setItem(r, 0, QTableWidgetItem(str(r)))
            table.setItem(r, 1, QTableWidgetItem(n))

    def _on_filter_changed(self, text: str) -> None:
        query = text.strip().lower()
        visible_count = 0
        for r in range(self.table_disasm.rowCount()):
            if not query:
                self.table_disasm.setRowHidden(r, False)
                visible_count += 1
                continue

            match = False
            for col in range(self.table_disasm.columnCount()):
                item = self.table_disasm.item(r, col)
                if item and query in item.text().lower():
                    match = True
                    break
            self.table_disasm.setRowHidden(r, not match)
            if match:
                visible_count += 1

        total = self.table_disasm.rowCount()
        if query:
            self.lbl_disasm_count.setText(f"Showing {visible_count:,} of {total:,} instructions")
        else:
            self.lbl_disasm_count.setText(f"{total:,} instructions")

    def _on_export_txt(self) -> None:
        if not self._current_result:
            return

        from analyzers.python_analyzer import format_disassembly_listing

        export_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Python Bytecode Disassembly",
            f"{self._current_result.file_name}_disasm.txt",
            "Text Files (*.txt);;All Files (*.*)",
        )
        if not export_path:
            return

        try:
            listing = format_disassembly_listing(self._current_result)
            Path(export_path).write_text(listing, encoding="utf-8")
            QMessageBox.information(
                self,
                "Export Successful",
                f"Full disassembly listing successfully saved to:\n{export_path}",
            )
        except Exception as exc:
            logger.error("Failed to export python disassembly: %s", exc)
            QMessageBox.warning(self, "Export Error", f"Failed to save disassembly:\n{exc}")

    # --------------------------------------------------------------------------
    # Drag and Drop
    # --------------------------------------------------------------------------
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if urls:
            first_path = urls[0].toLocalFile()
            if first_path:
                self.load_file(first_path)
                event.acceptProposedAction()
