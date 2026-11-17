"""File Analyzer Page --- Static Inspection, Signatures, Hashes & Export."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.constants import PAGE_FILE_ANALYZER
from core.models.file_models import FileAnalysisResult
from core.services.analysis_service import export_analysis_to_json
from core.validators import validate_file_path
from ui.widgets.status_banner import StatusBanner
from workers.analysis_worker import AnalysisWorker

logger = logging.getLogger(__name__)


class FileAnalyzerPage(QWidget):
    """Full-featured File Analyzer screen for static binary inspection."""

    file_analyzed = Signal(str, int)  # file_name, file_size

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_FILE_ANALYZER
        self._current_result: FileAnalysisResult | None = None
        self._thread: QThread | None = None
        self._worker: AnalysisWorker | None = None

        self.setAcceptDrops(True)
        self._init_ui()

    def _init_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        self.main_layout = QVBoxLayout(container)
        self.main_layout.setContentsMargins(32, 28, 32, 28)
        self.main_layout.setSpacing(20)

        # Header
        header_row = QHBoxLayout()
        title_col = QVBoxLayout()
        lbl_title = QLabel("File Analyzer")
        lbl_title.setProperty("class", "page-title")
        lbl_desc = QLabel("Static file identification, magic-byte inspection, cryptographic hashes, and format verification.")
        lbl_desc.setProperty("class", "page-subtitle")
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_desc)
        header_row.addLayout(title_col, 1)

        self.btn_select_file = QPushButton("Select File to Analyze...")
        self.btn_select_file.setProperty("class", "primary-btn")
        self.btn_select_file.setCursor(Qt.PointingHandCursor)
        self.btn_select_file.setMinimumHeight(36)
        self.btn_select_file.clicked.connect(self._on_browse_file)
        header_row.addWidget(self.btn_select_file)

        self.btn_export_json = QPushButton("Export JSON Report")
        self.btn_export_json.setCursor(Qt.PointingHandCursor)
        self.btn_export_json.setMinimumHeight(36)
        self.btn_export_json.setEnabled(False)
        self.btn_export_json.clicked.connect(self._on_export_json)
        header_row.addWidget(self.btn_export_json)

        self.main_layout.addLayout(header_row)

        # Progress Bar Card (Hidden by default)
        self.progress_frame = QFrame()
        self.progress_frame.setProperty("class", "card")
        self.progress_frame.setVisible(False)
        prog_layout = QVBoxLayout(self.progress_frame)
        self.lbl_progress_status = QLabel("Analyzing target file...")
        self.lbl_progress_status.setStyleSheet("color: #89b4fa; font-weight: 500;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        btn_cancel_row = QHBoxLayout()
        btn_cancel_row.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self._on_cancel_analysis)
        btn_cancel_row.addWidget(self.btn_cancel)

        prog_layout.addWidget(self.lbl_progress_status)
        prog_layout.addWidget(self.progress_bar)
        prog_layout.addLayout(btn_cancel_row)
        self.main_layout.addWidget(self.progress_frame)

        # Empty State Placeholder
        self.empty_card = QFrame()
        self.empty_card.setProperty("class", "card")
        empty_layout = QVBoxLayout(self.empty_card)
        empty_layout.setContentsMargins(40, 48, 40, 48)
        empty_layout.setSpacing(12)
        lbl_empty_title = QLabel("No File Loaded for Analysis")
        lbl_empty_title.setAlignment(Qt.AlignCenter)
        lbl_empty_title.setStyleSheet("font-size: 16px; font-weight: 600; color: #a6adc8;")
        lbl_empty_sub = QLabel(
            "Click 'Select File to Analyze' above or drag and drop any file directly onto this window.\n"
            "PyRE Studio operates in a read-only mode and never executes target files."
        )
        lbl_empty_sub.setAlignment(Qt.AlignCenter)
        lbl_empty_sub.setStyleSheet("color: #6c7086; font-size: 12px; line-height: 1.5;")
        empty_layout.addWidget(lbl_empty_title)
        empty_layout.addWidget(lbl_empty_sub)
        self.main_layout.addWidget(self.empty_card)

        # Results Container (Hidden until analysis completes)
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(16)

        # 1. Warnings Banner (if any)
        self.banner_warnings = StatusBanner(
            title="Analysis Warning",
            message="",
            banner_type="warning",
        )
        self.banner_warnings.setVisible(False)
        self.results_layout.addWidget(self.banner_warnings)

        # 2. File Metadata Card
        self.meta_card = self._create_metadata_card()
        self.results_layout.addWidget(self.meta_card)

        # 3. File Type & Format Signature Card
        self.sig_card = self._create_signature_card()
        self.results_layout.addWidget(self.sig_card)

        # 4. Cryptographic Hashes Card
        self.hashes_card = self._create_hashes_card()
        self.results_layout.addWidget(self.hashes_card)

        # 5. Security Disclaimer Card
        sec_card = StatusBanner(
            title="Static Analysis Notice",
            message="Signatures and headers are indicators of file structure and do not guarantee a file's safety, benign nature, or true purpose. Extracted metadata reflects static disk attributes.",
            banner_type="info",
        )
        self.results_layout.addWidget(sec_card)

        self.results_container.setVisible(False)
        self.main_layout.addWidget(self.results_container)
        self.main_layout.addStretch()

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(scroll)
        scroll.setWidget(container)

    def _create_metadata_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setSpacing(10)

        header_row = QHBoxLayout()
        lbl_hdr = QLabel("File System Metadata")
        lbl_hdr.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        header_row.addWidget(lbl_hdr)
        header_row.addStretch()

        btn_copy_path = QPushButton("Copy Path")
        btn_copy_path.setCursor(Qt.PointingHandCursor)
        btn_copy_path.setStyleSheet("padding: 3px 8px; font-size: 11px;")
        btn_copy_path.clicked.connect(self._copy_path)
        header_row.addWidget(btn_copy_path)
        layout.addLayout(header_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        grid.setVerticalSpacing(8)

        grid.addWidget(QLabel("<b>File Name:</b>"), 0, 0)
        self.lbl_meta_name = QLabel()
        grid.addWidget(self.lbl_meta_name, 0, 1)

        grid.addWidget(QLabel("<b>Full Path:</b>"), 1, 0)
        self.lbl_meta_path = QLabel()
        self.lbl_meta_path.setWordWrap(True)
        self.lbl_meta_path.setStyleSheet("color: #a6adc8;")
        grid.addWidget(self.lbl_meta_path, 1, 1)

        grid.addWidget(QLabel("<b>File Size:</b>"), 2, 0)
        self.lbl_meta_size = QLabel()
        grid.addWidget(self.lbl_meta_size, 2, 1)

        grid.addWidget(QLabel("<b>Permissions:</b>"), 3, 0)
        self.lbl_meta_perms = QLabel()
        grid.addWidget(self.lbl_meta_perms, 3, 1)

        grid.addWidget(QLabel("<b>Modified:</b>"), 4, 0)
        self.lbl_meta_mtime = QLabel()
        grid.addWidget(self.lbl_meta_mtime, 4, 1)

        grid.addWidget(QLabel("<b>Created:</b>"), 5, 0)
        self.lbl_meta_ctime = QLabel()
        grid.addWidget(self.lbl_meta_ctime, 5, 1)

        layout.addLayout(grid)
        return card

    def _create_signature_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setSpacing(10)

        lbl_hdr = QLabel("File Signature & Format Identification")
        lbl_hdr.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        layout.addWidget(lbl_hdr)

        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        grid.setVerticalSpacing(8)

        grid.addWidget(QLabel("<b>Detected Type:</b>"), 0, 0)
        self.lbl_sig_type = QLabel()
        self.lbl_sig_type.setStyleSheet("font-size: 14px; font-weight: 600; color: #89b4fa;")
        grid.addWidget(self.lbl_sig_type, 0, 1)

        grid.addWidget(QLabel("<b>Category & MIME:</b>"), 1, 0)
        self.lbl_sig_mime = QLabel()
        grid.addWidget(self.lbl_sig_mime, 1, 1)

        grid.addWidget(QLabel("<b>Extension Verification:</b>"), 2, 0)
        self.lbl_ext_comp = QLabel()
        self.lbl_ext_comp.setWordWrap(True)
        grid.addWidget(self.lbl_ext_comp, 2, 1)

        grid.addWidget(QLabel("<b>Magic Bytes (Hex):</b>"), 3, 0)
        self.lbl_magic_hex = QLabel()
        self.lbl_magic_hex.setStyleSheet("font-family: Consolas, monospace; color: #f9e2af;")
        self.lbl_magic_hex.setWordWrap(True)
        grid.addWidget(self.lbl_magic_hex, 3, 1)

        grid.addWidget(QLabel("<b>Magic Preview (ASCII):</b>"), 4, 0)
        self.lbl_magic_ascii = QLabel()
        self.lbl_magic_ascii.setStyleSheet("font-family: Consolas, monospace; color: #a6e3a1;")
        grid.addWidget(self.lbl_magic_ascii, 4, 1)

        layout.addLayout(grid)
        return card

    def _create_hashes_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "card")
        layout = QVBoxLayout(card)
        layout.setSpacing(10)

        header_row = QHBoxLayout()
        lbl_hdr = QLabel("Cryptographic Hashes")
        lbl_hdr.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        header_row.addWidget(lbl_hdr)
        header_row.addStretch()

        self.lbl_hash_time = QLabel()
        self.lbl_hash_time.setStyleSheet("color: #6c7086; font-size: 11px;")
        header_row.addWidget(self.lbl_hash_time)
        layout.addLayout(header_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(8)

        # MD5
        grid.addWidget(QLabel("<b>MD5:</b>"), 0, 0)
        self.lbl_hash_md5 = QLabel()
        self.lbl_hash_md5.setStyleSheet("font-family: Consolas, monospace; color: #cdd6f4;")
        btn_copy_md5 = QPushButton("Copy")
        btn_copy_md5.clicked.connect(lambda: self._copy_to_clipboard(self.lbl_hash_md5.text(), "MD5"))
        grid.addWidget(self.lbl_hash_md5, 0, 1)
        grid.addWidget(btn_copy_md5, 0, 2)

        # SHA-1
        grid.addWidget(QLabel("<b>SHA-1:</b>"), 1, 0)
        self.lbl_hash_sha1 = QLabel()
        self.lbl_hash_sha1.setStyleSheet("font-family: Consolas, monospace; color: #cdd6f4;")
        btn_copy_sha1 = QPushButton("Copy")
        btn_copy_sha1.clicked.connect(lambda: self._copy_to_clipboard(self.lbl_hash_sha1.text(), "SHA-1"))
        grid.addWidget(self.lbl_hash_sha1, 1, 1)
        grid.addWidget(btn_copy_sha1, 1, 2)

        # SHA-256
        grid.addWidget(QLabel("<b>SHA-256:</b>"), 2, 0)
        self.lbl_hash_sha256 = QLabel()
        self.lbl_hash_sha256.setStyleSheet("font-family: Consolas, monospace; color: #cdd6f4;")
        btn_copy_sha256 = QPushButton("Copy")
        btn_copy_sha256.clicked.connect(lambda: self._copy_to_clipboard(self.lbl_hash_sha256.text(), "SHA-256"))
        grid.addWidget(self.lbl_hash_sha256, 2, 1)
        grid.addWidget(btn_copy_sha256, 2, 2)

        # SHA-512
        grid.addWidget(QLabel("<b>SHA-512:</b>"), 3, 0)
        self.lbl_hash_sha512 = QLabel()
        self.lbl_hash_sha512.setWordWrap(True)
        self.lbl_hash_sha512.setStyleSheet("font-family: Consolas, monospace; color: #a6adc8; font-size: 11px;")
        btn_copy_sha512 = QPushButton("Copy")
        btn_copy_sha512.clicked.connect(lambda: self._copy_to_clipboard(self.lbl_hash_sha512.text(), "SHA-512"))
        grid.addWidget(self.lbl_hash_sha512, 3, 1)
        grid.addWidget(btn_copy_sha512, 3, 2)

        layout.addLayout(grid)
        return card

    # Drag and Drop Support
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
            "Select Target File for Static Analysis",
            "",
            "All Files (*.*);;Executables (*.exe *.dll *.sys *.bin);;Documents (*.pdf *.docx);;Archives (*.zip *.7z *.tar)",
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str | Path) -> None:
        """Start background static analysis on the requested file."""
        try:
            validated_path = validate_file_path(file_path)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid File", str(exc))
            return

        # Show progress, hide empty state and previous results
        self.empty_card.setVisible(False)
        self.results_container.setVisible(False)
        self.progress_frame.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_progress_status.setText(f"Initializing static analysis for {validated_path.name}...")
        self.btn_select_file.setEnabled(False)
        self.btn_export_json.setEnabled(False)

        # Spawn worker on QThread
        self._thread = QThread(self)
        self._worker = AnalysisWorker(validated_path)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.error.connect(self._on_worker_error)

        # Thread cleanup
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _on_worker_progress(self, percent: int, message: str) -> None:
        self.progress_bar.setValue(percent)
        self.lbl_progress_status.setText(message)

    def _on_worker_finished(self, result: FileAnalysisResult) -> None:
        self.progress_frame.setVisible(False)
        self.btn_select_file.setEnabled(True)
        self.btn_export_json.setEnabled(True)

        self._current_result = result
        self._display_results(result)
        self.results_container.setVisible(True)

        self.file_analyzed.emit(result.metadata.file_name, result.metadata.size_bytes)

    def _on_worker_error(self, error_message: str) -> None:
        self.progress_frame.setVisible(False)
        self.btn_select_file.setEnabled(True)
        self.empty_card.setVisible(True)
        QMessageBox.critical(self, "Analysis Error", f"Failed to complete file analysis:\n{error_message}")

    def _on_cancel_analysis(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.lbl_progress_status.setText("Cancelling analysis...")
            self.btn_cancel.setEnabled(False)

    def _display_results(self, result: FileAnalysisResult) -> None:
        meta = result.metadata

        # Metadata
        self.lbl_meta_name.setText(f"<b>{meta.file_name}</b>")
        self.lbl_meta_path.setText(meta.file_path)
        self.lbl_meta_size.setText(f"{meta.human_size} ({meta.size_bytes:,} bytes)")
        self.lbl_meta_perms.setText(meta.permissions)
        self.lbl_meta_mtime.setText(meta.modified_time)
        self.lbl_meta_ctime.setText(meta.created_time)

        # Signature
        if result.signature:
            sig = result.signature
            self.lbl_sig_type.setText(sig.name)
            self.lbl_sig_mime.setText(f"{sig.category} &nbsp;|&nbsp; MIME: <code>{sig.mime_type}</code> &nbsp;|&nbsp; Confidence: {sig.confidence}")
        else:
            self.lbl_sig_type.setText("Unidentified Binary / Unknown Signature")
            self.lbl_sig_mime.setText("Raw data or custom format")

        # Extension comparison
        if result.extension_matches_signature:
            self.lbl_ext_comp.setStyleSheet("color: #a6e3a1; font-weight: 500;")
            self.lbl_ext_comp.setText(f"✓ {result.extension_comparison_message}")
        else:
            self.lbl_ext_comp.setStyleSheet("color: #f38ba8; font-weight: 600;")
            self.lbl_ext_comp.setText(f"⚠ {result.extension_comparison_message}")

        self.lbl_magic_hex.setText(result.magic_preview_hex)
        self.lbl_magic_ascii.setText(result.magic_preview_ascii)

        # Hashes
        self.lbl_hash_md5.setText(result.hashes.md5)
        self.lbl_hash_sha1.setText(result.hashes.sha1)
        self.lbl_hash_sha256.setText(result.hashes.sha256)
        self.lbl_hash_sha512.setText(result.hashes.sha512)
        self.lbl_hash_time.setText(f"Calculation time: {result.hashes.elapsed_seconds:.4f}s")

        # Warnings
        if result.warnings:
            self.banner_warnings.setVisible(True)
            warn_text = "<br>• ".join([""] + result.warnings)
            self.banner_warnings.findChild(QLabel, "").setText(f"<b>Warnings and Observations:</b>{warn_text}")
        else:
            self.banner_warnings.setVisible(False)

    def _copy_path(self) -> None:
        if self._current_result:
            self._copy_to_clipboard(self._current_result.metadata.file_path, "File Path")

    def _copy_to_clipboard(self, text: str, label: str) -> None:
        clipboard = QApplication.clipboard()
        if clipboard and text:
            clipboard.setText(text)
            QMessageBox.information(self, "Copied", f"{label} copied to clipboard.")

    def _on_export_json(self) -> None:
        if not self._current_result:
            return

        suggested_name = f"{self._current_result.metadata.file_name}_analysis.json"
        export_file, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Report to JSON",
            suggested_name,
            "JSON Reports (*.json)",
        )
        if not export_file:
            return

        success = export_analysis_to_json(self._current_result, Path(export_file))
        if success:
            QMessageBox.information(
                self,
                "Report Exported",
                f"Analysis report successfully exported to:\n{export_file}",
            )
        else:
            QMessageBox.critical(self, "Export Error", "Failed to write JSON report to disk.")
