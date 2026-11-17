"""Background worker executing file analysis off the GUI thread."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from core.models.file_models import FileAnalysisResult
from core.services.analysis_service import analyze_file

logger = logging.getLogger(__name__)


class AnalysisWorker(QObject):
    """Worker object executing file analysis inside a dedicated QThread."""

    progress = Signal(int, str)  # percent (0-100), status message
    finished = Signal(FileAnalysisResult)
    error = Signal(str)

    def __init__(self, file_path: str | Path, max_size_mb: int = 100) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._max_size_mb = max_size_mb
        self._is_cancelled = False

    def cancel(self) -> None:
        """Signal the worker to cancel processing."""
        self._is_cancelled = True
        logger.info("Cancellation requested for analysis of '%s'", self._file_path)

    def is_cancelled(self) -> bool:
        return self._is_cancelled

    def run(self) -> None:
        """Execute the static analysis sequence."""
        try:
            self.progress.emit(10, f"Validating and reading metadata for {self._file_path.name}...")

            def on_progress(bytes_done: int, total_bytes: int) -> None:
                if total_bytes > 0:
                    percent = 10 + int((bytes_done / total_bytes) * 85)
                    self.progress.emit(min(percent, 95), f"Hashing binary data ({percent}%)...")

            result = analyze_file(
                self._file_path,
                max_size_mb=self._max_size_mb,
                progress_callback=on_progress,
                is_cancelled=self.is_cancelled,
            )

            if self._is_cancelled:
                self.error.emit("Analysis was cancelled by user.")
                return

            self.progress.emit(100, "Analysis complete.")
            self.finished.emit(result)

        except Exception as exc:
            logger.error("Analysis worker failed for '%s': %s", self._file_path, exc, exc_info=True)
            self.error.emit(str(exc))
