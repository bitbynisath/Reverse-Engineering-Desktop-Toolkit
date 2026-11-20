"""Background worker executing Windows PE analysis off the GUI thread."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from analyzers.pe_analyzer import parse_pe
from core.models.pe_models import PEAnalysisResult

logger = logging.getLogger(__name__)


class PEWorker(QObject):
    """Worker executing PE header, section, and symbol parsing on a dedicated QThread."""

    progress = Signal(int, str)
    finished = Signal(PEAnalysisResult)
    error = Signal(str)

    def __init__(self, file_path: str | Path) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._is_cancelled = False

    def cancel(self) -> None:
        self._is_cancelled = True

    def run(self) -> None:
        try:
            self.progress.emit(20, f"Validating headers for {self._file_path.name}...")
            if self._is_cancelled:
                return

            self.progress.emit(50, "Parsing sections, imports, and symbols...")
            result = parse_pe(self._file_path)

            if self._is_cancelled:
                return

            self.progress.emit(100, "PE analysis complete.")
            self.finished.emit(result)

        except Exception as exc:
            logger.error("PE worker failed for '%s': %s", self._file_path, exc, exc_info=True)
            self.error.emit(str(exc))
