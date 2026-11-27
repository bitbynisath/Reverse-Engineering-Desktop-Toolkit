"""Background worker executing Python bytecode analysis off the GUI thread."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from analyzers.python_analyzer import analyze_python_file
from core.models.python_models import PythonAnalysisResult

logger = logging.getLogger(__name__)


class PythonWorker(QObject):
    """Worker executing Python .pyc and .py bytecode analysis on a dedicated QThread."""

    progress = Signal(int, str)
    finished = Signal(PythonAnalysisResult)
    error = Signal(str)

    def __init__(self, file_path: str | Path) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._is_cancelled = False

    def cancel(self) -> None:
        self._is_cancelled = True

    def run(self) -> None:
        try:
            self.progress.emit(15, f"Inspecting header & magic bytes: {self._file_path.name}...")
            if self._is_cancelled:
                return

            self.progress.emit(50, "Unmarshalling code objects and disassembling instructions...")
            result = analyze_python_file(self._file_path)

            if self._is_cancelled:
                return

            self.progress.emit(100, f"Python analysis complete ({len(result.code_objects)} code objects).")
            self.finished.emit(result)

        except Exception as exc:
            logger.error(
                "Python bytecode worker failed for '%s': %s",
                self._file_path,
                exc,
                exc_info=True,
            )
            self.error.emit(str(exc))
