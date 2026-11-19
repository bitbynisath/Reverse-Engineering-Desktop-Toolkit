"""Background worker executing string extraction off the GUI thread."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from core.models.string_models import ExtractedString
from core.services.string_service import extract_strings

logger = logging.getLogger(__name__)


class StringWorker(QObject):
    """Worker object executing string extraction on a dedicated QThread."""

    progress = Signal(int, str)  # percent (0-100), message
    finished = Signal(list)     # list of ExtractedString objects
    error = Signal(str)

    def __init__(
        self,
        file_path: str | Path,
        min_length: int = 4,
        extract_ascii: bool = True,
        extract_utf16: bool = True,
        extract_utf8: bool = False,
        max_strings: int = 100_000,
    ) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._min_length = min_length
        self._extract_ascii = extract_ascii
        self._extract_utf16 = extract_utf16
        self._extract_utf8 = extract_utf8
        self._max_strings = max_strings
        self._is_cancelled = False

    def cancel(self) -> None:
        """Signal worker to abort extraction cooperatively."""
        self._is_cancelled = True
        logger.info("String extraction cancellation requested for '%s'", self._file_path)

    def is_cancelled(self) -> bool:
        return self._is_cancelled

    def run(self) -> None:
        """Execute the string extraction sequence."""
        try:
            self.progress.emit(0, f"Scanning {self._file_path.name} for strings...")

            def on_progress(bytes_done: int, total_bytes: int) -> None:
                if total_bytes > 0:
                    percent = int((bytes_done / total_bytes) * 100)
                    self.progress.emit(min(percent, 99), f"Extracting strings ({percent}%)...")

            strings = extract_strings(
                self._file_path,
                min_length=self._min_length,
                extract_ascii=self._extract_ascii,
                extract_utf16=self._extract_utf16,
                extract_utf8=self._extract_utf8,
                max_strings=self._max_strings,
                progress_callback=on_progress,
                is_cancelled=self.is_cancelled,
            )

            if self._is_cancelled:
                self.error.emit("String extraction cancelled by user.")
                return

            self.progress.emit(100, f"Found {len(strings):,} strings.")
            self.finished.emit(strings)

        except Exception as exc:
            logger.error("String worker failed for '%s': %s", self._file_path, exc, exc_info=True)
            self.error.emit(str(exc))
