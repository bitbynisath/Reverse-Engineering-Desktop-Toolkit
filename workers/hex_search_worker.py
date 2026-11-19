"""Background search worker for Hex Viewer."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from core.services.binary_reader import BinaryReader
from core.services.hex_service import parse_hex_pattern

logger = logging.getLogger(__name__)


class HexSearchWorker(QObject):
    """Worker object searching byte patterns across binary files off the GUI thread."""

    matches_found = Signal(list)  # list of match integer offsets
    search_finished = Signal(int)  # total count found
    error = Signal(str)

    def __init__(
        self,
        file_path: str | Path,
        query: str,
        search_mode: str = "hex",  # "hex" or "text"
        start_offset: int = 0,
        case_sensitive: bool = True,
        max_results: int = 500,
    ) -> None:
        super().__init__()
        self._file_path = Path(file_path)
        self._query = query
        self._search_mode = search_mode
        self._start_offset = start_offset
        self._case_sensitive = case_sensitive
        self._max_results = max_results
        self._is_cancelled = False

    def cancel(self) -> None:
        self._is_cancelled = True

    def run(self) -> None:
        try:
            with BinaryReader(self._file_path) as reader:
                if self._search_mode == "hex":
                    pattern = parse_hex_pattern(self._query)
                    matches = reader.search_bytes(
                        pattern,
                        start_offset=self._start_offset,
                        max_results=self._max_results,
                        is_cancelled=lambda: self._is_cancelled,
                    )
                else:
                    matches = reader.search_text(
                        self._query,
                        encoding="utf-8",
                        start_offset=self._start_offset,
                        case_sensitive=self._case_sensitive,
                        max_results=self._max_results,
                        is_cancelled=lambda: self._is_cancelled,
                    )

            if not self._is_cancelled:
                self.matches_found.emit(matches)
                self.search_finished.emit(len(matches))

        except Exception as exc:
            logger.error("Hex search failed for '%s': %s", self._file_path, exc, exc_info=True)
            self.error.emit(str(exc))
