"""Background QThread worker for Capstone disassembly operations."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from analyzers.disasm_analyzer import (
    MAX_INSTRUCTIONS,
    disassemble_bytes,
    disassemble_pe_section,
    list_disassemblable_sections,
)
from core.exceptions import AnalysisError, ConfigurationError, UnsupportedFormatError
from core.models.disasm_models import DisassemblyResult

logger = logging.getLogger(__name__)


class DisasmWorker(QObject):
    """QObject worker that runs Capstone disassembly on a background thread.

    Signals:
        progress(int):                    Percentage complete (0-100).
        finished(DisassemblyResult):      Emitted on successful completion.
        error(str):                       Human-readable error message on failure.
        status_message(str):              Descriptive status update for the status bar.
        sections_available(list[str]):    Emitted before disassembly when section names are known.
    """

    progress = Signal(int)
    finished = Signal(object)
    error = Signal(str)
    status_message = Signal(str)
    sections_available = Signal(list)

    def __init__(
        self,
        file_path: Path,
        mode: str = "auto",
        section_name: str = ".text",
        raw_mode: bool = False,
        pe_result=None,
        raw_offset: int = 0,
        raw_length: int | None = None,
        max_instructions: int = MAX_INSTRUCTIONS,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._file_path = file_path
        self._mode = mode
        self._section_name = section_name
        self._raw_mode = raw_mode
        self._pe_result = pe_result
        self._raw_offset = raw_offset
        self._raw_length = raw_length
        self._max_instructions = max_instructions
        self._cancelled = False

    def cancel(self) -> None:
        """Request cancellation before the next result emission."""
        self._cancelled = True

    def run(self) -> None:
        """Entry point called by QThread.started signal."""
        try:
            self._do_disassembly()
        except (ConfigurationError, UnsupportedFormatError, AnalysisError) as exc:
            logger.error("Disassembly worker error: %s", exc)
            self.error.emit(str(exc))
        except OSError as exc:
            logger.error("Disassembly I/O error: %s", exc)
            self.error.emit(f"File read error: {exc}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected disassembly error: %s", exc)
            self.error.emit(f"Unexpected error during disassembly: {exc}")

    def _do_disassembly() -> None:
        pass

    def _do_disassembly(self) -> None:
        self.progress.emit(0)
        self.status_message.emit(f"Preparing to disassemble: {self._file_path.name}")

        if self._raw_mode:
            self._run_raw_mode()
        elif self._pe_result is not None:
            self._run_pe_mode()
        else:
            self._run_raw_mode()

    def _run_pe_mode(self) -> None:
        pe = self._pe_result

        section_names = list_disassemblable_sections(pe)
        self.sections_available.emit(section_names)

        section = self._section_name
        if section not in [s.name for s in pe.sections]:
            if section_names:
                section = section_names[0]
                self.status_message.emit(
                    f"Section '{self._section_name}' not found — using '{section}' instead."
                )
            else:
                raise UnsupportedFormatError("No disassemblable sections found in PE binary.")

        self.status_message.emit(
            f"Disassembling '{section}' section of {self._file_path.name}..."
        )
        self.progress.emit(10)

        result = disassemble_pe_section(
            pe_result=pe,
            file_path=self._file_path,
            section_name=section,
            max_instructions=self._max_instructions,
        )

        if self._cancelled:
            return

        self.progress.emit(100)
        self.status_message.emit(
            f"Disassembly complete: {result.instruction_count:,} instructions decoded."
        )
        self.finished.emit(result)

    def _run_raw_mode(self) -> None:
        self.status_message.emit(f"Reading raw bytes from {self._file_path.name}...")
        self.progress.emit(5)

        try:
            with self._file_path.open("rb") as fh:
                fh.seek(self._raw_offset)
                if self._raw_length is not None:
                    data = fh.read(self._raw_length)
                else:
                    data = fh.read(16 * 1024 * 1024)
        except OSError as exc:
            raise AnalysisError(f"Cannot read {self._file_path.name}: {exc}") from exc

        if self._cancelled:
            return

        mode = self._mode if self._mode != "auto" else "64-bit"
        self.status_message.emit(f"Disassembling {len(data):,} bytes ({mode})...")
        self.progress.emit(20)

        result = disassemble_bytes(
            data=data,
            base_address=self._raw_offset,
            file_offset=self._raw_offset,
            mode=mode,
            section_name="raw",
            entry_point_rva=None,
            max_instructions=self._max_instructions,
        )

        if self._cancelled:
            return

        self.progress.emit(100)
        self.status_message.emit(
            f"Disassembly complete: {result.instruction_count:,} instructions decoded."
        )
        self.finished.emit(result)
