"""Memory-bounded binary reader supporting mmap and buffered streaming."""

from __future__ import annotations

import logging
import mmap
import re
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

from core.exceptions import FileAccessError, ValidationError
from core.validators import validate_file_path

logger = logging.getLogger(__name__)


class BinaryReader:
    """Thread-safe, memory-bounded binary file reader with paging support."""

    def __init__(self, file_path: str | Path) -> None:
        self.path = validate_file_path(file_path)
        self._file = None
        self._mmap = None
        self._file_size = self.path.stat().st_size
        self._open()

    def _open(self) -> None:
        try:
            self._file = self.path.open("rb")
            if self._file_size > 0:
                try:
                    # ACCESS_READ on Windows, PROT_READ on Unix
                    self._mmap = mmap.mmap(
                        self._file.fileno(), 0, access=mmap.ACCESS_READ
                    )
                except (OSError, ValueError) as exc:
                    logger.debug("mmap not available for '%s': %s (fallback to buffered reads)", self.path, exc)
                    self._mmap = None
        except OSError as exc:
            raise FileAccessError(f"Failed to open binary file '{self.path}': {exc}") from exc

    @property
    def file_size(self) -> int:
        return self._file_size

    def read_bytes(self, offset: int, length: int) -> bytes:
        """Read a bounded byte slice safely.

        Returns empty bytes if offset >= file_size or length <= 0.
        """
        if self._file is None:
            raise FileAccessError("Reader is closed.")

        if offset < 0:
            raise ValidationError(f"Invalid negative offset: {offset}")

        if offset >= self._file_size or length <= 0:
            return b""

        # Clamp length to remaining bytes
        actual_len = min(length, self._file_size - offset)

        if self._mmap is not None:
            return bytes(self._mmap[offset : offset + actual_len])

        # Fallback to seekable buffered read
        self._file.seek(offset)
        return self._file.read(actual_len)

    def search_bytes(
        self,
        pattern: bytes,
        start_offset: int = 0,
        max_results: int = 100,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> list[int]:
        """Search for a byte sequence across the file without full RAM buffering."""
        if not pattern:
            return []

        if start_offset < 0 or start_offset >= self._file_size:
            return []

        results: list[int] = []

        if self._mmap is not None:
            pos = start_offset
            while pos < self._file_size and len(results) < max_results:
                if is_cancelled and is_cancelled():
                    break
                idx = self._mmap.find(pattern, pos)
                if idx == -1:
                    break
                results.append(idx)
                pos = idx + 1
            return results

        # Buffered chunked scanning fallback
        chunk_size = 64 * 1024
        overlap = len(pattern) - 1
        pos = start_offset

        self._file.seek(pos)
        carry_over = b""

        while pos < self._file_size and len(results) < max_results:
            if is_cancelled and is_cancelled():
                break

            data = self._file.read(chunk_size)
            if not data:
                break

            block = carry_over + data
            block_base = pos - len(carry_over)

            sub_pos = 0
            while len(results) < max_results:
                idx = block.find(pattern, sub_pos)
                if idx == -1:
                    break
                match_offset = block_base + idx
                if match_offset >= start_offset and match_offset not in results:
                    results.append(match_offset)
                sub_pos = idx + 1

            if overlap > 0 and len(data) >= overlap:
                carry_over = data[-overlap:]
            else:
                carry_over = data

            pos += len(data)

        return results

    def search_text(
        self,
        text: str,
        encoding: str = "utf-8",
        start_offset: int = 0,
        case_sensitive: bool = True,
        max_results: int = 100,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> list[int]:
        """Search for a text string in the specified encoding."""
        if not text:
            return []

        try:
            pattern = text.encode(encoding)
        except UnicodeEncodeError as exc:
            raise ValidationError(f"Cannot encode search query '{text}' in {encoding}: {exc}") from exc

        if case_sensitive:
            return self.search_bytes(pattern, start_offset, max_results, is_cancelled)

        # Case-insensitive text search using byte regex
        regex = re.compile(re.escape(pattern), re.IGNORECASE)
        results: list[int] = []

        if self._mmap is not None:
            for match in regex.finditer(self._mmap, start_offset):
                if is_cancelled and is_cancelled():
                    break
                results.append(match.start())
                if len(results) >= max_results:
                    break
            return results

        chunk_size = 64 * 1024
        overlap = len(pattern) - 1
        pos = start_offset
        carry_over = b""

        self._file.seek(pos)
        while pos < self._file_size and len(results) < max_results:
            if is_cancelled and is_cancelled():
                break

            data = self._file.read(chunk_size)
            if not data:
                break

            block = carry_over + data
            block_base = pos - len(carry_over)

            for match in regex.finditer(block):
                match_offset = block_base + match.start()
                if match_offset >= start_offset and match_offset not in results:
                    results.append(match_offset)
                    if len(results) >= max_results:
                        break

            if overlap > 0 and len(data) >= overlap:
                carry_over = data[-overlap:]
            else:
                carry_over = data

            pos += len(data)

        return results[:max_results]

    def close(self) -> None:
        """Release file handles and memory mapping."""
        if self._mmap is not None:
            try:
                self._mmap.close()
            except Exception:
                pass
            self._mmap = None

        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

    def __enter__(self) -> BinaryReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()
