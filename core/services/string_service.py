"""High-performance string extraction, filtering, and export service."""

from __future__ import annotations

import csv
import logging
import re
from collections.abc import Callable
from pathlib import Path

from core.exceptions import FileAccessError, ValidationError
from core.models.string_models import ExtractedString
from core.validators import validate_file_path

logger = logging.getLogger(__name__)


def extract_strings(
    file_path: str | Path,
    min_length: int = 4,
    extract_ascii: bool = True,
    extract_utf16: bool = True,
    extract_utf8: bool = False,
    chunk_size: int = 512 * 1024,
    max_strings: int = 100_000,
    progress_callback: Callable[[int, int], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> list[ExtractedString]:
    """Extract printable strings from a binary file with byte offsets and encoding.

    Memory-bounded: reads file in chunks with safe boundary overlap.
    """
    path = validate_file_path(file_path)

    if min_length < 3:
        raise ValidationError(f"Minimum string length must be at least 3 (got {min_length}).")

    try:
        file_size = path.stat().st_size
    except OSError as exc:
        raise FileAccessError(f"Cannot stat file '{path}': {exc}") from exc

    if file_size == 0:
        return []

    # Compile regex patterns based on min_length
    ascii_re = (
        re.compile(rb"[\x20-\x7e\t]{" + str(min_length).encode() + rb",}")
        if extract_ascii
        else None
    )

    utf16_re = (
        re.compile(rb"(?:[\x20-\x7e\t]\x00){" + str(min_length).encode() + rb",}")
        if extract_utf16
        else None
    )

    # Overlap to avoid cutting strings straddling chunk boundaries
    overlap = max(64, min_length * 4)

    results: list[ExtractedString] = []
    seen: set[tuple[int, str]] = set()

    bytes_processed = 0
    carry_over = b""
    carry_offset = 0

    try:
        with path.open("rb") as f:
            while bytes_processed < file_size:
                if is_cancelled and is_cancelled():
                    logger.info("String extraction cancelled by user.")
                    break

                chunk = f.read(chunk_size)
                if not chunk:
                    break

                block = carry_over + chunk
                block_base_offset = carry_offset

                # 1. Extract ASCII
                if ascii_re:
                    for match in ascii_re.finditer(block):
                        rel_offset = match.start()
                        abs_offset = block_base_offset + rel_offset

                        key = (abs_offset, "ASCII")
                        if key not in seen:
                            val_bytes = match.group()
                            try:
                                text_val = val_bytes.decode("ascii")
                                seen.add(key)
                                results.append(
                                    ExtractedString(
                                        offset=abs_offset,
                                        offset_hex=f"0x{abs_offset:08X}",
                                        value=text_val,
                                        encoding="ASCII",
                                        length=len(text_val),
                                    )
                                )
                                if len(results) >= max_strings:
                                    break
                            except UnicodeDecodeError:
                                pass

                # 2. Extract UTF-16LE
                if utf16_re and len(results) < max_strings:
                    for match in utf16_re.finditer(block):
                        rel_offset = match.start()
                        abs_offset = block_base_offset + rel_offset

                        key = (abs_offset, "UTF-16LE")
                        if key not in seen:
                            val_bytes = match.group()
                            try:
                                text_val = val_bytes.decode("utf-16le")
                                seen.add(key)
                                results.append(
                                    ExtractedString(
                                        offset=abs_offset,
                                        offset_hex=f"0x{abs_offset:08X}",
                                        value=text_val,
                                        encoding="UTF-16LE",
                                        length=len(text_val),
                                    )
                                )
                                if len(results) >= max_strings:
                                    break
                            except UnicodeDecodeError:
                                pass

                # 3. Extract UTF-8 multibyte strings
                if extract_utf8 and len(results) < max_strings:
                    # Look for UTF-8 sequences containing non-ASCII printable chars
                    utf8_candidates = re.finditer(rb"[\x20-\x7e\t\xc2-\xf4][\x80-\xbf\x20-\x7e\t]{" + str(min_length).encode() + rb",}", block)
                    for match in utf8_candidates:
                        val_bytes = match.group()
                        # Only consider if contains high-order UTF-8 bytes
                        if any(b >= 0x80 for b in val_bytes):
                            try:
                                text_val = val_bytes.decode("utf-8")
                                rel_offset = match.start()
                                abs_offset = block_base_offset + rel_offset
                                key = (abs_offset, "UTF-8")
                                if key not in seen and len(text_val) >= min_length:
                                    seen.add(key)
                                    results.append(
                                        ExtractedString(
                                            offset=abs_offset,
                                            offset_hex=f"0x{abs_offset:08X}",
                                            value=text_val,
                                            encoding="UTF-8",
                                            length=len(text_val),
                                        )
                                    )
                                    if len(results) >= max_strings:
                                        break
                            except UnicodeDecodeError:
                                pass

                bytes_processed += len(chunk)

                if progress_callback:
                    progress_callback(bytes_processed, file_size)

                if len(results) >= max_strings:
                    logger.warning("Reached maximum string extraction limit (%d).", max_strings)
                    break

                # Prepare carry-over
                if len(block) > overlap:
                    carry_over = block[-overlap:]
                    carry_offset = block_base_offset + len(block) - overlap
                else:
                    carry_over = block
                    carry_offset = block_base_offset

    except OSError as exc:
        raise FileAccessError(f"Error reading file '{path}' during string extraction: {exc}") from exc

    # Sort results strictly by file offset
    results.sort(key=lambda s: s.offset)
    return results


def filter_strings(
    strings: list[ExtractedString],
    query: str = "",
    encoding: str = "All",
    min_len: int = 0,
) -> list[ExtractedString]:
    """Filter in-memory extracted strings by query text, encoding, or length."""
    filtered = strings

    if encoding and encoding != "All":
        filtered = [s for s in filtered if s.encoding.upper() == encoding.upper()]

    if min_len > 0:
        filtered = [s for s in filtered if s.length >= min_len]

    if query:
        query_lower = query.lower()
        filtered = [
            s for s in filtered
            if query_lower in s.value.lower() or query_lower in s.offset_hex.lower()
        ]

    return filtered


def export_strings_to_txt(
    strings: list[ExtractedString],
    target_path: Path,
    include_offsets: bool = True,
) -> bool:
    """Export extracted strings to plain text format."""
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with target_path.open("w", encoding="utf-8", errors="replace") as f:
            for s in strings:
                if include_offsets:
                    f.write(f"{s.offset_hex} [{s.encoding}]: {s.value}\n")
                else:
                    f.write(f"{s.value}\n")
        logger.info("Exported %d strings to TXT: %s", len(strings), target_path)
        return True
    except OSError as exc:
        logger.error("Failed to export strings to TXT '%s': %s", target_path, exc)
        return False


def export_strings_to_csv(
    strings: list[ExtractedString],
    target_path: Path,
) -> bool:
    """Export extracted strings to CSV format."""
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with target_path.open("w", encoding="utf-8", newline="", errors="replace") as f:
            writer = csv.writer(f)
            writer.writerow(["Offset", "Offset_Hex", "Encoding", "Length", "Value"])
            for s in strings:
                writer.writerow([s.offset, s.offset_hex, s.encoding, s.length, s.value])
        logger.info("Exported %d strings to CSV: %s", len(strings), target_path)
        return True
    except OSError as exc:
        logger.error("Failed to export strings to CSV '%s': %s", target_path, exc)
        return False
