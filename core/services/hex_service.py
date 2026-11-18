"""Formatting, paging, and byte inspection service for Hex Viewer."""

from __future__ import annotations

import re
import struct

from core.exceptions import ValidationError
from core.models.hex_models import ByteSelection, HexRow
from core.services.binary_reader import BinaryReader


def parse_hex_pattern(hex_str: str) -> bytes:
    """Parse a user-entered hexadecimal search pattern into raw bytes.

    Supports inputs such as:
      - "4D 5A 90 00"
      - "4D5A9000"
      - "0x4D 0x5A"
      - "\\x4d\\x5a"
    """
    cleaned = hex_str.strip()
    if not cleaned:
        raise ValidationError("Hexadecimal search pattern cannot be empty.")

    # Remove prefixes like 0x, \x, spaces, commas, colons
    cleaned = cleaned.replace("0x", "").replace("0X", "")
    cleaned = cleaned.replace("\\x", "").replace("\\X", "")
    cleaned = re.sub(r"[\s,:\-_]+", "", cleaned)

    if not cleaned:
        raise ValidationError("No valid hexadecimal digits found in pattern.")

    if len(cleaned) % 2 != 0:
        raise ValidationError(
            f"Hexadecimal sequence must contain an even number of characters (got {len(cleaned)} chars: '{cleaned}')."
        )

    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValidationError(f"Invalid hexadecimal digits in pattern '{cleaned}': {exc}") from exc


def format_hex_row(
    offset: int,
    data: bytes,
    bytes_per_row: int = 16,
    offset_width: int = 8,
) -> HexRow:
    """Format a contiguous slice of bytes into a structured HexRow."""
    offset_hex = f"{offset:0{offset_width}X}"

    # Hex byte tokens with space padding for partial rows
    hex_tokens = [f"{b:02X}" for b in data]
    # Extra spacing halfway through for readability (e.g. 8 bytes group)
    if bytes_per_row >= 16:
        midpoint = bytes_per_row // 2
        if len(hex_tokens) > midpoint:
            hex_tokens.insert(midpoint, " ")

    hex_representation = " ".join(hex_tokens)

    # ASCII representation
    ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in data]
    ascii_representation = "".join(ascii_chars)

    is_partial = len(data) < bytes_per_row

    return HexRow(
        offset=offset,
        offset_hex=offset_hex,
        data=data,
        hex_representation=hex_representation,
        ascii_representation=ascii_representation,
        is_partial=is_partial,
    )


def calculate_total_pages(
    file_size: int,
    rows_per_page: int = 32,
    bytes_per_row: int = 16,
) -> int:
    """Calculate the total number of pages needed to display the file."""
    if file_size <= 0:
        return 1
    bytes_per_page = rows_per_page * bytes_per_row
    return (file_size + bytes_per_page - 1) // bytes_per_page


def offset_to_page(
    offset: int,
    rows_per_page: int = 32,
    bytes_per_row: int = 16,
) -> int:
    """Convert a target byte offset into its corresponding zero-indexed page number."""
    if offset <= 0:
        return 0
    bytes_per_page = rows_per_page * bytes_per_row
    return offset // bytes_per_page


def get_hex_page(
    reader: BinaryReader,
    page_index: int,
    rows_per_page: int = 32,
    bytes_per_row: int = 16,
) -> list[HexRow]:
    """Read and format a single page of HexRow entries without loading entire file."""
    bytes_per_page = rows_per_page * bytes_per_row
    start_offset = page_index * bytes_per_page

    if reader.file_size == 0 or start_offset >= reader.file_size:
        return []

    # Read exactly one page worth of bytes
    page_bytes = reader.read_bytes(start_offset, bytes_per_page)
    rows: list[HexRow] = []

    for i in range(0, len(page_bytes), bytes_per_row):
        row_slice = page_bytes[i : i + bytes_per_row]
        row_offset = start_offset + i
        row = format_hex_row(
            offset=row_offset,
            data=row_slice,
            bytes_per_row=bytes_per_row,
        )
        rows.append(row)

    return rows


def inspect_byte(reader: BinaryReader, offset: int) -> ByteSelection:
    """Extract detailed numeric and textual breakdown of a byte at the given offset."""
    if offset < 0 or offset >= reader.file_size:
        raise ValidationError(f"Offset {offset} is out of bounds (file size: {reader.file_size}).")

    raw_bytes = reader.read_bytes(offset, 4)
    byte_val = raw_bytes[0]

    # Signed int8
    signed_int8 = struct.unpack("b", raw_bytes[:1])[0]

    # Optional uint16_le and uint32_le
    uint16_le = None
    if len(raw_bytes) >= 2:
        uint16_le = struct.unpack("<H", raw_bytes[:2])[0]

    uint32_le = None
    if len(raw_bytes) >= 4:
        uint32_le = struct.unpack("<I", raw_bytes[:4])[0]

    char_repr = chr(byte_val) if 32 <= byte_val <= 126 else "."

    return ByteSelection(
        offset=offset,
        offset_hex=f"0x{offset:08X}",
        byte_value=byte_val,
        byte_hex=f"0x{byte_val:02X}",
        byte_bin=f"{byte_val:08b}",
        byte_char=char_repr,
        signed_int8=signed_int8,
        uint16_le=uint16_le,
        uint32_le=uint32_le,
    )
