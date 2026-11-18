"""Unit tests for hexadecimal formatting, paging, and byte inspection."""

from pathlib import Path
import pytest
from core.exceptions import ValidationError
from core.models.hex_models import ByteSelection, HexRow
from core.services.binary_reader import BinaryReader
from core.services.hex_service import (
    calculate_total_pages,
    format_hex_row,
    get_hex_page,
    inspect_byte,
    offset_to_page,
    parse_hex_pattern,
)


def test_format_hex_row_full():
    """Verify formatting a full 16-byte row with midpoint split."""
    data = b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
    row = format_hex_row(offset=0, data=data, bytes_per_row=16)

    assert row.offset == 0
    assert row.offset_hex == "00000000"
    assert "4D 5A 90 00 03 00 00 00" in row.hex_representation
    assert row.ascii_representation == "MZ.............."
    assert row.is_partial is False


def test_format_hex_row_partial():
    """Verify formatting a partial row (last line of file)."""
    data = b"HELLO"
    row = format_hex_row(offset=32, data=data, bytes_per_row=16)

    assert row.offset == 32
    assert row.offset_hex == "00000020"
    assert row.hex_representation == "48 45 4C 4C 4F"
    assert row.ascii_representation == "HELLO"
    assert row.is_partial is True


def test_calculate_total_pages_and_offset_to_page():
    """Verify total pages math and offset mapping."""
    # 0 bytes -> 1 page
    assert calculate_total_pages(0, rows_per_page=32, bytes_per_row=16) == 1

    # Exactly 1 row (16 bytes)
    assert calculate_total_pages(16, rows_per_page=32, bytes_per_row=16) == 1

    # Exactly 1 page (32 * 16 = 512 bytes)
    assert calculate_total_pages(512, rows_per_page=32, bytes_per_row=16) == 1

    # 1 page + 1 byte (513 bytes) -> 2 pages
    assert calculate_total_pages(513, rows_per_page=32, bytes_per_row=16) == 2

    # Offset to page mapping (bytes_per_page = 512)
    assert offset_to_page(0, rows_per_page=32, bytes_per_row=16) == 0
    assert offset_to_page(511, rows_per_page=32, bytes_per_row=16) == 0
    assert offset_to_page(512, rows_per_page=32, bytes_per_row=16) == 1
    assert offset_to_page(1024, rows_per_page=32, bytes_per_row=16) == 2


def test_get_hex_page(tmp_path: Path):
    """Verify reading page rows from binary file."""
    sample = tmp_path / "page_sample.bin"
    # Write 64 bytes (4 rows of 16 bytes)
    sample.write_bytes(bytes(range(64)))

    with BinaryReader(sample) as reader:
        # Page with 2 rows per page
        page0 = get_hex_page(reader, page_index=0, rows_per_page=2, bytes_per_row=16)
        assert len(page0) == 2
        assert page0[0].offset == 0
        assert page0[1].offset == 16

        page1 = get_hex_page(reader, page_index=1, rows_per_page=2, bytes_per_row=16)
        assert len(page1) == 2
        assert page1[0].offset == 32
        assert page1[1].offset == 48

        # Page out of bounds
        page2 = get_hex_page(reader, page_index=2, rows_per_page=2, bytes_per_row=16)
        assert len(page2) == 0


def test_parse_hex_pattern_valid():
    """Verify parsing various valid hex pattern input syntaxes."""
    assert parse_hex_pattern("4D 5A 90") == b"\x4D\x5A\x90"
    assert parse_hex_pattern("4d5a90") == b"\x4D\x5A\x90"
    assert parse_hex_pattern("0x4D, 0x5A") == b"\x4D\x5A"
    assert parse_hex_pattern("\\x4d\\x5a") == b"\x4D\x5A"


def test_parse_hex_pattern_invalid():
    """Verify invalid hex patterns raise ValidationError."""
    with pytest.raises(ValidationError):
        parse_hex_pattern("")

    # Odd length
    with pytest.raises(ValidationError):
        parse_hex_pattern("4D 5")

    # Non-hex characters
    with pytest.raises(ValidationError):
        parse_hex_pattern("ZZ YY")


def test_inspect_byte(tmp_path: Path):
    """Verify byte inspection breakdowns."""
    sample = tmp_path / "inspect.bin"
    # 0x4D ('M', 77), 0x5A ('Z', 90), 0x01, 0x02
    sample.write_bytes(b"\x4D\x5A\x01\x02")

    with BinaryReader(sample) as reader:
        info = inspect_byte(reader, 0)
        assert info.offset == 0
        assert info.offset_hex == "0x00000000"
        assert info.byte_value == 77
        assert info.byte_hex == "0x4D"
        assert info.byte_bin == "01001101"
        assert info.byte_char == "M"
        assert info.signed_int8 == 77
        # uint16 LE: 0x5A4D = 23117
        assert info.uint16_le == 23117
        # uint32 LE: 0x02015A4D = 33643085
        assert info.uint32_le == 33643085

        with pytest.raises(ValidationError):
            inspect_byte(reader, 999)
