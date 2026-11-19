"""Unit tests for string extraction, filtering, and export services."""

import csv
from pathlib import Path
import pytest
from core.exceptions import ValidationError
from core.models.string_models import ExtractedString
from core.services.string_service import (
    export_strings_to_csv,
    export_strings_to_txt,
    extract_strings,
    filter_strings,
)


def test_extract_ascii_strings(tmp_path: Path):
    """Verify ASCII string extraction, offsets, and length."""
    sample = tmp_path / "ascii_sample.bin"
    # Offset 0: "HELLO_WORLD" (11 chars)
    # Offset 11: 4 null bytes
    # Offset 15: "PyRE_STUDIO" (11 chars)
    data = b"HELLO_WORLD\x00\x00\x00\x00PyRE_STUDIO\x00"
    sample.write_bytes(data)

    strings = extract_strings(sample, min_length=4, extract_ascii=True, extract_utf16=False)
    assert len(strings) == 2

    assert strings[0].value == "HELLO_WORLD"
    assert strings[0].offset == 0
    assert strings[0].offset_hex == "0x00000000"
    assert strings[0].encoding == "ASCII"
    assert strings[0].length == 11

    assert strings[1].value == "PyRE_STUDIO"
    assert strings[1].offset == 15
    assert strings[1].offset_hex == "0x0000000F"
    assert strings[1].encoding == "ASCII"
    assert strings[1].length == 11


def test_extract_utf16_strings(tmp_path: Path):
    """Verify UTF-16LE string extraction and offset tracking."""
    sample = tmp_path / "utf16_sample.bin"
    # UTF-16LE: "Windows PE"
    utf16_bytes = "Windows PE".encode("utf-16le")
    data = b"\x00" * 32 + utf16_bytes + b"\x00" * 16
    sample.write_bytes(data)

    strings = extract_strings(sample, min_length=4, extract_ascii=False, extract_utf16=True)
    assert len(strings) == 1

    s = strings[0]
    assert s.value == "Windows PE"
    assert s.offset == 32
    assert s.encoding == "UTF-16LE"
    assert s.length == 10


def test_min_length_enforcement(tmp_path: Path):
    """Verify minimum length filtering drops shorter sequences."""
    sample = tmp_path / "min_len.bin"
    # "abc" (len 3), "abcdef" (len 6)
    sample.write_bytes(b"abc\x00\x00abcdef\x00")

    # Min length 4 drops "abc"
    res4 = extract_strings(sample, min_length=4, extract_ascii=True, extract_utf16=False)
    assert len(res4) == 1
    assert res4[0].value == "abcdef"

    # Min length 3 keeps both
    res3 = extract_strings(sample, min_length=3, extract_ascii=True, extract_utf16=False)
    assert len(res3) == 2

    with pytest.raises(ValidationError):
        extract_strings(sample, min_length=2)


def test_extract_empty_file(tmp_path: Path):
    """Verify empty 0-byte file returns empty list."""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    strings = extract_strings(empty)
    assert strings == []


def test_filter_strings():
    """Verify in-memory filtering by query, encoding, and length."""
    items = [
        ExtractedString(offset=0, offset_hex="0x00000000", value="Kernel32.dll", encoding="ASCII", length=12),
        ExtractedString(offset=20, offset_hex="0x00000014", value="User32.dll", encoding="UTF-16LE", length=10),
        ExtractedString(offset=50, offset_hex="0x00000032", value="http://localhost", encoding="ASCII", length=16),
    ]

    # Filter by query
    res_dll = filter_strings(items, query="dll")
    assert len(res_dll) == 2

    # Filter by encoding
    res_utf16 = filter_strings(items, encoding="UTF-16LE")
    assert len(res_utf16) == 1
    assert res_utf16[0].value == "User32.dll"

    # Filter by min_len
    res_len = filter_strings(items, min_len=15)
    assert len(res_len) == 1
    assert res_len[0].value == "http://localhost"


def test_export_txt_and_csv(tmp_path: Path):
    """Verify exporting strings to TXT and CSV produces valid output."""
    items = [
        ExtractedString(offset=0, offset_hex="0x00000000", value="AppTitle", encoding="ASCII", length=8),
        ExtractedString(offset=16, offset_hex="0x00000010", value="MainModule", encoding="UTF-16LE", length=10),
    ]

    # TXT Export
    txt_file = tmp_path / "strings.txt"
    assert export_strings_to_txt(items, txt_file) is True
    assert txt_file.exists()
    content = txt_file.read_text(encoding="utf-8")
    assert "0x00000000 [ASCII]: AppTitle" in content

    # CSV Export
    csv_file = tmp_path / "strings.csv"
    assert export_strings_to_csv(items, csv_file) is True
    assert csv_file.exists()
    with csv_file.open(encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == ["Offset", "Offset_Hex", "Encoding", "Length", "Value"]
        row1 = next(reader)
        assert row1[4] == "AppTitle"
