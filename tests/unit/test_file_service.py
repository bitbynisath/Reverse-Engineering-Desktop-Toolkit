"""Unit tests for file system inspection service."""

from pathlib import Path
import pytest
from core.exceptions import FileAccessError
from core.services.file_service import (
    format_file_size,
    format_hex_and_ascii,
    format_permissions,
    get_file_metadata,
    read_header_bytes,
)


def test_format_file_size():
    """Verify size formatting across units."""
    assert format_file_size(0) == "0 B"
    assert format_file_size(512) == "512 B"
    assert format_file_size(1024) == "1.00 KB"
    assert format_file_size(1536) == "1.50 KB"
    assert format_file_size(1024 * 1024) == "1.00 MB"
    assert format_file_size(1024 * 1024 * 1024) == "1.00 GB"


def test_format_permissions():
    """Verify permissions string formatting."""
    perms = format_permissions(0o100644)
    assert perms.startswith("-")
    assert "r" in perms


def test_format_hex_and_ascii():
    """Verify hex and ascii preview formatting."""
    data = b"Hello\x00\x01\x02World!"
    hex_str, ascii_str = format_hex_and_ascii(data)
    assert hex_str.startswith("48 65 6C 6C 6F")
    assert ascii_str == "Hello...World!"

    empty_hex, empty_ascii = format_hex_and_ascii(b"")
    assert empty_hex == "<empty>"
    assert empty_ascii == "<empty>"


def test_read_header_bytes(tmp_path: Path):
    """Verify reading header bytes from disk."""
    sample = tmp_path / "header_sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 28)

    header = read_header_bytes(sample, length=4)
    assert header == b"\x7fELF"

    with pytest.raises(FileAccessError):
        read_header_bytes(tmp_path / "nonexistent.bin")


def test_get_file_metadata(tmp_path: Path):
    """Verify extraction of file metadata dataclass."""
    sample = tmp_path / "test_doc.pdf"
    sample.write_bytes(b"%PDF-1.4" + b" " * 100)

    meta = get_file_metadata(sample)
    assert meta.file_name == "test_doc.pdf"
    assert meta.extension == ".pdf"
    assert meta.size_bytes == 108
    assert meta.is_readable is True
    assert meta.is_empty is False
    assert meta.human_size == "108 B"
