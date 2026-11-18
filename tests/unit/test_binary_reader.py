"""Unit tests for memory-bounded BinaryReader."""

from pathlib import Path
import pytest
from core.exceptions import FileAccessError, ValidationError
from core.services.binary_reader import BinaryReader


def test_binary_reader_bounded_reads(tmp_path: Path):
    """Verify read_bytes accurately reads slices within bounds and clamps at EOF."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ABCDEFGHIJ0123456789")  # 20 bytes

    with BinaryReader(sample) as reader:
        assert reader.file_size == 20

        # Read first 5 bytes
        assert reader.read_bytes(0, 5) == b"ABCDE"

        # Read middle 5 bytes
        assert reader.read_bytes(5, 5) == b"FGHIJ"

        # Read past EOF (should clamp)
        assert reader.read_bytes(15, 10) == b"56789"

        # Read at or beyond EOF
        assert reader.read_bytes(20, 5) == b""
        assert reader.read_bytes(25, 5) == b""

        # Negative offset raises ValidationError
        with pytest.raises(ValidationError):
            reader.read_bytes(-1, 5)


def test_binary_reader_empty_file(tmp_path: Path):
    """Verify BinaryReader safely handles 0-byte files."""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    with BinaryReader(empty) as reader:
        assert reader.file_size == 0
        assert reader.read_bytes(0, 10) == b""
        assert reader.search_bytes(b"A") == []


def test_binary_reader_search_bytes(tmp_path: Path):
    """Verify searching byte sequences across binary file."""
    sample = tmp_path / "search_sample.bin"
    data = b"\x00" * 100 + b"\xDE\xAD\xBE\xEF" + b"\x00" * 50 + b"\xDE\xAD\xBE\xEF" + b"\x00" * 10
    sample.write_bytes(data)

    with BinaryReader(sample) as reader:
        matches = reader.search_bytes(b"\xDE\xAD\xBE\xEF")
        assert len(matches) == 2
        assert matches[0] == 100
        assert matches[1] == 154

        # Search with start_offset past first match
        matches_after = reader.search_bytes(b"\xDE\xAD\xBE\xEF", start_offset=101)
        assert len(matches_after) == 1
        assert matches_after[0] == 154

        # Search nonexistent pattern
        assert reader.search_bytes(b"\xCA\xFE") == []


def test_binary_reader_search_text(tmp_path: Path):
    """Verify searching text strings in case-sensitive and case-insensitive modes."""
    sample = tmp_path / "text_sample.bin"
    sample.write_bytes(b"Padding... PyRE Studio is awesome! ...pyre studio... End")

    with BinaryReader(sample) as reader:
        # Case sensitive
        cs_matches = reader.search_text("PyRE Studio", case_sensitive=True)
        assert len(cs_matches) == 1
        assert cs_matches[0] == 11

        # Case insensitive
        ci_matches = reader.search_text("pyre studio", case_sensitive=False)
        assert len(ci_matches) >= 2
