"""Unit tests for input and file path validators."""

from pathlib import Path
import pytest
from core.exceptions import FileAccessError, ValidationError
from core.validators import validate_file_path, validate_file_size


def test_validate_file_path_valid(tmp_path: Path):
    """Verify validation passes for an existing readable file."""
    test_file = tmp_path / "valid.bin"
    test_file.write_bytes(b"\x90\x90\x90")

    result = validate_file_path(test_file)
    assert result == test_file.resolve()


def test_validate_file_path_empty():
    """Verify validation fails on empty input string."""
    with pytest.raises(ValidationError):
        validate_file_path("")


def test_validate_file_path_nonexistent(tmp_path: Path):
    """Verify validation raises FileAccessError for nonexistent path."""
    nonexistent = tmp_path / "does_not_exist.bin"
    with pytest.raises(FileAccessError):
        validate_file_path(nonexistent)


def test_validate_file_path_is_directory(tmp_path: Path):
    """Verify validation fails if path is a directory instead of a regular file."""
    with pytest.raises(ValidationError):
        validate_file_path(tmp_path)


def test_validate_file_size(tmp_path: Path):
    """Verify file size validation and max limit check."""
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"A" * 1024)

    size = validate_file_size(test_file, max_size_mb=1)
    assert size == 1024

    with pytest.raises(ValidationError):
        validate_file_size(test_file, max_size_mb=0)
