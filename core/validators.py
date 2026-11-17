"""Input validation and file integrity checks for PyRE Studio."""

from __future__ import annotations

import os
from pathlib import Path

from core.exceptions import FileAccessError, ValidationError


def validate_file_path(path_str: str | Path) -> Path:
    """Validate that the provided string points to an existing regular file.

    Raises ValidationError or FileAccessError if invalid or unreadable.
    """
    if not path_str:
        raise ValidationError("File path cannot be empty.")

    try:
        path = Path(path_str).resolve()
    except Exception as exc:
        raise ValidationError(f"Invalid path format '{path_str}': {exc}") from exc

    if not path.exists():
        raise FileAccessError(f"File does not exist: {path}")

    if not path.is_file():
        raise ValidationError(f"Path is not a regular file: {path}")

    if not os.access(path, os.R_OK):
        raise FileAccessError(f"Permission denied: File is not readable: {path}")

    return path


def validate_file_size(path: Path, max_size_mb: int = 100) -> int:
    """Check file size and return size in bytes.

    Raises ValidationError if size exceeds maximum configured threshold.
    """
    try:
        size_bytes = path.stat().st_size
    except OSError as exc:
        raise FileAccessError(f"Could not read size of file '{path}': {exc}") from exc

    max_bytes = max_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        raise ValidationError(
            f"File size ({size_bytes / (1024*1024):.2f} MB) exceeds maximum allowed threshold "
            f"of {max_size_mb} MB."
        )

    return size_bytes
