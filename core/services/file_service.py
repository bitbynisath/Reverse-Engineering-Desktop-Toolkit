"""File system inspection and metadata extraction service."""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path

from core.exceptions import FileAccessError
from core.models.file_models import FileMetadata


def format_file_size(size_bytes: int) -> str:
    """Format byte size into human-readable representation."""
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


def format_permissions(mode: int) -> str:
    """Format file permission bits into human-readable string (e.g., -rwxr-xr-x)."""
    return stat.filemode(mode)


def read_header_bytes(path: Path, length: int = 32) -> bytes:
    """Safely read the first N bytes of a file in binary mode."""
    try:
        with path.open("rb") as f:
            return f.read(length)
    except OSError as exc:
        raise FileAccessError(f"Could not read header bytes from '{path}': {exc}") from exc


def format_hex_and_ascii(data: bytes) -> tuple[str, str]:
    """Format raw bytes into hex string and printable ASCII preview."""
    if not data:
        return "<empty>", "<empty>"

    hex_str = " ".join(f"{b:02X}" for b in data)
    ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in data]
    ascii_str = "".join(ascii_chars)
    return hex_str, ascii_str


def get_file_metadata(path: Path) -> FileMetadata:
    """Extract filesystem metadata and permissions for an existing file."""
    try:
        st = path.stat()
    except OSError as exc:
        raise FileAccessError(f"Failed to access file stat for '{path}': {exc}") from exc

    size_bytes = st.st_size
    is_readable = os.access(path, os.R_OK)

    created_iso = datetime.fromtimestamp(st.st_ctime).isoformat(sep=" ", timespec="seconds")
    modified_iso = datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds")
    accessed_iso = datetime.fromtimestamp(st.st_atime).isoformat(sep=" ", timespec="seconds")

    return FileMetadata(
        file_path=str(path.resolve()),
        file_name=path.name,
        extension=path.suffix.lower(),
        size_bytes=size_bytes,
        human_size=format_file_size(size_bytes),
        created_time=created_iso,
        modified_time=modified_iso,
        accessed_time=accessed_iso,
        permissions=format_permissions(st.st_mode),
        is_readable=is_readable,
        is_empty=(size_bytes == 0),
    )

