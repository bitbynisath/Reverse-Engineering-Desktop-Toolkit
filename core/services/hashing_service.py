"""Cryptographic hashing service using chunked memory-bounded streaming."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from pathlib import Path

from app.constants import DEFAULT_CHUNK_SIZE_BYTES
from core.exceptions import FileAccessError
from core.models.file_models import HashResults


def calculate_hashes(
    path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
    progress_callback: Callable[[int, int], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> HashResults:
    """Calculate MD5, SHA-1, SHA-256, and SHA-512 hashes in a single streaming pass.

    Args:
        path: Path to the file.
        chunk_size: Size of read chunks in bytes (default 64 KB).
        progress_callback: Optional callable(bytes_processed, total_bytes).
        is_cancelled: Optional callable returning True if processing should abort.

    Returns:
        HashResults containing hex digests and elapsed calculation time.
    """
    try:
        total_size = path.stat().st_size
    except OSError as exc:
        raise FileAccessError(f"Cannot stat file '{path}': {exc}") from exc

    md5_ctx = hashlib.md5()
    sha1_ctx = hashlib.sha1()
    sha256_ctx = hashlib.sha256()
    sha512_ctx = hashlib.sha512()

    start_time = time.perf_counter()
    bytes_processed = 0

    try:
        with path.open("rb") as f:
            while True:
                if is_cancelled and is_cancelled():
                    break

                chunk = f.read(chunk_size)
                if not chunk:
                    break

                md5_ctx.update(chunk)
                sha1_ctx.update(chunk)
                sha256_ctx.update(chunk)
                sha512_ctx.update(chunk)

                bytes_processed += len(chunk)
                if progress_callback:
                    progress_callback(bytes_processed, total_size)

    except OSError as exc:
        raise FileAccessError(f"Error reading file '{path}' during hash calculation: {exc}") from exc

    elapsed = time.perf_counter() - start_time

    return HashResults(
        md5=md5_ctx.hexdigest(),
        sha1=sha1_ctx.hexdigest(),
        sha256=sha256_ctx.hexdigest(),
        sha512=sha512_ctx.hexdigest(),
        elapsed_seconds=round(elapsed, 4),
    )
