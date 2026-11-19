"""Unit tests for cryptographic hashing service against standard test vectors."""

from pathlib import Path
from core.services.hashing_service import calculate_hashes


def test_hashes_empty_file(tmp_path: Path):
    """Verify hashes for empty file match known NIST test vectors."""
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    res = calculate_hashes(empty_file)
    assert res.md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert res.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert res.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hashes_known_test_vector(tmp_path: Path):
    """Verify hashes for standard 'The quick brown fox jumps over the lazy dog' vector."""
    msg_file = tmp_path / "fox.txt"
    msg_file.write_bytes(b"The quick brown fox jumps over the lazy dog")

    res = calculate_hashes(msg_file)
    assert res.md5 == "9e107d9d372bb6826bd81d3542a419d6"
    assert res.sha1 == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    assert res.sha256 == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"


def test_hashes_chunked_streaming(tmp_path: Path):
    """Verify hashing handles files in chunks with progress callback."""
    large_file = tmp_path / "chunked.bin"
    # Write 256 KB of deterministic data
    chunk = b"A" * 1024
    large_file.write_bytes(chunk * 256)

    progress_calls = []

    def on_progress(done: int, total: int):
        progress_calls.append((done, total))

    res = calculate_hashes(large_file, chunk_size=32 * 1024, progress_callback=on_progress)
    assert len(progress_calls) >= 8
    assert progress_calls[-1][0] == 256 * 1024
    assert res.sha256 is not None
    assert len(res.sha256) == 64


def test_hashes_cancellation(tmp_path: Path):
    """Verify cancellation flag stops hash computation early."""
    sample_file = tmp_path / "cancelled.bin"
    sample_file.write_bytes(b"B" * (64 * 1024))

    cancelled = True
    res = calculate_hashes(sample_file, is_cancelled=lambda: cancelled)
    assert res is not None
