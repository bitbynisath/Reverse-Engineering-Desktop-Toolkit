"""Unit tests for unified analysis orchestration and JSON export."""

import json
from pathlib import Path
import pytest
from core.exceptions import FileAccessError
from core.services.analysis_service import analyze_file, export_analysis_to_json


def test_analyze_file_complete_flow(tmp_path: Path):
    """Verify end-to-end static file analysis output."""
    sample = tmp_path / "document.pdf"
    content = b"%PDF-1.4\nTest PDF content for static analysis\n%%EOF"
    sample.write_bytes(content)

    result = analyze_file(sample)
    assert result.metadata.file_name == "document.pdf"
    assert result.metadata.size_bytes == len(content)
    assert result.signature is not None
    assert result.signature.name == "PDF Document"
    assert result.extension_matches_signature is True
    assert result.hashes.md5 is not None
    assert result.hashes.sha256 is not None
    assert "25 50 44 46" in result.magic_preview_hex


def test_analyze_empty_file_warning(tmp_path: Path):
    """Verify analysis of 0-byte file generates notice."""
    empty_file = tmp_path / "zero.bin"
    empty_file.write_bytes(b"")

    result = analyze_file(empty_file)
    assert result.metadata.is_empty is True
    assert any("0 bytes" in w for w in result.warnings)


def test_analyze_file_exceeds_threshold(tmp_path: Path):
    """Verify warning is generated when file exceeds size threshold."""
    large_sample = tmp_path / "large.bin"
    large_sample.write_bytes(b"X" * 1024)

    # Threshold set to 0 MB to trigger warning
    result = analyze_file(large_sample, max_size_mb=0)
    assert any("exceeds the warning threshold" in w for w in result.warnings)


def test_export_analysis_to_json(tmp_path: Path):
    """Verify exporting analysis result to JSON produces valid and readable file."""
    sample = tmp_path / "sample.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    result = analyze_file(sample)
    export_json = tmp_path / "export_report.json"

    success = export_analysis_to_json(result, export_json)
    assert success is True
    assert export_json.exists()

    data = json.loads(export_json.read_text(encoding="utf-8"))
    assert data["metadata"]["file_name"] == "sample.png"
    assert data["signature"]["name"] == "PNG Image"
    assert "sha256" in data["hashes"]
