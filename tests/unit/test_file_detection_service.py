"""Unit tests for binary format detection and extension verification."""

from pathlib import Path
from core.services.file_detection_service import (
    compare_extension_and_signature,
    detect_file_signature,
    detect_pe_format,
)


def test_detect_pe_executable(tmp_path: Path):
    """Verify detection of PE executable with MZ and PE signatures."""
    pe_file = tmp_path / "sample.exe"
    # Construct minimal PE header layout: MZ at 0x00, e_lfanew at 0x3C pointing to 0x80, PE\0\0 at 0x80
    data = bytearray(b"\x00" * 256)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
    data[0x80:0x84] = b"PE\x00\x00"
    pe_file.write_bytes(data)

    sig = detect_file_signature(data[:64], pe_file)
    assert sig is not None
    assert "Windows PE" in sig.name
    assert sig.category == "Executable"

    # Verify match with .exe
    matches, msg = compare_extension_and_signature(".exe", sig)
    assert matches is True

    # Verify mismatch when renamed to .pdf
    matches, msg = compare_extension_and_signature(".pdf", sig)
    assert matches is False
    assert "HIGH RISK MISMATCH" in msg


def test_detect_elf_binary():
    """Verify detection of ELF binary signature."""
    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 24
    sig = detect_file_signature(elf_header)
    assert sig is not None
    assert "ELF" in sig.name
    assert sig.category == "Executable"


def test_detect_pdf_document():
    """Verify detection of PDF document signature."""
    pdf_header = b"%PDF-1.7\r\n"
    sig = detect_file_signature(pdf_header)
    assert sig is not None
    assert "PDF" in sig.name
    assert sig.category == "Document"


def test_detect_png_image():
    """Verify detection of PNG image signature."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    sig = detect_file_signature(png_header)
    assert sig is not None
    assert "PNG" in sig.name
    assert sig.category == "Image"


def test_detect_zip_archive():
    """Verify detection of ZIP archive signature."""
    zip_header = b"PK\x03\x04\x14\x00\x00\x00"
    sig = detect_file_signature(zip_header)
    assert sig is not None
    assert "ZIP" in sig.name
    assert sig.category == "Archive"


def test_detect_python_bytecode():
    """Verify detection of Python bytecode (.pyc)."""
    # 3.12 / 3.13 / 3.14 pyc magic ending in \r\n
    pyc_header = b"\xcb\r\r\n\x00\x00\x00\x00"
    sig = detect_file_signature(pyc_header)
    assert sig is not None
    assert "Python Compiled Bytecode" in sig.name
    assert sig.category == "Bytecode"
