"""Unit tests for Windows PE analysis engine."""

from pathlib import Path
import pytest
from analyzers.pe_analyzer import calculate_entropy, parse_pe
from core.exceptions import UnsupportedFormatError
from tests.fixtures.pe_fixture import create_minimal_pe


def test_calculate_entropy():
    """Verify Shannon entropy calculation."""
    # All identical bytes -> entropy 0.0
    assert calculate_entropy(b"\x90" * 100) == 0.0

    # Empty bytes -> entropy 0.0
    assert calculate_entropy(b"") == 0.0

    # Uniformly distributed 256 bytes -> entropy ~ 8.0
    all_bytes = bytes(range(256)) * 4
    assert calculate_entropy(all_bytes) == 8.0


def test_parse_pe_64bit_fixture(tmp_path: Path):
    """Verify deep parsing of a 64-bit PE executable fixture."""
    pe_file = create_minimal_pe(tmp_path / "test64.exe", is_64bit=True)

    result = parse_pe(pe_file)
    hdr = result.header

    assert hdr.is_pe64 is True
    assert "PE32+" in hdr.format_type
    assert "AMD64" in hdr.machine or "8664" in hdr.machine_hex
    assert hdr.number_of_sections == 2
    assert hdr.entry_point_hex == "0x00001000"
    assert hdr.image_base_hex.endswith("140000000")
    assert "WINDOWS_GUI" in hdr.subsystem
    assert "DYNAMIC_BASE" in hdr.dll_characteristics
    assert "NX_COMPAT" in hdr.dll_characteristics

    # Sections
    assert len(result.sections) == 2
    sec_names = [s.name for s in result.sections]
    assert ".text" in sec_names
    assert ".data" in sec_names

    text_sec = next(s for s in result.sections if s.name == ".text")
    assert text_sec.permissions == "R-X"
    assert text_sec.virtual_address_hex == "0x00001000"

    data_sec = next(s for s in result.sections if s.name == ".data")
    assert data_sec.permissions == "RW-"


def test_parse_pe_32bit_fixture(tmp_path: Path):
    """Verify parsing a 32-bit PE binary fixture."""
    pe_file = create_minimal_pe(tmp_path / "test32.exe", is_64bit=False)

    result = parse_pe(pe_file)
    hdr = result.header

    assert hdr.is_pe64 is False
    assert "PE32" in hdr.format_type
    assert "I386" in hdr.machine or "014C" in hdr.machine_hex
    assert hdr.image_base_hex == "0x00400000"


def test_parse_pe_dll_fixture(tmp_path: Path):
    """Verify detection of DLL characteristic."""
    pe_file = create_minimal_pe(tmp_path / "test.dll", is_dll=True)

    result = parse_pe(pe_file)
    assert result.header.is_dll is True


def test_parse_pe_rwx_warning(tmp_path: Path):
    """Verify warning is issued when RWX section is detected."""
    pe_file = create_minimal_pe(tmp_path / "rwx.exe", rwx_section=True)

    result = parse_pe(pe_file)
    text_sec = next(s for s in result.sections if s.name == ".text")
    assert text_sec.permissions == "RWX"
    assert any("RWX" in w for w in result.warnings)


def test_parse_pe_non_pe_file(tmp_path: Path):
    """Verify attempting to parse non-PE file raises UnsupportedFormatError."""
    fake = tmp_path / "not_a_pe.bin"
    fake.write_bytes(b"This is just plain text content.")

    with pytest.raises(UnsupportedFormatError):
        parse_pe(fake)


def test_parse_pe_truncated_file(tmp_path: Path):
    """Verify truncated PE header raises UnsupportedFormatError."""
    trunc = tmp_path / "trunc.exe"
    trunc.write_bytes(b"MZ\x00\x00")

    with pytest.raises(UnsupportedFormatError):
        parse_pe(trunc)
