"""Unit tests for Python bytecode analyzer."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import pytest

from analyzers.python_analyzer import (
    analyze_python_file,
    decode_co_flags,
    format_disassembly_listing,
    parse_pyc,
    parse_pyc_header,
    parse_python_source,
    resolve_python_version,
)
from core.exceptions import AnalysisError
from tests.fixtures.python_fixture import (
    create_corrupt_pyc_file,
    create_sample_py_file,
    create_sample_pyc_file,
)


def test_resolve_python_version():
    """Verify mapping of known magic numbers to Python versions."""
    assert "3.14" in resolve_python_version(3627)
    assert "3.13" in resolve_python_version(3571)
    assert "3.12" in resolve_python_version(3531)
    assert "3.11" in resolve_python_version(3495)
    assert "2.7" in resolve_python_version(62211)
    assert "Unknown" in resolve_python_version(99999)


def test_decode_co_flags():
    """Verify decoding of code object bitmask flags."""
    # 0x0001 (CO_OPTIMIZED) + 0x0002 (CO_NEWLOCALS) = 3
    flags = decode_co_flags(3)
    assert any("CO_OPTIMIZED" in f for f in flags)
    assert any("CO_NEWLOCALS" in f for f in flags)

    # 0x0020 (CO_GENERATOR) = 32
    gen_flags = decode_co_flags(32)
    assert any("CO_GENERATOR" in f for f in gen_flags)

    # 0 = empty
    assert decode_co_flags(0) == []


def test_parse_pyc_header_valid(tmp_path: Path):
    """Verify header parsing on a freshly compiled .pyc file."""
    pyc_path = create_sample_pyc_file(tmp_path)
    data = pyc_path.read_bytes()

    header_info, header_size = parse_pyc_header(data)
    assert header_size in (12, 16)
    assert header_info.magic_bytes_hex == importlib.util.MAGIC_NUMBER.hex()
    assert header_info.is_current_python is True
    assert header_info.magic_int == int.from_bytes(data[:2], "little")
    assert header_info.hash_check_mode in ("Timestamp-based", "Hash-based (checked)", "Hash-based (unchecked)")


def test_parse_pyc_header_too_short():
    """Verify error on truncated pyc binary."""
    with pytest.raises(AnalysisError, match="too short"):
        parse_pyc_header(b"short_bytes")


def test_parse_pyc_file_full(tmp_path: Path):
    """Verify full static inspection of a .pyc file."""
    pyc_path = create_sample_pyc_file(tmp_path)
    result = parse_pyc(pyc_path)

    assert result.file_type == "pyc"
    assert result.is_compatible is True
    assert result.header is not None
    assert len(result.code_objects) >= 4  # module, sample_function, Calculator, compute, inner_closure, generator

    # Root module code object
    module_co = result.code_objects[0]
    assert module_co.name == "<module>"
    assert len(module_co.instructions) > 0
    assert any(c["is_code"] for c in module_co.consts)

    # Verify nested functions were extracted
    names = [co.name for co in result.code_objects]
    assert "sample_function" in names
    assert "compute" in names
    assert "generator_example" in names

    # Verify to_dict serialisation
    res_dict = result.to_dict()
    assert "code_objects" in res_dict
    assert len(res_dict["code_objects"]) == len(result.code_objects)


def test_parse_python_source(tmp_path: Path):
    """Verify static analysis on a .py source code file."""
    py_path = create_sample_py_file(tmp_path)
    result = parse_python_source(py_path)

    assert result.file_type == "py_source"
    assert result.header is None
    assert result.is_compatible is True
    assert len(result.code_objects) >= 4

    names = [co.name for co in result.code_objects]
    assert "sample_function" in names
    assert "Calculator" in names


def test_analyze_python_file_dispatcher(tmp_path: Path):
    """Verify analyze_python_file automatically routes by extension and magic."""
    py_path = create_sample_py_file(tmp_path)
    pyc_path = create_sample_pyc_file(tmp_path)

    res_src = analyze_python_file(py_path)
    assert res_src.file_type == "py_source"

    res_bin = analyze_python_file(pyc_path)
    assert res_bin.file_type == "pyc"


def test_corrupted_pyc_handling(tmp_path: Path):
    """Verify corrupted .pyc file handles unmarshal errors gracefully without raising."""
    corrupt_path = create_corrupt_pyc_file(tmp_path)
    result = parse_pyc(corrupt_path)

    assert result.is_compatible is False
    assert len(result.errors) > 0
    assert result.header is not None  # Header was valid


def test_format_disassembly_listing(tmp_path: Path):
    """Verify formatted plain-text disassembly report."""
    pyc_path = create_sample_pyc_file(tmp_path)
    result = parse_pyc(pyc_path)

    listing = format_disassembly_listing(result)
    assert "PyRE Studio Python Bytecode Disassembly" in listing
    assert "Code Object:" in listing
    assert "Opcode" in listing
