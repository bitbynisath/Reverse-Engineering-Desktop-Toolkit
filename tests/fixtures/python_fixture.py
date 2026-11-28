"""Test fixtures generating Python source and compiled bytecode (.pyc) files."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import py_compile
import tempfile

SAMPLE_PYTHON_SOURCE = '''"""Sample module for static bytecode analysis testing."""

GLOBAL_CONFIG = {"debug": True, "timeout": 30}
MAX_RETRIES = 5

def sample_function(x: int, y: int = 10, *args, **kwargs) -> int:
    """A sample function with arguments and local variables."""
    total = x + y
    if total > 50:
        return total * 2
    else:
        return total - 5

class Calculator:
    """Sample class with methods and nested code objects."""

    def __init__(self, base: int = 0) -> None:
        self.base = base

    def compute(self, multiplier: int) -> int:
        factor = 2
        def inner_closure(val: int) -> int:
            return (val + self.base) * factor
        return inner_closure(multiplier)

def generator_example(limit: int):
    """Generator function testing CO_GENERATOR flag."""
    for i in range(limit):
        yield i * i
'''


def create_sample_py_file(tmp_dir: Path, filename: str = "sample_test.py") -> Path:
    """Create a temporary Python source (.py) file."""
    py_path = tmp_dir / filename
    py_path.write_text(SAMPLE_PYTHON_SOURCE, encoding="utf-8")
    return py_path


def create_sample_pyc_file(tmp_dir: Path, filename: str = "sample_test.pyc") -> Path:
    """Create a compiled Python bytecode (.pyc) file."""
    py_path = create_sample_py_file(tmp_dir, "temp_src.py")
    pyc_path = tmp_dir / filename
    py_compile.compile(str(py_path), cfile=str(pyc_path))
    return pyc_path


def create_corrupt_pyc_file(tmp_dir: Path, filename: str = "corrupt.pyc") -> Path:
    """Create a corrupted .pyc file with invalid header and body."""
    path = tmp_dir / filename
    # Valid magic bytes for current Python, but corrupted unmarshal payload
    magic = importlib.util.MAGIC_NUMBER
    corrupt_data = magic + b"\x00" * 12 + b"\xff\xff\x00\x00corrupted_payload"
    path.write_bytes(corrupt_data)
    return path
