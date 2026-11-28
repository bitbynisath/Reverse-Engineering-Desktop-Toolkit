"""Strongly-typed data models for Python bytecode analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PycHeaderInfo:
    """Header metadata extracted from a compiled Python (.pyc) binary."""

    magic_bytes_hex: str
    magic_int: int
    python_version_detected: str
    is_current_python: bool
    header_size: int
    is_hash_based: bool
    hash_check_mode: str
    timestamp: str | None = None
    source_size_bytes: int | None = None
    siphash_hex: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PythonInstruction:
    """Individual disassembled Python bytecode instruction."""

    offset: int
    opname: str
    opcode: int
    arg: int | None
    argval: str
    argrepr: str
    starts_line: int | None
    is_jump_target: bool
    jump_target: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CodeObjectSummary:
    """Detailed structural metadata and bytecode for a Python code object."""

    id: str
    name: str
    qualified_name: str
    filename: str
    firstlineno: int
    argcount: int
    posonlyargcount: int
    kwonlyargcount: int
    nlocals: int
    stacksize: int
    flags_int: int
    flags_names: list[str] = field(default_factory=list)
    consts: list[dict[str, Any]] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    varnames: list[str] = field(default_factory=list)
    freevars: list[str] = field(default_factory=list)
    cellvars: list[str] = field(default_factory=list)
    instructions: list[PythonInstruction] = field(default_factory=list)
    instruction_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "filename": self.filename,
            "firstlineno": self.firstlineno,
            "argcount": self.argcount,
            "posonlyargcount": self.posonlyargcount,
            "kwonlyargcount": self.kwonlyargcount,
            "nlocals": self.nlocals,
            "stacksize": self.stacksize,
            "flags_int": self.flags_int,
            "flags_names": self.flags_names,
            "consts": self.consts,
            "names": self.names,
            "varnames": self.varnames,
            "freevars": self.freevars,
            "cellvars": self.cellvars,
            "instructions": [ins.to_dict() for ins in self.instructions],
            "instruction_count": self.instruction_count,
        }


@dataclass
class PythonAnalysisResult:
    """Complete static analysis outcome of a Python .pyc or .py file."""

    file_path: str
    file_name: str
    file_type: str  # "pyc" or "py_source"
    file_size: int
    header: PycHeaderInfo | None
    code_objects: list[CodeObjectSummary] = field(default_factory=list)
    is_compatible: bool = True
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "header": self.header.to_dict() if self.header else None,
            "code_objects": [co.to_dict() for co in self.code_objects],
            "is_compatible": self.is_compatible,
            "warnings": self.warnings,
            "errors": self.errors,
        }
