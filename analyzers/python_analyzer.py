"""Python Bytecode Analyzer Service.

Provides non-executing, static inspection of compiled Python (.pyc) files and
Python source (.py) code objects, parsing headers, constants, variable names,
co_flags, and generating instructions via dis.
"""

from __future__ import annotations

from datetime import datetime, timezone
import dis
import importlib.util
import logging
import marshal
from pathlib import Path
import types
from typing import Any

from core.exceptions import AnalysisError, FileAccessError, ValidationError
from core.models.python_models import (
    CodeObjectSummary,
    PycHeaderInfo,
    PythonAnalysisResult,
    PythonInstruction,
)
from core.validators import validate_file_path

logger = logging.getLogger(__name__)

# Known magic numbers mapping to Python versions
# Little-endian 2-byte magic int -> Version string
MAGIC_NUMBER_MAP: dict[int, str] = {
    # Python 2.x
    50823: "Python 2.0",
    60202: "Python 2.1",
    60717: "Python 2.2",
    62011: "Python 2.3",
    62061: "Python 2.4",
    62131: "Python 2.5",
    62161: "Python 2.6",
    62211: "Python 2.7",
    # Python 3.x
    3000: "Python 3.0",
    3151: "Python 3.1",
    3180: "Python 3.2",
    3230: "Python 3.3",
    3310: "Python 3.4",
    3350: "Python 3.5",
    3351: "Python 3.5.3+",
    3379: "Python 3.6",
    3394: "Python 3.7",
    3413: "Python 3.8",
    3425: "Python 3.9",
    3439: "Python 3.10",
    3495: "Python 3.11",
    3531: "Python 3.12",
    3571: "Python 3.13",
    3627: "Python 3.14",
}

# Standard co_flags bitmasks
CO_FLAGS_MAP: list[tuple[int, str]] = [
    (0x0001, "CO_OPTIMIZED (Uses fast locals)"),
    (0x0002, "CO_NEWLOCALS (Creates new local dictionary)"),
    (0x0004, "CO_VARARGS (Accepts *args)"),
    (0x0008, "CO_VARKEYWORDS (Accepts **kwargs)"),
    (0x0010, "CO_NESTED (Constructed inside another function)"),
    (0x0020, "CO_GENERATOR (Generator function)"),
    (0x0040, "CO_NOFREE (No free or cell variables)"),
    (0x0080, "CO_COROUTINE (Async coroutine)"),
    (0x0100, "CO_ITERABLE_COROUTINE (Iterable coroutine)"),
    (0x0200, "CO_ASYNC_GENERATOR (Async generator)"),
    (0x04000000, "CO_HAS_DOCSTRING (Has docstring)"),
    (0x08000000, "CO_METHOD (Method code object)"),
]


def resolve_python_version(magic_int: int) -> str:
    """Map a 2-byte magic number to a human-readable Python release version."""
    if magic_int in MAGIC_NUMBER_MAP:
        return MAGIC_NUMBER_MAP[magic_int]

    # Approximate ranges for intermediate development versions
    if 3600 <= magic_int <= 3699:
        return f"Python 3.14+ (Magic: {magic_int})"
    if 3540 <= magic_int <= 3599:
        return f"Python 3.13 (Magic: {magic_int})"
    if 3500 <= magic_int <= 3539:
        return f"Python 3.12 (Magic: {magic_int})"
    if 3450 <= magic_int <= 3499:
        return f"Python 3.11 (Magic: {magic_int})"
    if 3430 <= magic_int <= 3449:
        return f"Python 3.10 (Magic: {magic_int})"
    if 3420 <= magic_int <= 3429:
        return f"Python 3.9 (Magic: {magic_int})"
    if 3400 <= magic_int <= 3419:
        return f"Python 3.8 (Magic: {magic_int})"
    if 3390 <= magic_int <= 3399:
        return f"Python 3.7 (Magic: {magic_int})"
    if 3360 <= magic_int <= 3389:
        return f"Python 3.6 (Magic: {magic_int})"

    return f"Unknown Python Version (Magic: {magic_int})"


def decode_co_flags(flags: int) -> list[str]:
    """Decode a co_flags bitmask integer into human-readable flag names."""
    decoded: list[str] = []
    for mask, name in CO_FLAGS_MAP:
        if flags & mask:
            decoded.append(name)
    return decoded


def parse_pyc_header(data: bytes) -> tuple[PycHeaderInfo, int]:
    """Parse the header of a .pyc file and return (PycHeaderInfo, header_size_bytes).

    Raises:
        AnalysisError: If the binary is too short or lacks valid magic bytes.
    """
    if len(data) < 12:
        raise AnalysisError(
            f"File is too short for a Python .pyc header ({len(data)} bytes, minimum 12 required)."
        )

    magic_bytes = data[:4]
    magic_int = int.from_bytes(data[:2], "little")
    magic_hex = magic_bytes.hex()

    current_magic = importlib.util.MAGIC_NUMBER
    is_current_python = magic_bytes == current_magic

    version_name = resolve_python_version(magic_int)

    # In Python 3.7+ (PEP 552), pyc header is 16 bytes:
    # 4 bytes magic, 4 bytes bitfield/flags, 8 bytes (mtime+size OR 64-bit siphash).
    # In Python 3.0-3.6, pyc header was 12 bytes (4 bytes magic, 4 bytes mtime, 4 bytes size).
    header_size = 16
    is_hash_based = False
    hash_mode = "Timestamp-based"
    timestamp_str: str | None = None
    source_size: int | None = None
    siphash_hex: str | None = None

    if len(data) >= 16:
        # Check PEP 552 flags
        flags_field = int.from_bytes(data[4:8], "little")
        if flags_field & 0x01:
            is_hash_based = True
            is_checked = bool(flags_field & 0x02)
            hash_mode = "Hash-based (checked)" if is_checked else "Hash-based (unchecked)"
            siphash_hex = data[8:16].hex()
        else:
            is_hash_based = False
            hash_mode = "Timestamp-based"
            mtime = int.from_bytes(data[8:12], "little")
            source_size = int.from_bytes(data[12:16], "little")
            try:
                if 0 < mtime < 4102444800:  # Valid timestamp between 1970 and 2100
                    timestamp_str = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                else:
                    timestamp_str = f"Raw timestamp: {mtime}"
            except (ValueError, OverflowError, OSError):
                timestamp_str = f"Raw timestamp: {mtime}"
    else:
        # 12-byte header fallback (older Python 3.x)
        header_size = 12
        mtime = int.from_bytes(data[4:8], "little")
        source_size = int.from_bytes(data[8:12], "little")
        try:
            timestamp_str = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            timestamp_str = f"Raw timestamp: {mtime}"

    header_info = PycHeaderInfo(
        magic_bytes_hex=magic_hex,
        magic_int=magic_int,
        python_version_detected=version_name,
        is_current_python=is_current_python,
        header_size=header_size,
        is_hash_based=is_hash_based,
        hash_check_mode=hash_mode,
        timestamp=timestamp_str,
        source_size_bytes=source_size,
        siphash_hex=siphash_hex,
    )

    return header_info, header_size


def extract_instructions(code_obj: types.CodeType) -> list[PythonInstruction]:
    """Disassemble a code object into a strongly-typed list of PythonInstruction objects."""
    instructions: list[PythonInstruction] = []

    try:
        for ins in dis.get_instructions(code_obj):
            jump_target: int | None = None
            if ins.is_jump_target or "JUMP" in ins.opname:
                # dis provides jump_target or argval for jumps
                if hasattr(ins, "jump_target") and ins.jump_target is not None:
                    jump_target = ins.jump_target
                elif isinstance(ins.argval, int):
                    jump_target = ins.argval

            instructions.append(
                PythonInstruction(
                    offset=ins.offset,
                    opname=ins.opname,
                    opcode=ins.opcode,
                    arg=ins.arg,
                    argval=str(ins.argval) if ins.argval is not None else "",
                    argrepr=ins.argrepr,
                    starts_line=ins.starts_line,
                    is_jump_target=ins.is_jump_target,
                    jump_target=jump_target,
                )
            )
    except Exception as exc:
        logger.warning("Error generating instructions for %s: %s", code_obj.co_name, exc)

    return instructions


def inspect_code_object_recursive(
    co: types.CodeType,
    qualified_name: str = "<module>",
    counter: list[int] | None = None,
) -> list[CodeObjectSummary]:
    """Recursively traverse a code object and all its nested code objects in co_consts."""
    if counter is None:
        counter = [0]

    obj_id = f"co_{counter[0]}"
    counter[0] += 1

    # Format constants
    consts_list: list[dict[str, Any]] = []
    for idx, const_val in enumerate(co.co_consts):
        is_code = isinstance(const_val, types.CodeType)
        type_name = type(const_val).__name__
        val_repr = repr(const_val)
        if len(val_repr) > 100:
            val_repr = val_repr[:97] + "..."
        consts_list.append(
            {
                "index": idx,
                "type": type_name,
                "repr": val_repr,
                "is_code": is_code,
            }
        )

    # Disassemble instructions
    ins_list = extract_instructions(co)

    summary = CodeObjectSummary(
        id=obj_id,
        name=co.co_name,
        qualified_name=qualified_name,
        filename=co.co_filename,
        firstlineno=co.co_firstlineno,
        argcount=co.co_argcount,
        posonlyargcount=getattr(co, "co_posonlyargcount", 0),
        kwonlyargcount=co.co_kwonlyargcount,
        nlocals=co.co_nlocals,
        stacksize=co.co_stacksize,
        flags_int=co.co_flags,
        flags_names=decode_co_flags(co.co_flags),
        consts=consts_list,
        names=list(co.co_names),
        varnames=list(co.co_varnames),
        freevars=list(co.co_freevars),
        cellvars=list(co.co_cellvars),
        instructions=ins_list,
        instruction_count=len(ins_list),
    )

    all_summaries: list[CodeObjectSummary] = [summary]

    # Recurse into nested code objects
    for const_val in co.co_consts:
        if isinstance(const_val, types.CodeType):
            inner_name = f"{qualified_name} -> {const_val.co_name}"
            nested = inspect_code_object_recursive(const_val, inner_name, counter)
            all_summaries.extend(nested)

    return all_summaries


def parse_pyc(file_path: str | Path) -> PythonAnalysisResult:
    """Parse a compiled Python (.pyc) file and extract headers and code objects."""
    path = validate_file_path(file_path)

    try:
        data = path.read_bytes()
    except (OSError, PermissionError) as exc:
        raise FileAccessError(f"Cannot read .pyc file: {exc}") from exc

    file_size = len(data)
    warnings: list[str] = []
    errors: list[str] = []

    try:
        header_info, header_size = parse_pyc_header(data)
    except AnalysisError as exc:
        return PythonAnalysisResult(
            file_path=str(path),
            file_name=path.name,
            file_type="pyc",
            file_size=file_size,
            header=None,
            is_compatible=False,
            errors=[str(exc)],
        )

    # Check magic compatibility
    if not header_info.is_current_python:
        warnings.append(
            f"Bytecode version ({header_info.python_version_detected}) differs from current interpreter "
            f"({resolve_python_version(int.from_bytes(importlib.util.MAGIC_NUMBER[:2], 'little'))}). "
            "Safe unmarshalling will be attempted, but disassembly differences may occur."
        )

    code_objects: list[CodeObjectSummary] = []
    is_compatible = True

    try:
        # Safe deserialization via marshal (non-executing)
        code_bytes = data[header_size:]
        code_obj = marshal.loads(code_bytes)

        if not isinstance(code_obj, types.CodeType):
            warnings.append(f"Unmarshalled root object is {type(code_obj).__name__}, expected CodeType.")
        else:
            code_objects = inspect_code_object_recursive(code_obj, qualified_name=f"<{path.stem}>")

    except Exception as exc:
        is_compatible = False
        error_msg = (
            f"Failed to unmarshal bytecode: {exc}. The file may be compiled for an incompatible "
            f"Python release or corrupted."
        )
        logger.warning(error_msg)
        errors.append(error_msg)

    return PythonAnalysisResult(
        file_path=str(path),
        file_name=path.name,
        file_type="pyc",
        file_size=file_size,
        header=header_info,
        code_objects=code_objects,
        is_compatible=is_compatible,
        warnings=warnings,
        errors=errors,
    )


def parse_python_source(file_path: str | Path) -> PythonAnalysisResult:
    """Compile Python source code (.py) statically without executing it, then analyze."""
    path = validate_file_path(file_path)

    try:
        source_code = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        raise FileAccessError(f"Cannot read Python source file: {exc}") from exc

    file_size = path.stat().st_size
    warnings: list[str] = []
    errors: list[str] = []
    code_objects: list[CodeObjectSummary] = []

    try:
        # Static compilation to code object (no execution)
        code_obj = compile(source_code, str(path), "exec")
        code_objects = inspect_code_object_recursive(code_obj, qualified_name=f"<{path.stem}>")
    except SyntaxError as exc:
        errors.append(f"Syntax error compiling source file: {exc}")
    except Exception as exc:
        errors.append(f"Failed to compile Python source: {exc}")

    return PythonAnalysisResult(
        file_path=str(path),
        file_name=path.name,
        file_type="py_source",
        file_size=file_size,
        header=None,
        code_objects=code_objects,
        is_compatible=len(errors) == 0,
        warnings=warnings,
        errors=errors,
    )


def analyze_python_file(file_path: str | Path) -> PythonAnalysisResult:
    """Unified entry point analyzing a .pyc or .py file statically."""
    path = validate_file_path(file_path)

    # Check extension or file signature
    if path.suffix.lower() == ".pyc":
        return parse_pyc(path)
    elif path.suffix.lower() == ".py":
        return parse_python_source(path)

    # Inspect first 4 bytes for pyc magic
    try:
        prefix = path.open("rb").read(4)
        if len(prefix) >= 4 and prefix[2:4] == b"\r\n":
            return parse_pyc(path)
    except Exception:
        pass

    # Fall back to source code parser
    return parse_python_source(path)


def format_disassembly_listing(
    result: PythonAnalysisResult,
    target_code_id: str | None = None,
) -> str:
    """Generate a clean plain text disassembly report for export."""
    lines: list[str] = []
    lines.append("=" * 80)
    lines.append(f"PyRE Studio Python Bytecode Disassembly: {result.file_name}")
    lines.append(f"File Type: {result.file_type.upper()}")
    lines.append(f"File Size: {result.file_size} bytes")

    if result.header:
        h = result.header
        lines.append(f"Magic: 0x{h.magic_bytes_hex} ({h.python_version_detected})")
        lines.append(f"Validation: {h.hash_check_mode}")
        if h.timestamp:
            lines.append(f"Source Timestamp: {h.timestamp}")
        if h.source_size_bytes is not None:
            lines.append(f"Source Size: {h.source_size_bytes} bytes")
        if h.siphash_hex:
            lines.append(f"Source SipHash: 0x{h.siphash_hex}")

    lines.append("=" * 80)
    lines.append("")

    targets = result.code_objects
    if target_code_id:
        targets = [co for co in result.code_objects if co.id == target_code_id]

    for co in targets:
        lines.append("-" * 80)
        lines.append(f"Code Object: {co.qualified_name} (Line {co.firstlineno})")
        lines.append(
            f"Args: {co.argcount} (PosOnly: {co.posonlyargcount}, KwOnly: {co.kwonlyargcount}) | "
            f"Locals: {co.nlocals} | Stack: {co.stacksize}"
        )
        if co.flags_names:
            lines.append(f"Flags: {', '.join(co.flags_names)}")
        if co.names:
            lines.append(f"Names: {', '.join(co.names)}")
        if co.varnames:
            lines.append(f"Varnames: {', '.join(co.varnames)}")
        lines.append("-" * 80)
        lines.append(f"{'Line':>5}  {'Offset':>7}  {'Opcode':<28} {'Arg':>6}  {'Details'}")
        lines.append("-" * 80)

        for ins in co.instructions:
            line_str = str(ins.starts_line) if ins.starts_line is not None else ""
            arg_str = str(ins.arg) if ins.arg is not None else ""
            details = ins.argrepr if ins.argrepr else ins.argval
            jump_tag = ">> " if ins.is_jump_target else "   "
            lines.append(
                f"{line_str:>5}  {jump_tag}{ins.offset:>5}  {ins.opname:<28} {arg_str:>6}  {details}"
            )
        lines.append("")

    return "\n".join(lines)
