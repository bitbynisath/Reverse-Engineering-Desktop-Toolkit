"""Capstone-based static disassembly engine for x86 / x86-64 binaries.

Strictly read-only static analysis — target files are NEVER executed.
Supports:
  - Raw byte-stream disassembly (useful for shellcode or arbitrary regions).
  - PE .text section disassembly via an existing PEAnalysisResult.

Architecture selection:
  - x86 32-bit  : CS_ARCH_X86 / CS_MODE_32
  - x86 64-bit  : CS_ARCH_X86 / CS_MODE_64
  - Mode is detected automatically from PE headers when available.

Address mapping:
  - Virtual addresses are computed from base_address + offset_within_section.
  - File offsets are computed from raw_data_offset + offset_within_section.
  - Virtual address != file offset; this module makes the distinction explicit.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from core.exceptions import AnalysisError, ConfigurationError, UnsupportedFormatError
from core.models.disasm_models import DisassembledInstruction, DisassemblyResult

logger = logging.getLogger(__name__)

# Maximum instructions returned in one disassembly run to prevent memory exhaustion.
MAX_INSTRUCTIONS = 100_000

# Chunk size when reading PE section data from disk.
_READ_CHUNK = 64 * 1024  # 64 KB

ArchStr = Literal["x86"]
ModeStr = Literal["32-bit", "64-bit"]

_JUMP_MNEMONICS = frozenset(
    {
        "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
        "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp",
        "jnp", "jpe", "jpo", "jcxz", "jecxz", "jrcxz", "loop",
        "loope", "loopne", "loopz", "loopnz",
    }
)
_CALL_MNEMONICS = frozenset({"call", "callq", "callf"})
_RET_MNEMONICS = frozenset({"ret", "retq", "retn", "retf", "iret", "iretd", "iretq", "sysret"})
_PRIVILEGED_MNEMONICS = frozenset(
    {"in", "out", "ins", "outs", "insd", "outsd", "insw", "outsw",
     "insb", "outsb", "hlt", "cli", "sti", "clts", "lmsw", "lgdt",
     "lidt", "lldt", "ltr", "rdmsr", "wrmsr", "rdpmc", "invd",
     "wbinvd", "invlpg", "cpuid"}
)


def _require_capstone():
    """Import capstone and raise ConfigurationError if unavailable."""
    try:
        import capstone  # noqa: PLC0415
        return capstone
    except ImportError as exc:
        raise ConfigurationError(
            "capstone library is required for disassembly. "
            "Install via: pip install capstone"
        ) from exc


def _classify(mnemonic: str) -> tuple[bool, bool, bool, bool]:
    """Return (is_jump, is_call, is_ret, is_privileged) for a mnemonic."""
    m = mnemonic.lower()
    return (
        m in _JUMP_MNEMONICS,
        m in _CALL_MNEMONICS,
        m in _RET_MNEMONICS,
        m in _PRIVILEGED_MNEMONICS,
    )


def disassemble_bytes(
    data: bytes,
    base_address: int = 0,
    file_offset: int = 0,
    mode: ModeStr = "64-bit",
    section_name: str = "raw",
    entry_point_rva: int | None = None,
    max_instructions: int = MAX_INSTRUCTIONS,
) -> DisassemblyResult:
    """Disassemble a raw byte sequence using Capstone."""
    cs = _require_capstone()

    if mode == "32-bit":
        cs_mode = cs.CS_MODE_32
    elif mode == "64-bit":
        cs_mode = cs.CS_MODE_64
    else:
        raise UnsupportedFormatError(f"Unsupported disassembly mode: {mode!r}. Use '32-bit' or '64-bit'.")

    md = cs.Cs(cs.CS_ARCH_X86, cs_mode)
    md.detail = False

    warnings: list[str] = []
    instructions: list[DisassembledInstruction] = []
    decoded_bytes = 0
    truncated = False

    if not data:
        warnings.append("Input data is empty — nothing to disassemble.")
        return DisassemblyResult(
            architecture="x86",
            mode=mode,
            base_address=base_address,
            file_offset=file_offset,
            section_name=section_name,
            entry_point_rva=entry_point_rva,
            instructions=[],
            total_bytes=0,
            decoded_bytes=0,
            warnings=warnings,
        )

    try:
        for insn in md.disasm(data, base_address):
            if len(instructions) >= max_instructions:
                truncated = True
                warnings.append(
                    f"Result set capped at {max_instructions:,} instructions. "
                    "Use a smaller byte range or increase the limit."
                )
                break

            byte_pos = insn.address - base_address
            insn_file_offset = file_offset + byte_pos

            is_jump, is_call, is_ret, is_priv = _classify(insn.mnemonic)
            raw_hex = " ".join(f"{b:02X}" for b in insn.bytes)

            inst = DisassembledInstruction(
                offset=insn_file_offset,
                offset_hex=f"0x{insn_file_offset:08X}",
                rva=insn.address,
                rva_hex=f"0x{insn.address:08X}",
                raw_bytes=bytes(insn.bytes),
                raw_bytes_hex=raw_hex,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                size=insn.size,
                is_jump=is_jump,
                is_call=is_call,
                is_ret=is_ret,
                is_privileged=is_priv,
            )
            instructions.append(inst)
            decoded_bytes += insn.size

    except cs.CsError as exc:
        raise AnalysisError(f"Capstone disassembly error: {exc}") from exc

    logger.info(
        "Disassembly complete: %d instructions decoded from %d bytes (%s, %s)",
        len(instructions),
        len(data),
        "x86",
        mode,
    )

    return DisassemblyResult(
        architecture="x86",
        mode=mode,
        base_address=base_address,
        file_offset=file_offset,
        section_name=section_name,
        entry_point_rva=entry_point_rva,
        instructions=instructions,
        total_bytes=len(data),
        decoded_bytes=decoded_bytes,
        warnings=warnings,
        truncated=truncated,
    )


def disassemble_pe_section(
    pe_result,
    file_path: str | Path,
    section_name: str = ".text",
    max_instructions: int = MAX_INSTRUCTIONS,
) -> DisassemblyResult:
    """Disassemble a named section from an already-parsed PE binary."""
    path = Path(file_path)

    target_section = None
    for sec in pe_result.sections:
        if sec.name == section_name:
            target_section = sec
            break

    if target_section is None:
        available = [s.name for s in pe_result.sections]
        raise UnsupportedFormatError(
            f"Section '{section_name}' not found in PE binary. "
            f"Available sections: {available}"
        )

    if target_section.raw_size == 0:
        raise UnsupportedFormatError(
            f"Section '{section_name}' has no raw data (raw_size = 0)."
        )

    raw_offset = target_section.raw_data_offset
    raw_size = target_section.raw_size

    try:
        with path.open("rb") as fh:
            fh.seek(raw_offset)
            section_data = fh.read(raw_size)
    except OSError as exc:
        raise AnalysisError(
            f"Could not read section '{section_name}' from {path.name}: {exc}"
        ) from exc

    if not section_data:
        raise UnsupportedFormatError(
            f"Section '{section_name}' yielded no bytes from disk at offset {raw_offset:#x}."
        )

    mode: ModeStr = "64-bit" if pe_result.header.is_pe64 else "32-bit"
    base_va = pe_result.header.image_base + target_section.virtual_address
    ep_rva = pe_result.header.entry_point_rva

    logger.info(
        "Disassembling PE section '%s': raw_offset=0x%X, size=%d bytes, mode=%s, base_va=0x%X",
        section_name,
        raw_offset,
        len(section_data),
        mode,
        base_va,
    )

    return disassemble_bytes(
        data=section_data,
        base_address=base_va,
        file_offset=raw_offset,
        mode=mode,
        section_name=section_name,
        entry_point_rva=ep_rva,
        max_instructions=max_instructions,
    )


def list_disassemblable_sections(pe_result) -> list[str]:
    """Return section names that have executable flag or non-zero raw data."""
    executable = []
    with_data = []
    for sec in pe_result.sections:
        if sec.raw_size > 0:
            if "X" in sec.permissions:
                executable.append(sec.name)
            else:
                with_data.append(sec.name)
    return executable + with_data
