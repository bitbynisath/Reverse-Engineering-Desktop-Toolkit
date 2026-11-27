"""Data models for Capstone disassembly results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class DisassembledInstruction:
    """A single decoded machine-code instruction.

    Attributes:
        offset:         Raw file offset where instruction bytes begin.
        offset_hex:     Hexadecimal representation of the file offset (e.g. '0x00000400').
        rva:            Relative Virtual Address (image_base removed) or linear virtual address.
        rva_hex:        Hexadecimal RVA string (e.g. '0x00001000').
        raw_bytes:      Raw instruction bytes as a bytes object.
        raw_bytes_hex:  Space-separated uppercase hex string (e.g. '55 89 E5').
        mnemonic:       Instruction mnemonic in lowercase (e.g. 'push', 'mov', 'call').
        op_str:         Operand string as decoded by Capstone (e.g. 'rbp', 'eax, ebx').
        size:           Instruction length in bytes.
        is_jump:        True when this instruction is an unconditional or conditional jump.
        is_call:        True when this instruction is a CALL.
        is_ret:         True when this instruction is a RET / RETN / RETF.
        is_privileged:  True when the instruction requires elevated privilege (e.g. IN, OUT, HLT).
    """

    offset: int
    offset_hex: str
    rva: int
    rva_hex: str
    raw_bytes: bytes
    raw_bytes_hex: str
    mnemonic: str
    op_str: str
    size: int
    is_jump: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_privileged: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary (bytes converted to hex string)."""
        d = asdict(self)
        d["raw_bytes"] = self.raw_bytes_hex
        return d

    @property
    def full_text(self) -> str:
        """Human-readable single-line representation of the instruction."""
        ops = f"  {self.op_str}" if self.op_str else ""
        return f"{self.rva_hex}  {self.raw_bytes_hex:<24}  {self.mnemonic}{ops}"


@dataclass
class DisassemblyResult:
    """Container for a full disassembly run on a code region.

    Attributes:
        architecture:       Capstone architecture string (e.g. 'x86').
        mode:               Bit-width mode string (e.g. '32-bit', '64-bit').
        base_address:       Virtual address used as the base for RVA calculation.
        file_offset:        File offset where disassembly started.
        section_name:       PE section name if disassembling from a named section, else 'raw'.
        entry_point_rva:    Entry-point RVA from the PE header (None for raw binaries).
        instructions:       Decoded instructions in address order.
        total_bytes:        Total bytes of input data fed to the disassembler.
        decoded_bytes:      Total bytes accounted for by decoded instructions.
        warnings:           Non-fatal diagnostic messages.
        truncated:          True when results were capped by MAX_INSTRUCTIONS limit.
    """

    architecture: str
    mode: str
    base_address: int
    file_offset: int
    section_name: str
    entry_point_rva: int | None
    instructions: list[DisassembledInstruction]
    total_bytes: int
    decoded_bytes: int
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def coverage_percent(self) -> float:
        """Fraction of input bytes covered by decoded instructions (0–100)."""
        if self.total_bytes == 0:
            return 0.0
        return round(self.decoded_bytes / self.total_bytes * 100, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "mode": self.mode,
            "base_address": hex(self.base_address),
            "file_offset": hex(self.file_offset),
            "section_name": self.section_name,
            "entry_point_rva": hex(self.entry_point_rva) if self.entry_point_rva is not None else None,
            "instruction_count": self.instruction_count,
            "total_bytes": self.total_bytes,
            "decoded_bytes": self.decoded_bytes,
            "coverage_percent": self.coverage_percent,
            "truncated": self.truncated,
            "warnings": self.warnings,
            "instructions": [i.to_dict() for i in self.instructions],
        }
