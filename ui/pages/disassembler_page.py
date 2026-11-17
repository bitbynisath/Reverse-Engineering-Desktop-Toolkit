"""Disassembler Page placeholder for Phase 1."""

from __future__ import annotations

from app.constants import PAGE_DISASSEMBLER
from ui.pages.placeholder_page import PlaceholderPage


class DisassemblerPage(PlaceholderPage):
    """Disassembler screen scheduled for Phase 6."""

    def __init__(self, parent=None) -> None:
        super().__init__(
            module_id=PAGE_DISASSEMBLER,
            title="Disassembler",
            phase_label="Phase 6 --- Capstone Disassembly Engine",
            description=(
                "Static machine code disassembly for x86 and x86-64 binaries utilizing the Capstone engine."
            ),
            planned_features=[
                "x86 (32-bit) and x86-64 disassembly",
                "Instruction address, raw instruction bytes, mnemonics, and operands",
                "Linear sweep and entry-point analysis",
                "File offset to Virtual Address (RVA) mapping",
                "Instruction navigation and jump target referencing",
                "Syntax highlighting for assembly instructions",
            ],
            dependencies=["capstone"],
            parent=parent,
        )
