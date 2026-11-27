"""Unit tests for the Capstone disassembly engine (analyzers.disasm_analyzer).

All tests use known x86 / x86-64 byte sequences so results can be asserted
deterministically without executing any code.
"""

from __future__ import annotations

import pytest

from analyzers.disasm_analyzer import (
    MAX_INSTRUCTIONS,
    disassemble_bytes,
    disassemble_pe_section,
    list_disassemblable_sections,
)
from core.exceptions import AnalysisError, ConfigurationError, UnsupportedFormatError
from core.models.disasm_models import DisassembledInstruction, DisassemblyResult


# ---------------------------------------------------------------------------
# Well-known x86-64 byte sequences (NOP sled + RET)
# ---------------------------------------------------------------------------
_X64_NOP_RET = bytes(
    [
        0x90,                          # nop
        0x90,                          # nop
        0x48, 0x89, 0xE5,              # mov rbp, rsp
        0x48, 0x31, 0xC0,              # xor rax, rax
        0xC3,                          # ret
    ]
)

# Simple x86-64 CALL + JMP sequence
_X64_CALL_JMP = bytes(
    [
        0xE8, 0x00, 0x00, 0x00, 0x00,  # call +0
        0xEB, 0xFE,                    # jmp -2
    ]
)

# x86 32-bit PUSH EBP / MOV EBP,ESP / POP EBP / RET
_X86_PROLOGUE = bytes(
    [
        0x55,                          # push ebp
        0x89, 0xEC,                    # mov esp, ebp
        0x5D,                          # pop ebp
        0xC3,                          # ret
    ]
)

# IN / OUT (privileged)
_X86_PRIVILEGED = bytes(
    [
        0xEC,                          # in al, dx
        0xEE,                          # out dx, al
        0xF4,                          # hlt
    ]
)


class TestDisassembleBytes:
    """Tests for disassemble_bytes()."""

    def test_x64_nop_sled_returns_instructions(self):
        result = disassemble_bytes(_X64_NOP_RET, base_address=0x1000, mode="64-bit")
        assert isinstance(result, DisassemblyResult)
        assert result.instruction_count > 0
        assert result.architecture == "x86"
        assert result.mode == "64-bit"

    def test_x64_mnemonics_correct(self):
        result = disassemble_bytes(_X64_NOP_RET, base_address=0x1000, mode="64-bit")
        mnemonics = [i.mnemonic for i in result.instructions]
        assert "nop" in mnemonics
        assert "ret" in mnemonics
        assert "xor" in mnemonics

    def test_x64_ret_flagged(self):
        result = disassemble_bytes(_X64_NOP_RET, base_address=0x1000, mode="64-bit")
        ret_insns = [i for i in result.instructions if i.is_ret]
        assert len(ret_insns) == 1
        assert ret_insns[0].mnemonic in ("ret", "retq")

    def test_x64_call_flagged(self):
        result = disassemble_bytes(_X64_CALL_JMP, base_address=0x2000, mode="64-bit")
        call_insns = [i for i in result.instructions if i.is_call]
        assert len(call_insns) >= 1

    def test_x64_jmp_flagged(self):
        result = disassemble_bytes(_X64_CALL_JMP, base_address=0x2000, mode="64-bit")
        jmp_insns = [i for i in result.instructions if i.is_jump]
        assert len(jmp_insns) >= 1

    def test_x86_32bit_prologue(self):
        result = disassemble_bytes(_X86_PROLOGUE, base_address=0x401000, mode="32-bit")
        mnemonics = [i.mnemonic for i in result.instructions]
        assert "push" in mnemonics
        assert "ret" in mnemonics

    def test_privileged_instructions_flagged(self):
        result = disassemble_bytes(_X86_PRIVILEGED, base_address=0x0, mode="32-bit")
        priv_insns = [i for i in result.instructions if i.is_privileged]
        assert len(priv_insns) >= 1

    def test_base_address_applied_to_rva(self):
        base = 0x140001000
        result = disassemble_bytes(_X64_NOP_RET, base_address=base, mode="64-bit")
        assert result.instructions[0].rva == base
        assert result.instructions[0].rva_hex == f"0x{base:08X}"

    def test_file_offset_applied(self):
        file_off = 0x400
        result = disassemble_bytes(
            _X64_NOP_RET, base_address=0x1000, file_offset=file_off, mode="64-bit"
        )
        assert result.instructions[0].offset == file_off
        assert result.instructions[0].offset_hex == f"0x{file_off:08X}"

    def test_decoded_bytes_match_total(self):
        result = disassemble_bytes(_X64_NOP_RET, mode="64-bit")
        assert result.decoded_bytes <= result.total_bytes
        assert result.decoded_bytes > 0

    def test_raw_bytes_hex_format(self):
        result = disassemble_bytes(b"\x90", base_address=0, mode="64-bit")
        insn = result.instructions[0]
        assert insn.raw_bytes_hex == "90"
        assert insn.raw_bytes == b"\x90"

    def test_empty_data_returns_empty_result(self):
        result = disassemble_bytes(b"", mode="64-bit")
        assert result.instruction_count == 0
        assert result.total_bytes == 0
        assert len(result.warnings) > 0

    def test_max_instructions_cap(self):
        result = disassemble_bytes(b"\x90" * 1000, mode="64-bit", max_instructions=5)
        assert result.instruction_count == 5
        assert result.truncated is True
        assert len(result.warnings) > 0

    def test_unsupported_mode_raises(self):
        with pytest.raises(UnsupportedFormatError):
            disassemble_bytes(b"\x90", mode="arm")  # type: ignore[arg-type]

    def test_coverage_percent_full(self):
        result = disassemble_bytes(b"\x90" * 10, mode="64-bit")
        assert result.coverage_percent == 100.0

    def test_to_dict_serialisable(self):
        result = disassemble_bytes(_X64_NOP_RET, mode="64-bit")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "instructions" in d
        assert isinstance(d["instructions"], list)
        import json
        json.dumps(d)


class TestDisassembledInstructionModel:
    """Tests for the DisassembledInstruction dataclass."""

    def _make_insn(self, mnemonic="nop", op_str="") -> DisassembledInstruction:
        return DisassembledInstruction(
            offset=0x200,
            offset_hex="0x00000200",
            rva=0x1000,
            rva_hex="0x00001000",
            raw_bytes=b"\x90",
            raw_bytes_hex="90",
            mnemonic=mnemonic,
            op_str=op_str,
            size=1,
        )

    def test_full_text_no_operands(self):
        insn = self._make_insn("nop")
        assert "nop" in insn.full_text
        assert "0x00001000" in insn.full_text

    def test_full_text_with_operands(self):
        insn = self._make_insn("mov", "rax, rbx")
        assert "mov" in insn.full_text
        assert "rax, rbx" in insn.full_text

    def test_to_dict_has_expected_keys(self):
        insn = self._make_insn()
        d = insn.to_dict()
        for key in ("offset", "rva", "mnemonic", "op_str", "size"):
            assert key in d

    def test_to_dict_raw_bytes_is_string(self):
        insn = self._make_insn()
        d = insn.to_dict()
        assert isinstance(d["raw_bytes"], str)


class TestDisassemblePESection:
    """Tests for disassemble_pe_section() using the fixture generator."""

    @pytest.fixture()
    def pe64_file(self, tmp_path):
        from tests.fixtures.pe_fixture import create_minimal_pe
        from analyzers.pe_analyzer import parse_pe
        path = create_minimal_pe(tmp_path / "test64.exe", is_64bit=True)
        result = parse_pe(path)
        return path, result

    @pytest.fixture()
    def pe32_file(self, tmp_path):
        from tests.fixtures.pe_fixture import create_minimal_pe
        from analyzers.pe_analyzer import parse_pe
        path = create_minimal_pe(tmp_path / "test32.exe", is_64bit=False)
        result = parse_pe(path)
        return path, result

    def test_pe64_text_section_disassembled(self, pe64_file):
        path, pe = pe64_file
        result = disassemble_pe_section(pe, path, section_name=".text")
        assert isinstance(result, DisassemblyResult)
        assert result.mode == "64-bit"
        assert result.section_name == ".text"
        assert result.instruction_count > 0

    def test_pe32_text_section_disassembled(self, pe32_file):
        path, pe = pe32_file
        result = disassemble_pe_section(pe, path, section_name=".text")
        assert result.mode == "32-bit"
        assert result.instruction_count > 0

    def test_missing_section_raises(self, pe64_file):
        path, pe = pe64_file
        with pytest.raises(UnsupportedFormatError):
            disassemble_pe_section(pe, path, section_name=".nonexistent")

    def test_nop_sled_produces_nop_mnemonics(self, pe64_file):
        path, pe = pe64_file
        result = disassemble_pe_section(pe, path, section_name=".text")
        mnemonics = {i.mnemonic for i in result.instructions}
        assert "nop" in mnemonics

    def test_base_address_uses_image_base_plus_section_va(self, pe64_file):
        path, pe = pe64_file
        result = disassemble_pe_section(pe, path, section_name=".text")
        section = next(s for s in pe.sections if s.name == ".text")
        expected_va = pe.header.image_base + section.virtual_address
        assert result.base_address == expected_va


class TestListDisassemblableSections:
    """Tests for list_disassemblable_sections()."""

    @pytest.fixture()
    def pe_result(self, tmp_path):
        from tests.fixtures.pe_fixture import create_minimal_pe
        from analyzers.pe_analyzer import parse_pe
        path = create_minimal_pe(tmp_path / "test.exe")
        return parse_pe(path)

    def test_returns_list(self, pe_result):
        sections = list_disassemblable_sections(pe_result)
        assert isinstance(sections, list)

    def test_text_section_included(self, pe_result):
        sections = list_disassemblable_sections(pe_result)
        assert ".text" in sections

    def test_executable_sections_come_first(self, pe_result):
        sections = list_disassemblable_sections(pe_result)
        if ".data" in sections:
            assert sections.index(".text") < sections.index(".data")
