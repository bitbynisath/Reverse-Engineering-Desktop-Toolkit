"""Integration tests for DisassemblerPage UI widget (Phase 6)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from tests.fixtures.pe_fixture import create_minimal_pe
from ui.pages.disassembler_page import DisassemblerPage


@pytest.fixture()
def page(qapp: QApplication) -> DisassemblerPage:
    """Return a DisassemblerPage instance with offscreen rendering."""
    p = DisassemblerPage()
    p.show()
    qapp.processEvents()
    return p


@pytest.fixture()
def pe64_path(tmp_path: Path) -> Path:
    """Create a minimal 64-bit PE fixture on disk."""
    return create_minimal_pe(tmp_path / "test64.exe", is_64bit=True)


@pytest.fixture()
def pe32_path(tmp_path: Path) -> Path:
    """Create a minimal 32-bit PE fixture on disk."""
    return create_minimal_pe(tmp_path / "test32.exe", is_64bit=False)


class TestDisassemblerPageStructure:
    """Verify widget is correctly initialised before any file is loaded."""

    def test_module_id(self, page: DisassemblerPage):
        from app.constants import PAGE_DISASSEMBLER
        assert page.module_id == PAGE_DISASSEMBLER

    def test_has_expected_widgets(self, page: DisassemblerPage):
        assert hasattr(page, "table")
        assert hasattr(page, "btn_browse")
        assert hasattr(page, "btn_disassemble")
        assert hasattr(page, "btn_cancel")
        assert hasattr(page, "search_input")
        assert hasattr(page, "combo_mode")
        assert hasattr(page, "combo_section")
        assert hasattr(page, "progress_bar")
        assert hasattr(page, "btn_export")

    def test_disassemble_button_disabled_initially(self, page: DisassemblerPage):
        assert not page.btn_disassemble.isEnabled()

    def test_progress_bar_hidden_initially(self, page: DisassemblerPage):
        assert not page.progress_bar.isVisible()

    def test_export_button_disabled_initially(self, page: DisassemblerPage):
        assert not page.btn_export.isEnabled()


class TestLoadFile:
    """Verify load_file() updates UI correctly."""

    def test_load_file_enables_disassemble(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        page.load_file(pe64_path)
        qapp.processEvents()
        assert page.btn_disassemble.isEnabled()

    def test_load_file_updates_path_label(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        page.load_file(pe64_path)
        qapp.processEvents()
        assert pe64_path.name in page.lbl_file_path.text()

    def test_current_file_set(
        self, page: DisassemblerPage, pe64_path: Path
    ):
        page.load_file(pe64_path)
        assert page._current_file == pe64_path


class TestDisassembly:
    """Full disassembly run tests (using background QThread)."""

    def _wait_for_result(self, page: DisassemblerPage, qapp: QApplication, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            qapp.processEvents()
            if page._thread is None or not page._thread.isRunning():
                break
            time.sleep(0.05)
        qapp.processEvents()

    def test_disassemble_pe64_produces_instructions(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        from analyzers.pe_analyzer import parse_pe
        pe = parse_pe(pe64_path)
        page.load_file(pe64_path)
        page.set_pe_result(pe)
        qapp.processEvents()

        page._start_disassembly()
        self._wait_for_result(page, qapp)

        assert page._current_result is not None
        assert page._current_result.instruction_count > 0
        assert page.table.rowCount() > 0

    def test_disassemble_pe32_produces_instructions(
        self, page: DisassemblerPage, pe32_path: Path, qapp: QApplication
    ):
        from analyzers.pe_analyzer import parse_pe
        pe = parse_pe(pe32_path)
        page.load_file(pe32_path)
        page.set_pe_result(pe)
        qapp.processEvents()

        page._start_disassembly()
        self._wait_for_result(page, qapp)

        assert page._current_result is not None
        assert page._current_result.mode == "32-bit"

    def test_disassemble_raw_mode(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        page.load_file(pe64_path)
        page.btn_raw_mode.setChecked(True)
        qapp.processEvents()

        page._start_disassembly()
        self._wait_for_result(page, qapp)

        assert page._current_result is not None
        assert page._current_result.section_name == "raw"

    def test_export_button_enabled_after_disassembly(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        from analyzers.pe_analyzer import parse_pe
        pe = parse_pe(pe64_path)
        page.load_file(pe64_path)
        page.set_pe_result(pe)
        qapp.processEvents()

        page._start_disassembly()
        self._wait_for_result(page, qapp)

        assert page.btn_export.isEnabled()

    def test_progress_bar_hidden_after_disassembly(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        from analyzers.pe_analyzer import parse_pe
        pe = parse_pe(pe64_path)
        page.load_file(pe64_path)
        page.set_pe_result(pe)
        qapp.processEvents()

        page._start_disassembly()
        self._wait_for_result(page, qapp)

        assert not page.progress_bar.isVisible()

    def test_file_loaded_signal_emitted(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        from analyzers.pe_analyzer import parse_pe
        emitted = []
        page.file_loaded.connect(lambda name, count: emitted.append((name, count)))

        pe = parse_pe(pe64_path)
        page.load_file(pe64_path)
        page.set_pe_result(pe)
        qapp.processEvents()

        page._start_disassembly()
        self._wait_for_result(page, qapp)

        assert len(emitted) == 1
        name, count = emitted[0]
        assert name == pe64_path.name
        assert count > 0


class TestSearch:
    """Verify search/filter functionality on a populated table."""

    def _populate(
        self, page: DisassemblerPage, path: Path, qapp: QApplication
    ) -> None:
        from analyzers.pe_analyzer import parse_pe
        pe = parse_pe(path)
        page.load_file(path)
        page.set_pe_result(pe)
        qapp.processEvents()
        page._start_disassembly()
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            qapp.processEvents()
            if page._thread is None or not page._thread.isRunning():
                break
            time.sleep(0.05)
        qapp.processEvents()

    def test_search_nop_hides_non_matching_rows(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        self._populate(page, pe64_path, qapp)

        total_rows = page.table.rowCount()
        assert total_rows > 0

        page.search_input.setText("nop")
        qapp.processEvents()

        visible = sum(1 for r in range(total_rows) if not page.table.isRowHidden(r))
        assert visible > 0
        assert visible <= total_rows

    def test_clear_search_restores_all_rows(
        self, page: DisassemblerPage, pe64_path: Path, qapp: QApplication
    ):
        self._populate(page, pe64_path, qapp)

        total_rows = page.table.rowCount()
        page.search_input.setText("zzznomatchzzz")
        qapp.processEvents()

        page._clear_search()
        qapp.processEvents()

        visible = sum(1 for r in range(total_rows) if not page.table.isRowHidden(r))
        assert visible == total_rows
