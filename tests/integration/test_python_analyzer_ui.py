"""Integration tests for Python Bytecode Analyzer UI page."""

from __future__ import annotations

from pathlib import Path
import time

from PySide6.QtWidgets import QApplication

from app.constants import PAGE_PYTHON_ANALYZER
from tests.fixtures.python_fixture import create_sample_py_file, create_sample_pyc_file
from ui.pages.python_analyzer_page import PythonAnalyzerPage


def test_python_analyzer_ui_structure(qapp: QApplication):
    """Verify widget hierarchy, module ID, and initial UI state."""
    page = PythonAnalyzerPage()
    page.show()
    qapp.processEvents()

    assert page.module_id == PAGE_PYTHON_ANALYZER
    assert page.tabs.count() == 4
    assert hasattr(page, "btn_browse")
    assert hasattr(page, "btn_export_txt")
    assert not page.btn_export_txt.isEnabled()
    assert hasattr(page, "combo_code_objects")
    assert hasattr(page, "table_disasm")
    assert hasattr(page, "table_consts")
    assert hasattr(page, "table_names")

    page.close()


def test_python_analyzer_ui_load_pyc_file(qapp: QApplication, tmp_path: Path):
    """Verify loading a .pyc file populates metrics, tabs, and disassembly."""
    pyc_file = create_sample_pyc_file(tmp_path)

    page = PythonAnalyzerPage()
    page.show()
    qapp.processEvents()

    page.load_file(pyc_file)

    # Wait for background worker thread to finish
    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    # Export button should be enabled
    assert page.btn_export_txt.isEnabled()

    # Code objects dropdown populated
    assert page.combo_code_objects.count() >= 4

    # Disassembly table populated
    assert page.table_disasm.rowCount() > 0

    # Constants table populated
    assert page.table_consts.rowCount() > 0

    page.close()


def test_python_analyzer_ui_code_object_selection(qapp: QApplication, tmp_path: Path):
    """Verify selecting different code objects in dropdown updates table and properties."""
    pyc_file = create_sample_pyc_file(tmp_path)

    page = PythonAnalyzerPage()
    page.show()
    qapp.processEvents()

    page.load_file(pyc_file)

    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    # Switch to second code object
    assert page.combo_code_objects.count() > 1
    page.combo_code_objects.setCurrentIndex(1)
    qapp.processEvents()

    # Properties updated
    assert page.lbl_prop_name.text() != "—"
    assert page.table_disasm.rowCount() > 0

    page.close()


def test_python_analyzer_ui_filter(qapp: QApplication, tmp_path: Path):
    """Verify live search/filtering of disassembly instructions."""
    pyc_file = create_sample_pyc_file(tmp_path)

    page = PythonAnalyzerPage()
    page.show()
    qapp.processEvents()

    page.load_file(pyc_file)

    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    initial_rows = page.table_disasm.rowCount()
    assert initial_rows > 0

    # Filter for non-existent mnemonic
    page.input_search.setText("NONEXISTENT_OPCODE_XYZ")
    qapp.processEvents()

    # All rows should be hidden
    visible = sum(1 for r in range(page.table_disasm.rowCount()) if not page.table_disasm.isRowHidden(r))
    assert visible == 0

    # Clear filter
    page.input_search.clear()
    qapp.processEvents()
    visible_after = sum(1 for r in range(page.table_disasm.rowCount()) if not page.table_disasm.isRowHidden(r))
    assert visible_after == initial_rows

    page.close()


def test_python_analyzer_ui_invalid_file(qapp: QApplication, tmp_path: Path, monkeypatch):
    """Verify invalid file path triggers safe error warning without crashing."""
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)

    fake_file = tmp_path / "does_not_exist.pyc"

    page = PythonAnalyzerPage()
    page.show()
    qapp.processEvents()

    page.load_file(fake_file)
    qapp.processEvents()

    assert not page.btn_export_txt.isEnabled()
    page.close()
