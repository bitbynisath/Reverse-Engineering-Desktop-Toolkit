"""Integration tests for PE Analyzer UI and structure presentation."""

from pathlib import Path
import time
from PySide6.QtWidgets import QApplication
from tests.fixtures.pe_fixture import create_minimal_pe
from ui.pages.pe_analyzer_page import PEAnalyzerPage


def test_pe_analyzer_ui_load_file(qapp: QApplication, tmp_path: Path):
    """Verify loading PE fixture populates tables and header tabs."""
    pe_file = create_minimal_pe(tmp_path / "ui_test.exe", is_64bit=True)

    page = PEAnalyzerPage()
    page.show()
    qapp.processEvents()

    assert not page.empty_card.isHidden()
    assert page.tabs.isHidden()

    # Load file
    page.load_file(pe_file)

    # Wait for worker thread
    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert not page.tabs.isHidden()
    assert page.empty_card.isHidden()

    # Verify Header labels
    assert "PE32+" in page.lbl_pe_format.text()
    assert "0x00001000" in page.lbl_pe_entry.text()
    assert "2" in page.lbl_pe_sections_count.text()

    # Verify Sections table
    assert page.sections_table.rowCount() == 2
    assert ".text" in page.sections_table.item(0, 0).text()
    assert ".data" in page.sections_table.item(1, 0).text()

    page.close()


def test_pe_analyzer_ui_invalid_file(qapp: QApplication, tmp_path: Path, monkeypatch):
    """Verify loading non-PE file fails gracefully and maintains clean state."""
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)

    fake = tmp_path / "not_a_pe.bin"
    fake.write_bytes(b"Plain text non-executable file")

    page = PEAnalyzerPage()
    page.show()
    qapp.processEvents()

    page.load_file(fake)

    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert not page.empty_card.isHidden()
    assert page.tabs.isHidden()
    page.close()
