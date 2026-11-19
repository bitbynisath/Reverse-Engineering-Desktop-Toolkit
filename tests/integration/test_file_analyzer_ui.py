"""Integration tests for File Analyzer page and UI interaction."""

from pathlib import Path
import time
from PySide6.QtWidgets import QApplication
from ui.pages.file_analyzer_page import FileAnalyzerPage


def test_file_analyzer_ui_load_file(qapp: QApplication, tmp_path: Path):
    """Verify loading and displaying file analysis results in FileAnalyzerPage."""
    sample = tmp_path / "test_program.exe"
    data = bytearray(b"\x00" * 128)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, byteorder="little")
    data[0x40:0x44] = b"PE\x00\x00"
    sample.write_bytes(data)

    page = FileAnalyzerPage()
    page.show()
    qapp.processEvents()

    assert not page.empty_card.isHidden()
    assert page.results_container.isHidden()

    # Start analysis
    page.load_file(sample)

    # Process Qt event loop until background thread finishes
    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    # Allow slot execution
    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert not page.results_container.isHidden()
    assert page.empty_card.isHidden()
    assert "test_program.exe" in page.lbl_meta_name.text()
    assert "Windows PE" in page.lbl_sig_type.text()
    assert page.lbl_hash_md5.text() != ""
    assert page.lbl_hash_sha256.text() != ""
    assert page.btn_export_json.isEnabled() is True
    page.close()


def test_file_analyzer_ui_empty_file(qapp: QApplication, tmp_path: Path):
    """Verify loading empty 0-byte file in UI displays warnings appropriately."""
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    page = FileAnalyzerPage()
    page.show()
    qapp.processEvents()

    page.load_file(empty_file)

    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert not page.results_container.isHidden()
    assert not page.banner_warnings.isHidden()
    page.close()
