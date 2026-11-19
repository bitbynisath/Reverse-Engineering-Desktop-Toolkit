"""Integration tests for String Extractor UI and interactive filtering."""

from pathlib import Path
import time
from PySide6.QtWidgets import QApplication
from ui.pages.string_extractor_page import StringExtractorPage


def test_string_extractor_ui_load_file(qapp: QApplication, tmp_path: Path):
    """Verify loading file in StringExtractorPage, background worker, and table rendering."""
    sample = tmp_path / "str_test.bin"
    ascii_part = b"FirstAsciiString\x00\x00"
    utf16_part = "SecondUnicodeString".encode("utf-16le")
    sample.write_bytes(ascii_part + utf16_part)

    page = StringExtractorPage()
    page.show()
    qapp.processEvents()

    # Load and trigger extraction
    page.load_file(sample)

    # Wait for worker thread
    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert len(page._all_strings) >= 2
    assert page.table.rowCount() >= 2
    assert page.btn_export_txt.isEnabled() is True
    assert page.btn_export_csv.isEnabled() is True

    # Test filtering by query
    page.input_filter.setText("Unicode")
    qapp.processEvents()
    assert page.table.rowCount() == 1
    assert "SecondUnicodeString" in page.table.item(0, 3).text()

    # Test filter by encoding
    page.input_filter.setText("")
    page.combo_encoding.setCurrentText("ASCII")
    qapp.processEvents()
    assert page.table.rowCount() == 1
    assert "FirstAsciiString" in page.table.item(0, 3).text()

    # Reset filter
    page.combo_encoding.setCurrentText("All")
    qapp.processEvents()
    assert page.table.rowCount() >= 2

    page.close()


def test_string_extractor_ui_cancellation(qapp: QApplication, tmp_path: Path):
    """Verify cancelling extraction gracefully stops worker."""
    sample = tmp_path / "cancel_test.bin"
    sample.write_bytes(b"A" * (100 * 1024))

    page = StringExtractorPage()
    page.show()
    qapp.processEvents()

    page.load_file(sample)
    # Immediately trigger cancellation
    page._on_cancel_extraction()

    timeout = time.time() + 5.0
    while page._thread and page._thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert page.progress_frame.isVisible() is False
    page.close()
