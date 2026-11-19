"""Integration tests for Hex Viewer UI, paging, and interactive search."""

from pathlib import Path
import time
from PySide6.QtWidgets import QApplication
from ui.pages.hex_viewer_page import HexViewerPage


def test_hex_viewer_ui_load_file(qapp: QApplication, tmp_path: Path):
    """Verify loading binary file and populating table with hex and ASCII data."""
    sample = tmp_path / "test_hex.bin"
    sample.write_bytes(b"\x4D\x5A\x90\x00Hello World!" + b"\x00" * 32)

    page = HexViewerPage()
    page.show()
    qapp.processEvents()

    page.load_file(sample)
    qapp.processEvents()

    assert page.hex_table.rowCount() > 0
    # First row offset should be 00000000:
    assert "00000000" in page.hex_table.item(0, 0).text()
    # Hex bytes column should contain 4D 5A
    assert "4D 5A" in page.hex_table.item(0, 1).text()
    # ASCII column should contain MZ
    assert "MZ" in page.hex_table.item(0, 2).text()

    # Verify inspector updated on default selection
    assert page.lbl_insp_offset.text() != "---"
    assert "0x4D" in page.lbl_insp_byte.text()
    page.close()


def test_hex_viewer_ui_paging(qapp: QApplication, tmp_path: Path):
    """Verify multi-page navigation controls."""
    sample = tmp_path / "multi_page.bin"
    # 32 rows * 16 bytes = 512 bytes/page. Write 1500 bytes -> 3 pages.
    sample.write_bytes(bytes([i % 256 for i in range(1500)]))

    page = HexViewerPage()
    page.show()
    qapp.processEvents()

    page.load_file(sample)
    qapp.processEvents()

    assert page._total_pages == 3
    assert page._current_page == 0

    # Go next
    page._go_next_page()
    qapp.processEvents()
    assert page._current_page == 1
    assert page.spin_page.value() == 2

    # Go last
    page._go_last_page()
    qapp.processEvents()
    assert page._current_page == 2
    assert page.spin_page.value() == 3

    # Go first
    page._go_first_page()
    qapp.processEvents()
    assert page._current_page == 0
    assert page.spin_page.value() == 1
    page.close()


def test_hex_viewer_ui_goto_offset(qapp: QApplication, tmp_path: Path):
    """Verify jumping to offset via hex or decimal input."""
    sample = tmp_path / "goto_sample.bin"
    sample.write_bytes(bytes([i % 256 for i in range(1024)]))

    page = HexViewerPage()
    page.show()
    qapp.processEvents()

    page.load_file(sample)
    qapp.processEvents()

    # Jump to offset 0x200 (512 dec -> page 1)
    page.input_goto_offset.setText("0x200")
    page._on_goto_offset()
    qapp.processEvents()

    assert page._current_page == 1
    page.close()


def test_hex_viewer_ui_search(qapp: QApplication, tmp_path: Path):
    """Verify interactive background search finds byte patterns and jumps to offset."""
    sample = tmp_path / "search_ui.bin"
    # Write padding then specific marker
    data = b"\x00" * 600 + b"\xCA\xFE\xBA\xBE" + b"\x00" * 200
    sample.write_bytes(data)

    page = HexViewerPage()
    page.show()
    qapp.processEvents()

    page.load_file(sample)
    qapp.processEvents()

    page.input_search.setText("CA FE BA BE")
    page.combo_search_mode.setCurrentIndex(0)  # Hex Bytes
    page._on_search()

    # Wait for search worker thread
    timeout = time.time() + 5.0
    while page._search_thread and page._search_thread.isRunning() and time.time() < timeout:
        qapp.processEvents()
        time.sleep(0.05)

    for _ in range(5):
        qapp.processEvents()
        time.sleep(0.02)

    assert len(page._search_matches) == 1
    assert page._search_matches[0] == 600
    # Marker is at offset 600 (which is in page 1 since 512 bytes/page)
    assert page._current_page == 1
    page.close()
