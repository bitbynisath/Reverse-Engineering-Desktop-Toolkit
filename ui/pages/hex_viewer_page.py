"""Hex Viewer Page placeholder for Phase 1."""

from __future__ import annotations

from app.constants import PAGE_HEX_VIEWER
from ui.pages.placeholder_page import PlaceholderPage


class HexViewerPage(PlaceholderPage):
    """Hex Viewer screen scheduled for Phase 3."""

    def __init__(self, parent=None) -> None:
        super().__init__(
            module_id=PAGE_HEX_VIEWER,
            title="Hexadecimal Viewer",
            phase_label="Phase 3 --- Hexadecimal Viewer",
            description=(
                "Inspect raw binary byte contents with memory-bounded chunked reads, "
                "customizable rows, hex/ASCII views, and pattern searching."
            ),
            planned_features=[
                "Configurable bytes per row (default 16 bytes)",
                "Offset address column, hexadecimal byte columns, and printable ASCII column",
                "High-performance bounded reads and paging for multi-gigabyte files",
                "Go-to-offset navigation (hex or decimal)",
                "Byte sequence search in hex and ASCII",
                "Byte inspector showing decimal, hex, binary, and ASCII representations",
            ],
            dependencies=["mmap", "buffered I/O"],
            parent=parent,
        )
