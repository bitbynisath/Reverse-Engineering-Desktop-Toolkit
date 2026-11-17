"""String Extractor Page placeholder for Phase 1."""

from __future__ import annotations

from app.constants import PAGE_STRING_EXTRACTOR
from ui.pages.placeholder_page import PlaceholderPage


class StringExtractorPage(PlaceholderPage):
    """String Extractor screen scheduled for Phase 4."""

    def __init__(self, parent=None) -> None:
        super().__init__(
            module_id=PAGE_STRING_EXTRACTOR,
            title="String Extractor",
            phase_label="Phase 4 --- String Extraction",
            description=(
                "Extract printable ASCII, UTF-8, and UTF-16LE text sequences with precise file offsets, "
                "search filters, and export capabilities."
            ),
            planned_features=[
                "Printable ASCII string extraction",
                "UTF-16LE string extraction (common in Windows PE binaries)",
                "UTF-8 string extraction with strict validity checks",
                "Configurable minimum string length (default 4 chars)",
                "Offset address tracking and encoding labeling",
                "Real-time search, regex filtering, and sortable results table",
                "Export results to TXT and CSV formats",
                "Background processing with cancellation and progress reporting",
            ],
            dependencies=["re", "QThread worker"],
            parent=parent,
        )
