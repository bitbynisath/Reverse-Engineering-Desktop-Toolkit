"""Reports Page placeholder for Phase 1."""

from __future__ import annotations

from app.constants import PAGE_REPORTS
from ui.pages.placeholder_page import PlaceholderPage


class ReportsPage(PlaceholderPage):
    """Reports screen scheduled for Phase 9."""

    def __init__(self, parent=None) -> None:
        super().__init__(
            module_id=PAGE_REPORTS,
            title="Analysis Reports",
            phase_label="Phase 9 --- Reporting Engine",
            description=(
                "Generate structured, professional static-analysis reports in JSON, CSV, "
                "HTML, and PDF formats."
            ),
            planned_features=[
                "Export complete analysis findings to structured JSON",
                "Export tabular data (strings, imports, sections) to CSV",
                "Generate formatted standalone HTML reports with styling",
                "Generate PDF executive summaries and technical reports",
                "Clear separation between factual observations and heuristic interpretations",
            ],
            dependencies=["json", "csv", "jinja2", "reportlab"],
            parent=parent,
        )
