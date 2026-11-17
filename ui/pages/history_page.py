"""Analysis History Page placeholder for Phase 1."""

from __future__ import annotations

from app.constants import PAGE_HISTORY
from ui.pages.placeholder_page import PlaceholderPage


class HistoryPage(PlaceholderPage):
    """Analysis History screen scheduled for Phase 9."""

    def __init__(self, parent=None) -> None:
        super().__init__(
            module_id=PAGE_HISTORY,
            title="Analysis History",
            phase_label="Phase 9 --- SQLite History & Session Persistence",
            description=(
                "Search, review, and manage past analysis sessions backed by local SQLite storage."
            ),
            planned_features=[
                "Local SQLite database schema for session records",
                "Historical record search by filename, hash, and timestamp",
                "Reopen previous analysis sessions without re-analyzing",
                "Detailed session statistics and metadata cache",
                "Safe history record cleanup without deleting original user files",
            ],
            dependencies=["sqlite3"],
            parent=parent,
        )
