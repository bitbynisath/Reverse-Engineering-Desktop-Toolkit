"""Reusable Metric / Stat Card Widget."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout


class StatCard(QFrame):
    """Card showing an analysis metric, label, and secondary text."""

    def __init__(
        self,
        title: str,
        value: str = "0",
        subtitle: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", "card")
        self.setObjectName("statCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        self._lbl_title = QLabel(title.upper())
        self._lbl_title.setProperty("class", "stat-label")
        self._lbl_title.setStyleSheet("font-weight: 600; font-size: 11px; letter-spacing: 0.5px;")

        self._lbl_value = QLabel(value)
        self._lbl_value.setProperty("class", "stat-value")

        layout.addWidget(self._lbl_title)
        layout.addWidget(self._lbl_value)

        if subtitle:
            self._lbl_subtitle = QLabel(subtitle)
            self._lbl_subtitle.setStyleSheet("color: #6c7086; font-size: 11px;")
            self._lbl_subtitle.setWordWrap(True)
            layout.addWidget(self._lbl_subtitle)
        else:
            self._lbl_subtitle = None

        layout.addStretch()

    def set_value(self, value: str) -> None:
        """Update displayed stat value."""
        self._lbl_value.setText(value)

    def set_subtitle(self, subtitle: str) -> None:
        """Update subtitle text."""
        if self._lbl_subtitle:
            self._lbl_subtitle.setText(subtitle)
