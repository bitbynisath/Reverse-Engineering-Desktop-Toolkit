"""Interactive Quick Action Card for Dashboard Navigation."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)


class QuickActionCard(QFrame):
    """Clickable dashboard card that triggers navigation to an analysis module."""

    clicked = Signal(str)

    def __init__(
        self,
        module_id: str,
        title: str,
        description: str,
        badge_text: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.module_id = module_id
        self.setProperty("class", "quick-action-card")
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)

        self._lbl_title = QLabel(title)
        self._lbl_title.setProperty("class", "section-header")

        header_layout.addWidget(self._lbl_title)
        header_layout.addStretch()

        if badge_text:
            self._lbl_badge = QLabel(badge_text)
            self._lbl_badge.setStyleSheet(
                "background-color: #313244; color: #89b4fa; padding: 2px 6px; "
                "border-radius: 4px; font-size: 10px; font-weight: 600;"
            )
            header_layout.addWidget(self._lbl_badge)

        self._lbl_desc = QLabel(description)
        self._lbl_desc.setWordWrap(True)
        self._lbl_desc.setStyleSheet("color: #a6adc8; font-size: 12px; line-height: 1.4;")

        layout.addLayout(header_layout)
        layout.addWidget(self._lbl_desc)
        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self._btn_open = QPushButton("Open →")
        self._btn_open.setCursor(Qt.PointingHandCursor)
        self._btn_open.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self._btn_open.clicked.connect(self._on_clicked)
        btn_layout.addWidget(self._btn_open)

        layout.addLayout(btn_layout)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.module_id)
        super().mousePressEvent(event)

    def _on_clicked(self) -> None:
        self.clicked.emit(self.module_id)
