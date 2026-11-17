"""Status and Notification Banner Component."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout


class StatusBanner(QFrame):
    """Informational, warning, or error banner with custom border accent."""

    def __init__(
        self,
        title: str,
        message: str,
        banner_type: str = "info",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", f"status-banner status-banner-{banner_type}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        if title:
            lbl_title = QLabel(title)
            lbl_title.setStyleSheet("font-weight: 600; font-size: 13px; color: #cdd6f4;")
            layout.addWidget(lbl_title)

        lbl_message = QLabel(message)
        lbl_message.setWordWrap(True)
        lbl_message.setStyleSheet("font-size: 12px; color: #a6adc8;")
        layout.addWidget(lbl_message)
