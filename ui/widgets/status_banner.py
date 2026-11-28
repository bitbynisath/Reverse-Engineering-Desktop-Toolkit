"""Status and Notification Banner Component."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout


class StatusBanner(QFrame):
    """Informational, warning, or error banner with custom border accent."""

    def __init__(
        self,
        title: str = "",
        message: str = "",
        banner_type: str = "info",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", f"status-banner status-banner-{banner_type}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet("font-weight: 600; font-size: 13px; color: #cdd6f4;")
        self.lbl_title.setVisible(bool(title))
        layout.addWidget(self.lbl_title)

        self.lbl_message = QLabel(message)
        self.lbl_message.setWordWrap(True)
        self.lbl_message.setStyleSheet("font-size: 12px; color: #a6adc8;")
        layout.addWidget(self.lbl_message)

    def set_message(
        self,
        message: str,
        title: str | None = None,
        banner_type: str | None = None,
    ) -> None:
        """Update banner text and visual styling."""
        if title is not None:
            self.lbl_title.setText(title)
            self.lbl_title.setVisible(bool(title))

        self.lbl_message.setText(message)

        if banner_type:
            self.setProperty("class", f"status-banner status-banner-{banner_type}")
            self.style().unpolish(self)
            self.style().polish(self)

    def set_error(self, message: str, title: str = "Error") -> None:
        """Helper to show error banner."""
        self.set_message(message, title=title, banner_type="error")

    def set_warning(self, message: str, title: str = "Warning") -> None:
        """Helper to show warning banner."""
        self.set_message(message, title=title, banner_type="warning")

    def set_info(self, message: str, title: str = "Information") -> None:
        """Helper to show informational banner."""
        self.set_message(message, title=title, banner_type="info")
