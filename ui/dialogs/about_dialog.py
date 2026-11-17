"""About Dialog for PyRE Studio."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
)

from app.constants import (
    APP_NAME,
    APP_SUBTITLE,
    APP_VERSION,
    DISCLAIMER_TEXT,
)


class AboutDialog(QDialog):
    """About dialog showing application identity, credits, and legal disclaimer."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setFixedSize(520, 440)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 20)
        layout.setSpacing(16)

        # Header
        hdr_layout = QVBoxLayout()
        hdr_layout.setSpacing(4)

        lbl_name = QLabel(f"{APP_NAME} <span style='font-size: 13px; color: #89b4fa;'>v{APP_VERSION}</span>")
        lbl_name.setStyleSheet("font-size: 20px; font-weight: 700; color: #cdd6f4;")
        lbl_sub = QLabel(APP_SUBTITLE)
        lbl_sub.setStyleSheet("font-size: 12px; color: #a6adc8;")

        hdr_layout.addWidget(lbl_name)
        hdr_layout.addWidget(lbl_sub)
        layout.addLayout(hdr_layout)

        # Content Card
        card = QFrame()
        card.setProperty("class", "card")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(10)

        desc_lbl = QLabel(
            "PyRE Studio is an extensible, modular reverse engineering and binary analysis "
            "desktop environment written in Python and PySide6."
        )
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color: #cdd6f4; font-size: 12px;")
        card_layout.addWidget(desc_lbl)

        disc_title = QLabel("Security Policy & Safe Operation:")
        disc_title.setStyleSheet("font-weight: 600; color: #f9e2af; font-size: 11px;")
        card_layout.addWidget(disc_title)

        disc_lbl = QLabel(DISCLAIMER_TEXT)
        disc_lbl.setWordWrap(True)
        disc_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; line-height: 1.4;")
        card_layout.addWidget(disc_lbl)

        layout.addWidget(card)

        # Details
        py_ver = sys.version.split()[0]
        details_lbl = QLabel(
            f"<b>Runtime:</b> Python {py_ver} &bull; PySide6 (Qt 6)<br>"
            f"<b>License:</b> Apache-2.0 License<br>"
            f"<b>Target OS:</b> Windows 10 / 11 (Cross-platform ready)"
        )
        details_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; line-height: 1.5;")
        layout.addWidget(details_lbl)

        layout.addStretch()

        # Dialog Buttons
        btns = QDialogButtonBox(QDialogButtonBox.Ok)
        btns.accepted.connect(self.accept)
        layout.addWidget(btns)
