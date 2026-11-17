"""Reusable placeholder page for modules scheduled in subsequent phases."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


class PlaceholderPage(QWidget):
    """Page displaying transparent development status for upcoming modules."""

    def __init__(
        self,
        module_id: str,
        title: str,
        phase_label: str,
        description: str,
        planned_features: list[str] | None = None,
        dependencies: list[str] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.module_id = module_id

        # Root scroll area for resizability
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)

        # Header with title and phase badge
        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        lbl_title = QLabel(title)
        lbl_title.setProperty("class", "page-title")
        header_row.addWidget(lbl_title)

        lbl_badge = QLabel(f"Scheduled: {phase_label}")
        lbl_badge.setStyleSheet(
            "background-color: #313244; color: #89b4fa; padding: 4px 10px; "
            "border-radius: 4px; font-weight: 600; font-size: 11px;"
        )
        header_row.addWidget(lbl_badge)
        header_row.addStretch()

        layout.addLayout(header_row)

        lbl_desc = QLabel(description)
        lbl_desc.setWordWrap(True)
        lbl_desc.setProperty("class", "page-subtitle")
        layout.addWidget(lbl_desc)

        # Status Notice Card
        notice_card = QFrame()
        notice_card.setProperty("class", "card")
        notice_layout = QVBoxLayout(notice_card)
        notice_layout.setSpacing(8)

        notice_title = QLabel("Module Development Status")
        notice_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        notice_layout.addWidget(notice_title)

        notice_body = QLabel(
            f"This module is part of the PyRE Studio specification and is intentionally "
            f"scheduled for implementation in <b>{phase_label}</b>. PyRE Studio adheres to an "
            f"incremental development discipline—each phase is fully built, tested, and verified "
            f"before downstream modules are activated."
        )
        notice_body.setWordWrap(True)
        notice_body.setStyleSheet("color: #a6adc8; line-height: 1.5;")
        notice_layout.addWidget(notice_body)

        layout.addWidget(notice_card)

        # Planned Features Card
        if planned_features:
            features_card = QFrame()
            features_card.setProperty("class", "card")
            feat_layout = QVBoxLayout(features_card)
            feat_layout.setSpacing(8)

            feat_title = QLabel("Planned Capabilities")
            feat_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
            feat_layout.addWidget(feat_title)

            for feat in planned_features:
                item_lbl = QLabel(f"•  {feat}")
                item_lbl.setStyleSheet("color: #cdd6f4; font-size: 12px; margin-left: 4px;")
                feat_layout.addWidget(item_lbl)

            layout.addWidget(features_card)

        # Target Dependencies
        if dependencies:
            dep_card = QFrame()
            dep_card.setProperty("class", "card")
            dep_layout = QVBoxLayout(dep_card)
            dep_layout.setSpacing(6)

            dep_title = QLabel("Target Engine & Dependencies")
            dep_title.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
            dep_layout.addWidget(dep_title)

            for dep in dependencies:
                dep_lbl = QLabel(f"•  {dep}")
                dep_lbl.setStyleSheet("color: #a6adc8; font-size: 12px; margin-left: 4px;")
                dep_layout.addWidget(dep_lbl)

            layout.addWidget(dep_card)

        layout.addStretch()

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(scroll)
        scroll.setWidget(container)
