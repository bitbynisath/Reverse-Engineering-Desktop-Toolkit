"""Application Settings Page."""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import AppConfig, save_config
from app.constants import (
    DEFAULT_HEX_BYTES_PER_ROW,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MIN_STRING_LEN,
    DEFAULT_THEME,
    PAGE_SETTINGS,
    THEME_DARK,
    THEME_LIGHT,
)
from core.dependency_checker import get_all_dependencies_status

logger = logging.getLogger(__name__)


class SettingsPage(QWidget):
    """Configuration and environment settings screen."""

    theme_changed = Signal(str)

    def __init__(self, config: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.module_id = PAGE_SETTINGS
        self._config = config

        self._init_ui()
        self._load_values()

    def _init_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)

        # Header
        lbl_title = QLabel("Application Settings")
        lbl_title.setProperty("class", "page-title")
        lbl_desc = QLabel("Configure PyRE Studio appearance, analysis limits, and execution preferences.")
        lbl_desc.setProperty("class", "page-subtitle")
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_desc)

        # Appearance Card
        app_card = QFrame()
        app_card.setProperty("class", "card")
        app_layout = QVBoxLayout(app_card)
        app_layout.setSpacing(12)

        lbl_app_hdr = QLabel("Appearance & Display")
        lbl_app_hdr.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        app_layout.addWidget(lbl_app_hdr)

        grid_app = QGridLayout()
        grid_app.setHorizontalSpacing(16)
        grid_app.setVerticalSpacing(10)

        grid_app.addWidget(QLabel("Interface Theme:"), 0, 0)
        self._combo_theme = QComboBox()
        self._combo_theme.addItems(["Dark (Default)", "Light"])
        self._combo_theme.currentIndexChanged.connect(self._on_theme_changed)
        grid_app.addWidget(self._combo_theme, 0, 1)

        grid_app.addWidget(QLabel("Hex Bytes per Row:"), 1, 0)
        self._spin_hex_bytes = QSpinBox()
        self._spin_hex_bytes.setRange(8, 32)
        self._spin_hex_bytes.setSingleStep(8)
        grid_app.addWidget(self._spin_hex_bytes, 1, 1)

        app_layout.addLayout(grid_app)
        layout.addWidget(app_card)

        # Analysis Defaults Card
        analysis_card = QFrame()
        analysis_card.setProperty("class", "card")
        analysis_layout = QVBoxLayout(analysis_card)
        analysis_layout.setSpacing(12)

        lbl_an_hdr = QLabel("Analysis Thresholds & Directories")
        lbl_an_hdr.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        analysis_layout.addWidget(lbl_an_hdr)

        grid_an = QGridLayout()
        grid_an.setHorizontalSpacing(16)
        grid_an.setVerticalSpacing(10)

        grid_an.addWidget(QLabel("Default Analysis Directory:"), 0, 0)
        dir_row = QHBoxLayout()
        self._lbl_default_dir = QLabel()
        self._lbl_default_dir.setStyleSheet("color: #a6adc8; font-style: italic;")
        btn_browse_dir = QPushButton("Browse...")
        btn_browse_dir.clicked.connect(self._on_browse_dir)
        dir_row.addWidget(self._lbl_default_dir, 1)
        dir_row.addWidget(btn_browse_dir)
        grid_an.addLayout(dir_row, 0, 1)

        grid_an.addWidget(QLabel("Min String Extraction Length:"), 1, 0)
        self._spin_min_string = QSpinBox()
        self._spin_min_string.setRange(3, 32)
        grid_an.addWidget(self._spin_min_string, 1, 1)

        grid_an.addWidget(QLabel("Max File Size Warning (MB):"), 2, 0)
        self._spin_max_file_size = QSpinBox()
        self._spin_max_file_size.setRange(10, 2048)
        self._spin_max_file_size.setSingleStep(50)
        grid_an.addWidget(self._spin_max_file_size, 2, 1)

        grid_an.addWidget(QLabel("Logging Level:"), 3, 0)
        self._combo_log_level = QComboBox()
        self._combo_log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        grid_an.addWidget(self._combo_log_level, 3, 1)

        analysis_layout.addLayout(grid_an)
        layout.addWidget(analysis_card)

        # Dependency Inspection Card
        dep_card = QFrame()
        dep_card.setProperty("class", "card")
        dep_layout = QVBoxLayout(dep_card)
        dep_layout.setSpacing(10)

        lbl_dep_hdr = QLabel("Environment & Optional Dependencies")
        lbl_dep_hdr.setStyleSheet("font-weight: 600; font-size: 14px; color: #cdd6f4;")
        dep_layout.addWidget(lbl_dep_hdr)

        self._dep_table = QTableWidget()
        self._dep_table.setColumnCount(5)
        self._dep_table.setHorizontalHeaderLabels(
            ["Package", "Required", "Status", "Version", "Target Phase"]
        )
        self._dep_table.horizontalHeader().setStretchLastSection(True)
        self._dep_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._dep_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._populate_dependencies()
        dep_layout.addWidget(self._dep_table)

        layout.addWidget(dep_card)

        # Action Buttons
        btn_row = QHBoxLayout()
        self._btn_save = QPushButton("Save Preferences")
        self._btn_save.setProperty("class", "primary-btn")
        self._btn_save.clicked.connect(self._on_save_preferences)

        self._btn_reset = QPushButton("Reset Defaults")
        self._btn_reset.clicked.connect(self._on_reset_defaults)

        btn_row.addWidget(self._btn_save)
        btn_row.addWidget(self._btn_reset)
        btn_row.addStretch()

        layout.addLayout(btn_row)
        layout.addStretch()

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.addWidget(scroll)
        scroll.setWidget(container)

    def _load_values(self) -> None:
        """Load settings from current AppConfig instance."""
        theme_idx = 0 if self._config.theme.lower() == THEME_DARK else 1
        self._combo_theme.setCurrentIndex(theme_idx)
        self._spin_hex_bytes.setValue(self._config.hex_bytes_per_row)
        self._lbl_default_dir.setText(self._config.default_analysis_dir)
        self._spin_min_string.setValue(self._config.min_string_len)
        self._spin_max_file_size.setValue(self._config.max_file_size_mb)

        log_idx = self._combo_log_level.findText(self._config.log_level)
        if log_idx >= 0:
            self._combo_log_level.setCurrentIndex(log_idx)

    def _populate_dependencies(self) -> None:
        """Populate the dependency status table."""
        deps = get_all_dependencies_status()
        self._dep_table.setRowCount(len(deps))

        for row, dep in enumerate(deps):
            self._dep_table.setItem(row, 0, QTableWidgetItem(dep.name))
            self._dep_table.setItem(row, 1, QTableWidgetItem("Yes" if dep.required else "Optional"))

            status_str = "Installed" if dep.installed else "Not Installed"
            status_item = QTableWidgetItem(status_str)
            if dep.installed:
                status_item.setForeground(Qt.green)
            else:
                status_item.setForeground(Qt.yellow if not dep.required else Qt.red)
            self._dep_table.setItem(row, 2, status_item)

            ver_str = dep.version or "---"
            self._dep_table.setItem(row, 3, QTableWidgetItem(ver_str))
            self._dep_table.setItem(row, 4, QTableWidgetItem(f"{dep.target_phase} - {dep.description}"))

        self._dep_table.resizeColumnsToContents()

    def _on_theme_changed(self, index: int) -> None:
        new_theme = THEME_DARK if index == 0 else THEME_LIGHT
        self.theme_changed.emit(new_theme)

    def _on_browse_dir(self) -> None:
        selected_dir = QFileDialog.getExistingDirectory(
            self, "Select Default Analysis Directory", self._lbl_default_dir.text()
        )
        if selected_dir:
            self._lbl_default_dir.setText(selected_dir)

    def _on_save_preferences(self) -> None:
        self._config.theme = THEME_DARK if self._combo_theme.currentIndex() == 0 else THEME_LIGHT
        self._config.hex_bytes_per_row = self._spin_hex_bytes.value()
        self._config.default_analysis_dir = self._lbl_default_dir.text()
        self._config.min_string_len = self._spin_min_string.value()
        self._config.max_file_size_mb = self._spin_max_file_size.value()
        self._config.log_level = self._combo_log_level.currentText()

        saved = save_config(self._config)
        if saved:
            QMessageBox.information(self, "Settings Saved", "Preferences have been saved successfully.")
        else:
            QMessageBox.warning(self, "Save Error", "Could not write configuration to disk.")

    def _on_reset_defaults(self) -> None:
        res = QMessageBox.question(
            self,
            "Reset Preferences",
            "Are you sure you want to restore all settings to default values?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if res == QMessageBox.Yes:
            self._config.theme = DEFAULT_THEME
            self._config.default_analysis_dir = str(Path.home())
            self._config.hex_bytes_per_row = DEFAULT_HEX_BYTES_PER_ROW
            self._config.min_string_len = DEFAULT_MIN_STRING_LEN
            self._config.max_file_size_mb = DEFAULT_MAX_FILE_SIZE_MB
            self._config.log_level = DEFAULT_LOG_LEVEL
            self._load_values()
            save_config(self._config)
            self.theme_changed.emit(self._config.theme)
            QMessageBox.information(self, "Preferences Reset", "Settings have been restored to defaults.")
