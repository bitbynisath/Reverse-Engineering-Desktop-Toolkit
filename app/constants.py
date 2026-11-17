"""Application-wide constants for PyRE Studio."""

from pathlib import Path

# Application Metadata
APP_NAME = "PyRE Studio"
APP_SUBTITLE = "All-in-One Python Reverse Engineering Desktop Toolkit"
APP_VERSION = "0.1.0"
APP_ORGANIZATION = "PyRE-Studio"
APP_DOMAIN = "pyre-studio.local"

# Security & Nature of Analysis
DISCLAIMER_TEXT = (
    "PyRE Studio is an authorized static-analysis toolkit designed for security research, "
    "interoperability, debugging, and educational inspection. It operates strictly in a "
    "read-only mode and never executes analyzed target files."
)

# Navigation Page Identifiers
PAGE_DASHBOARD = "dashboard"
PAGE_FILE_ANALYZER = "file_analyzer"
PAGE_HEX_VIEWER = "hex_viewer"
PAGE_STRING_EXTRACTOR = "string_extractor"
PAGE_PE_ANALYZER = "pe_analyzer"
PAGE_DISASSEMBLER = "disassembler"
PAGE_PYTHON_ANALYZER = "python_analyzer"
PAGE_ADVANCED_ANALYSIS = "advanced_analysis"
PAGE_REPORTS = "reports"
PAGE_HISTORY = "history"
PAGE_SETTINGS = "settings"
PAGE_ABOUT = "about"

# Default File Constraints
DEFAULT_MAX_FILE_SIZE_MB = 100
DEFAULT_CHUNK_SIZE_BYTES = 64 * 1024  # 64 KB chunk size for hashes and reads
DEFAULT_HEX_BYTES_PER_ROW = 16
DEFAULT_MIN_STRING_LEN = 4

# Themes
THEME_DARK = "dark"
THEME_LIGHT = "light"
DEFAULT_THEME = THEME_DARK

# Log Configuration Defaults
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FILENAME = "pyre_studio.log"
