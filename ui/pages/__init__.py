"""UI Pages package."""

from ui.pages.advanced_analysis_page import AdvancedAnalysisPage
from ui.pages.disassembler_page import DisassemblerPage
from ui.pages.file_analyzer_page import FileAnalyzerPage
from ui.pages.hex_viewer_page import HexViewerPage
from ui.pages.history_page import HistoryPage
from ui.pages.pe_analyzer_page import PEAnalyzerPage
from ui.pages.placeholder_page import PlaceholderPage
from ui.pages.python_analyzer_page import PythonAnalyzerPage
from ui.pages.reports_page import ReportsPage
from ui.pages.settings_page import SettingsPage
from ui.pages.string_extractor_page import StringExtractorPage

__all__ = [
    "PlaceholderPage",
    "FileAnalyzerPage",
    "HexViewerPage",
    "StringExtractorPage",
    "PEAnalyzerPage",
    "DisassemblerPage",
    "PythonAnalyzerPage",
    "AdvancedAnalysisPage",
    "ReportsPage",
    "HistoryPage",
    "SettingsPage",
]
