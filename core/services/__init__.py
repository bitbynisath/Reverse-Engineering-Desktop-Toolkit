"""Core analysis and file services."""

from core.services.analysis_service import analyze_file, export_analysis_to_json
from core.services.binary_reader import BinaryReader
from core.services.file_detection_service import (
    compare_extension_and_signature,
    detect_file_signature,
)
from core.services.file_service import (
    format_file_size,
    format_hex_and_ascii,
    format_permissions,
    get_file_metadata,
    read_header_bytes,
)
from core.services.hashing_service import calculate_hashes
from core.services.hex_service import (
    calculate_total_pages,
    format_hex_row,
    get_hex_page,
    inspect_byte,
    offset_to_page,
    parse_hex_pattern,
)

__all__ = [
    "analyze_file",
    "export_analysis_to_json",
    "calculate_hashes",
    "detect_file_signature",
    "compare_extension_and_signature",
    "get_file_metadata",
    "read_header_bytes",
    "format_hex_and_ascii",
    "format_file_size",
    "format_permissions",
    "BinaryReader",
    "parse_hex_pattern",
    "format_hex_row",
    "calculate_total_pages",
    "offset_to_page",
    "get_hex_page",
    "inspect_byte",
]
