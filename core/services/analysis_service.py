"""Unified static file analysis service."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

from core.exceptions import FileAccessError, ValidationError
from core.models.file_models import FileAnalysisResult
from core.services.file_detection_service import (
    compare_extension_and_signature,
    detect_file_signature,
)
from core.services.file_service import (
    format_hex_and_ascii,
    get_file_metadata,
    read_header_bytes,
)
from core.services.hashing_service import calculate_hashes
from core.validators import validate_file_path

logger = logging.getLogger(__name__)


def analyze_file(
    file_path: str | Path,
    max_size_mb: int = 100,
    progress_callback: Callable[[int, int], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> FileAnalysisResult:
    """Perform comprehensive static analysis on the specified target file.

    Guaranteed read-only and static; never executes target files.
    """
    path = validate_file_path(file_path)
    warnings: list[str] = []

    # 1. Metadata
    metadata = get_file_metadata(path)
    if metadata.is_empty:
        warnings.append("Notice: File is 0 bytes (empty file).")

    max_bytes = max_size_mb * 1024 * 1024
    if metadata.size_bytes > max_bytes:
        warnings.append(
            f"Warning: File size ({metadata.human_size}) exceeds the warning threshold of {max_size_mb} MB."
        )

    # 2. Header and Magic Bytes
    header_bytes = read_header_bytes(path, length=64)
    magic_hex, magic_ascii = format_hex_and_ascii(header_bytes[:32])

    # 3. Signature & Extension Matching
    signature = detect_file_signature(header_bytes, path)
    matches_ext, comp_msg = compare_extension_and_signature(metadata.extension, signature)
    if not matches_ext:
        warnings.append(comp_msg)

    # 4. Hashes (chunked)
    hashes = calculate_hashes(
        path,
        progress_callback=progress_callback,
        is_cancelled=is_cancelled,
    )

    result = FileAnalysisResult(
        metadata=metadata,
        signature=signature,
        hashes=hashes,
        extension_matches_signature=matches_ext,
        extension_comparison_message=comp_msg,
        magic_preview_hex=magic_hex,
        magic_preview_ascii=magic_ascii,
        warnings=warnings,
    )

    logger.info("Analyzed '%s': %s (%s)", path.name, signature.name if signature else "Unknown", hashes.sha256[:12])
    return result


def export_analysis_to_json(result: FileAnalysisResult, export_path: Path) -> bool:
    """Serialize file analysis results into a formatted JSON report."""
    try:
        export_path.parent.mkdir(parents=True, exist_ok=True)
        data = result.to_dict()
        export_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Exported analysis report to JSON: %s", export_path)
        return True
    except Exception as exc:
        logger.error("Failed to export analysis JSON to %s: %s", export_path, exc)
        return False
