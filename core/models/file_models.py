"""Data models for file inspection, signatures, and hashing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FileMetadata:
    """Detailed filesystem metadata of an inspected file."""

    file_path: str
    file_name: str
    extension: str
    size_bytes: int
    human_size: str
    created_time: str
    modified_time: str
    accessed_time: str
    permissions: str
    is_readable: bool
    is_empty: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileSignature:
    """Identified binary or format signature."""

    name: str
    category: str
    mime_type: str
    magic_hex: str
    description: str
    confidence: str = "High"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HashResults:
    """Cryptographic hash digests calculated from file contents."""

    md5: str
    sha1: str
    sha256: str
    sha512: str = ""
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileAnalysisResult:
    """Comprehensive static file analysis outcome."""

    metadata: FileMetadata
    signature: FileSignature | None
    hashes: HashResults
    extension_matches_signature: bool
    extension_comparison_message: str
    magic_preview_hex: str
    magic_preview_ascii: str
    warnings: list[str] = field(default_factory=list)
    analysis_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "signature": self.signature.to_dict() if self.signature else None,
            "hashes": self.hashes.to_dict(),
            "extension_matches_signature": self.extension_matches_signature,
            "extension_comparison_message": self.extension_comparison_message,
            "magic_preview_hex": self.magic_preview_hex,
            "magic_preview_ascii": self.magic_preview_ascii,
            "warnings": self.warnings,
            "analysis_timestamp": self.analysis_timestamp,
        }

