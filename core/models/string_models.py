"""Data models for string extraction and classification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ExtractedString:
    """An individual string extracted from binary data with file offset and encoding."""

    offset: int
    offset_hex: str
    value: str
    encoding: str  # "ASCII", "UTF-16LE", "UTF-8"
    length: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
