"""Data models for hexadecimal binary viewing and byte inspection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class HexRow:
    """A formatted row of hexadecimal data."""

    offset: int
    offset_hex: str
    data: bytes
    hex_representation: str
    ascii_representation: str
    is_partial: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "offset_hex": self.offset_hex,
            "hex_representation": self.hex_representation,
            "ascii_representation": self.ascii_representation,
            "byte_count": len(self.data),
            "is_partial": self.is_partial,
        }


@dataclass(frozen=True)
class ByteSelection:
    """Detailed structural interpretation of a selected byte at a given offset."""

    offset: int
    offset_hex: str
    byte_value: int  # 0 - 255
    byte_hex: str    # e.g. "0x4D"
    byte_bin: str    # e.g. "01001101"
    byte_char: str   # printable ASCII char or "."
    signed_int8: int
    uint16_le: int | None = None
    uint32_le: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HexSearchResult:
    """Match result for a byte or text search operation."""

    offset: int
    offset_hex: str
    length: int
    query: str
    pattern_type: str  # "hex" or "text"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
