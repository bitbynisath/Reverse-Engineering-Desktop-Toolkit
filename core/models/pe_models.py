"""Data models for Windows Portable Executable (PE) analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class PEHeaderInfo:
    """Header metadata for DOS, COFF, and Optional Headers."""

    format_type: str  # "PE32" or "PE32+"
    machine: str
    machine_hex: str
    number_of_sections: int
    timestamp: int
    timestamp_iso: str
    timestamp_note: str
    entry_point_rva: int
    entry_point_hex: str
    image_base: int
    image_base_hex: str
    subsystem: str
    subsystem_version: str
    os_version: str
    characteristics: list[str]
    dll_characteristics: list[str]
    checksum: str
    is_pe64: bool
    is_dll: bool
    is_driver: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PESectionInfo:
    """Structure and security characteristics of a PE section."""

    name: str
    virtual_address: int
    virtual_address_hex: str
    virtual_size: int
    raw_size: int
    raw_data_offset: int
    raw_data_offset_hex: str
    entropy: float
    characteristics_hex: str
    permissions: str  # "R--", "R-X", "RW-", "RWX"
    flags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ImportedSymbol:
    """An imported function or symbol with ordinal / name resolution."""

    name: str | None
    ordinal: int | None
    address_rva: int
    address_rva_hex: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ImportedLibrary:
    """A dynamically linked library (DLL) and its imported symbols."""

    name: str
    symbols: list[ImportedSymbol]

    @property
    def symbol_count(self) -> int:
        return len(self.symbols)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "symbol_count": self.symbol_count,
            "symbols": [s.to_dict() for s in self.symbols],
        }


@dataclass(frozen=True)
class ExportedSymbol:
    """A symbol exported by the PE executable or dynamic link library."""

    name: str | None
    ordinal: int
    address_rva: int
    address_rva_hex: str
    forwarder: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResourceSummary:
    """Summary of PE resources (icons, manifests, dialogs, version)."""

    total_resources: int
    type_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DebugDirectoryEntry:
    """Metadata extracted from the PE Debug Directory."""

    type_name: str
    timestamp_iso: str
    guid: str | None = None
    pdb_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CertificateInfo:
    """Authenticode digital signature / security directory metadata."""

    has_certificate: bool
    certificate_type: str = "None"
    length: int = 0
    revision: str = "None"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PEAnalysisResult:
    """Comprehensive static Windows PE analysis result."""

    header: PEHeaderInfo
    sections: list[PESectionInfo]
    imports: list[ImportedLibrary]
    exports: list[ExportedSymbol]
    resources: ResourceSummary
    debug_entries: list[DebugDirectoryEntry]
    certificate: CertificateInfo
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "sections": [s.to_dict() for s in self.sections],
            "imports": [lib.to_dict() for lib in self.imports],
            "exports": [exp.to_dict() for exp in self.exports],
            "resources": self.resources.to_dict(),
            "debug_entries": [dbg.to_dict() for dbg in self.debug_entries],
            "certificate": self.certificate.to_dict(),
            "warnings": self.warnings,
        }
