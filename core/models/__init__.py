"""Core typed data models."""

from core.models.disasm_models import DisassembledInstruction, DisassemblyResult
from core.models.file_models import (
    FileAnalysisResult,
    FileMetadata,
    FileSignature,
    HashResults,
)
from core.models.hex_models import (
    ByteSelection,
    HexRow,
    HexSearchResult,
)
from core.models.pe_models import (
    CertificateInfo,
    DebugDirectoryEntry,
    ExportedSymbol,
    ImportedLibrary,
    ImportedSymbol,
    PEAnalysisResult,
    PEHeaderInfo,
    PESectionInfo,
    ResourceSummary,
)
from core.models.python_models import (
    CodeObjectSummary,
    PycHeaderInfo,
    PythonAnalysisResult,
    PythonInstruction,
)
from core.models.string_models import ExtractedString

# Backward compatibility alias
HashResult = HashResults

__all__ = [
    "FileMetadata",
    "FileSignature",
    "HashResults",
    "HashResult",
    "FileAnalysisResult",
    "HexRow",
    "ByteSelection",
    "HexSearchResult",
    "ExtractedString",
    "PEHeaderInfo",
    "PESectionInfo",
    "ImportedSymbol",
    "ImportedLibrary",
    "ExportedSymbol",
    "ResourceSummary",
    "DebugDirectoryEntry",
    "CertificateInfo",
    "PEAnalysisResult",
    "DisassembledInstruction",
    "DisassemblyResult",
    "PycHeaderInfo",
    "PythonInstruction",
    "CodeObjectSummary",
    "PythonAnalysisResult",
]
