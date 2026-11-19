"""Binary signature matching and file format detection service."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import NamedTuple

from core.models.file_models import FileSignature


class SignatureRule(NamedTuple):
    name: str
    category: str
    mime_type: str
    offset: int
    magic: bytes
    expected_extensions: tuple[str, ...]
    description: str


# Common signatures database
SIGNATURE_RULES: list[SignatureRule] = [
    # Executable Formats
    SignatureRule(
        name="ELF Executable / Library",
        category="Executable",
        mime_type="application/x-executable",
        offset=0,
        magic=b"\x7fELF",
        expected_extensions=(".so", ".elf", ".bin", ".o", ".axf", ".prx"),
        description="Executable and Linkable Format (Linux / Unix binary or shared object).",
    ),
    SignatureRule(
        name="Mach-O 64-bit Binary (Little Endian)",
        category="Executable",
        mime_type="application/x-mach-binary",
        offset=0,
        magic=b"\xcf\xfa\xed\xfe",
        expected_extensions=(".dylib", ".macho", ""),
        description="macOS / iOS 64-bit executable or dylib binary.",
    ),
    SignatureRule(
        name="Mach-O 32-bit Binary (Little Endian)",
        category="Executable",
        mime_type="application/x-mach-binary",
        offset=0,
        magic=b"\xce\xfa\xed\xfe",
        expected_extensions=(".dylib", ".macho", ""),
        description="macOS / iOS 32-bit executable or dylib binary.",
    ),
    SignatureRule(
        name="Mach-O Universal / Fat Binary",
        category="Executable",
        mime_type="application/x-mach-binary",
        offset=0,
        magic=b"\xca\xfe\xba\xbe",
        expected_extensions=(".dylib", ".macho", ""),
        description="Apple Universal Multi-Architecture (Fat) Binary.",
    ),
    # Documents & Media
    SignatureRule(
        name="PDF Document",
        category="Document",
        mime_type="application/pdf",
        offset=0,
        magic=b"%PDF-",
        expected_extensions=(".pdf",),
        description="Adobe Portable Document Format.",
    ),
    SignatureRule(
        name="PNG Image",
        category="Image",
        mime_type="image/png",
        offset=0,
        magic=b"\x89PNG\r\n\x1a\n",
        expected_extensions=(".png",),
        description="Portable Network Graphics image.",
    ),
    SignatureRule(
        name="JPEG Image",
        category="Image",
        mime_type="image/jpeg",
        offset=0,
        magic=b"\xff\xd8\xff",
        expected_extensions=(".jpg", ".jpeg", ".jpe"),
        description="JPEG raster image.",
    ),
    SignatureRule(
        name="GIF Image",
        category="Image",
        mime_type="image/gif",
        offset=0,
        magic=b"GIF89a",
        expected_extensions=(".gif",),
        description="Graphics Interchange Format (GIF89a).",
    ),
    SignatureRule(
        name="GIF Image",
        category="Image",
        mime_type="image/gif",
        offset=0,
        magic=b"GIF87a",
        expected_extensions=(".gif",),
        description="Graphics Interchange Format (GIF87a).",
    ),
    SignatureRule(
        name="BMP Image",
        category="Image",
        mime_type="image/bmp",
        offset=0,
        magic=b"BM",
        expected_extensions=(".bmp", ".dib"),
        description="Windows Bitmap image.",
    ),
    # Archives & Packages
    SignatureRule(
        name="ZIP Archive / Package",
        category="Archive",
        mime_type="application/zip",
        offset=0,
        magic=b"PK\x03\x04",
        expected_extensions=(".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".whl"),
        description="ZIP compressed container or Open Packaging Convention package.",
    ),
    SignatureRule(
        name="7-Zip Archive",
        category="Archive",
        mime_type="application/x-7z-compressed",
        offset=0,
        magic=b"7z\xbc\xaf\x27\x1c",
        expected_extensions=(".7z",),
        description="7-Zip compressed archive.",
    ),
    SignatureRule(
        name="GZIP Archive",
        category="Archive",
        mime_type="application/gzip",
        offset=0,
        magic=b"\x1f\x8b",
        expected_extensions=(".gz", ".tgz"),
        description="Gnu ZIP compressed archive.",
    ),
    SignatureRule(
        name="BZIP2 Archive",
        category="Archive",
        mime_type="application/x-bzip2",
        offset=0,
        magic=b"BZh",
        expected_extensions=(".bz2", ".tbz2"),
        description="BZIP2 compressed archive.",
    ),
    SignatureRule(
        name="RAR Archive",
        category="Archive",
        mime_type="application/x-rar-compressed",
        offset=0,
        magic=b"Rar!\x1a\x07",
        expected_extensions=(".rar",),
        description="Roshal Archive compressed container.",
    ),
    # Scripts and text
    SignatureRule(
        name="Unix Script (Shebang)",
        category="Script",
        mime_type="text/x-shellscript",
        offset=0,
        magic=b"#!",
        expected_extensions=(".sh", ".bash", ".py", ".pl", ".rb", ""),
        description="Executable script beginning with interpreter shebang directive.",
    ),
    SignatureRule(
        name="XML Document",
        category="Document",
        mime_type="application/xml",
        offset=0,
        magic=b"<?xml",
        expected_extensions=(".xml", ".svg", ".plist", ".manifest"),
        description="Extensible Markup Language document.",
    ),
]


def detect_pe_format(header_bytes: bytes, file_path: Path | None = None) -> FileSignature | None:
    """Detect Windows Portable Executable (EXE, DLL, SYS) by inspecting DOS and PE signatures."""
    if len(header_bytes) < 2 or header_bytes[:2] != b"MZ":
        return None

    # Check e_lfanew offset at 0x3C if header buffer is large enough
    is_confirmed_pe = False
    if len(header_bytes) >= 0x40:
        (e_lfanew,) = struct.unpack_from("<I", header_bytes, 0x3C)
        if 0 < e_lfanew < 1024 * 1024:
            if len(header_bytes) >= e_lfanew + 4:
                pe_sig = header_bytes[e_lfanew : e_lfanew + 4]
                if pe_sig == b"PE\x00\x00":
                    is_confirmed_pe = True
            elif file_path and file_path.is_file():
                try:
                    with file_path.open("rb") as f:
                        f.seek(e_lfanew)
                        if f.read(4) == b"PE\x00\x00":
                            is_confirmed_pe = True
                except OSError:
                    pass

    if is_confirmed_pe:
        return FileSignature(
            name="Windows PE Executable / DLL",
            category="Executable",
            mime_type="application/vnd.microsoft.portable-executable",
            magic_hex="4D 5A ... 50 45 00 00",
            description="Windows Portable Executable binary (verified DOS and PE signature).",
            confidence="High",
        )

    return FileSignature(
        name="MS-DOS Executable (MZ)",
        category="Executable",
        mime_type="application/x-dosexec",
        magic_hex="4D 5A",
        description="Legacy MS-DOS executable or PE binary with unverified PE header offset.",
        confidence="Medium",
    )


def detect_python_bytecode(header_bytes: bytes) -> FileSignature | None:
    """Detect Python compiled bytecode (.pyc) from trailing carriage-return newline magic."""
    if len(header_bytes) >= 4 and header_bytes[2:4] == b"\r\n":
        magic_hex = " ".join(f"{b:02X}" for b in header_bytes[:4])
        return FileSignature(
            name="Python Compiled Bytecode (.pyc)",
            category="Bytecode",
            mime_type="application/x-python-code",
            magic_hex=magic_hex,
            description="Compiled Python bytecode containing interpreter magic number and timestamp/hash.",
            confidence="High",
        )
    return None


def detect_file_signature(header_bytes: bytes, file_path: Path | None = None) -> FileSignature | None:
    """Identify binary file type by evaluating known signature rules."""
    if not header_bytes:
        return None

    # 1. Check Windows PE / MZ
    pe_sig = detect_pe_format(header_bytes, file_path)
    if pe_sig:
        return pe_sig

    # 2. Check Python Bytecode
    pyc_sig = detect_python_bytecode(header_bytes)
    if pyc_sig:
        return pyc_sig

    # 3. Check General Signatures Table
    for rule in SIGNATURE_RULES:
        end = rule.offset + len(rule.magic)
        if len(header_bytes) >= end:
            if header_bytes[rule.offset : end] == rule.magic:
                return FileSignature(
                    name=rule.name,
                    category=rule.category,
                    mime_type=rule.mime_type,
                    magic_hex=" ".join(f"{b:02X}" for b in rule.magic),
                    description=rule.description,
                    confidence="High",
                )

    return None


def compare_extension_and_signature(
    extension: str,
    signature: FileSignature | None,
) -> tuple[bool, str]:
    """Compare declared file extension with detected content signature.

    Returns:
        (matches, message): A boolean match status and an explanatory message.
    """
    ext_clean = extension.lower().strip()

    if signature is None:
        if ext_clean:
            return True, f"Unidentified binary or text format with declared extension '{ext_clean}'."
        return True, "Unidentified binary format with no extension."

    # Look up rule in database
    for rule in SIGNATURE_RULES:
        if rule.name == signature.name:
            if ext_clean in rule.expected_extensions:
                return True, f"Declared extension '{ext_clean}' matches detected {signature.name} format."
            return (
                False,
                f"POTENTIAL MISMATCH: Declared extension '{ext_clean}' does not match detected "
                f"{signature.name} format (expected {', '.join(rule.expected_extensions) or 'none'}).",
            )

    # Special handling for PE
    if "Windows PE" in signature.name or "MS-DOS" in signature.name:
        pe_extensions = (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi", ".drv")
        if ext_clean in pe_extensions:
            return True, f"Declared extension '{ext_clean}' matches Windows PE Executable format."
        return (
            False,
            f"HIGH RISK MISMATCH: File contains Windows PE Executable signatures, but declared extension "
            f"is '{ext_clean or '[none]'}'. This may be an executable disguised as another file type.",
        )

    # Special handling for Python bytecode
    if "Python Compiled Bytecode" in signature.name:
        if ext_clean in (".pyc", ".pyo"):
            return True, f"Declared extension '{ext_clean}' matches Python bytecode format."
        return (
            False,
            f"MISMATCH: File contains Python bytecode signatures, but declared extension is '{ext_clean}'.",
        )

    return True, f"Declared extension '{ext_clean}' is consistent with detected format."
