"""Windows Portable Executable (PE) static analysis engine."""

from __future__ import annotations

import datetime
import logging
import math
from pathlib import Path
from typing import Any

from core.exceptions import AnalysisError, ConfigurationError, UnsupportedFormatError
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
from core.validators import validate_file_path

logger = logging.getLogger(__name__)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte stream (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    for count in occurrences:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_pe(file_path: str | Path) -> PEAnalysisResult:
    """Perform deep static analysis of a Windows PE binary (EXE, DLL, SYS).

    Safely inspects structures without executing the binary.
    """
    path = validate_file_path(file_path)

    try:
        import pefile
    except ImportError as exc:
        raise ConfigurationError("pefile library is required for PE analysis. Install via pip install pefile.") from exc

    # Quick check for MZ signature before parsing
    with path.open("rb") as f:
        magic = f.read(2)
        if magic != b"MZ":
            raise UnsupportedFormatError(
                f"File '{path.name}' is not a valid Windows executable (missing MZ signature)."
            )

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        raise UnsupportedFormatError(f"Corrupted or malformed PE format in '{path.name}': {exc}") from exc
    except Exception as exc:
        raise AnalysisError(f"Unexpected error parsing PE structure: {exc}") from exc

    warnings: list[str] = []

    # 1. Headers Inspection
    coff = pe.FILE_HEADER
    opt = pe.OPTIONAL_HEADER if hasattr(pe, "OPTIONAL_HEADER") else None

    # Magic / Format
    is_pe64 = False
    format_type = "PE32"
    if opt is not None:
        is_pe64 = (opt.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS)
        format_type = "PE32+ (64-bit)" if is_pe64 else "PE32 (32-bit)"

    # Machine Architecture
    machine_val = coff.Machine
    machine_name = pefile.MACHINE_TYPE.get(machine_val, f"UNKNOWN (0x{machine_val:04X})")

    # Timestamp
    ts_val = coff.TimeDateStamp
    try:
        ts_iso = datetime.datetime.fromtimestamp(ts_val, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        ts_iso = f"Invalid timestamp value ({ts_val})"
    ts_note = "PE timestamps can be arbitrary, zeroed, forged, or reproducible build hashes."

    # Characteristics flags
    char_flags: list[str] = []
    for flag, bit in pefile.IMAGE_CHARACTERISTICS:
        if coff.Characteristics & bit:
            char_flags.append(flag)

    is_dll = bool(coff.Characteristics & 0x2000)
    is_driver = bool(coff.Characteristics & 0x1000)

    # Optional Header attributes
    entry_point = opt.AddressOfEntryPoint if opt else 0
    image_base = opt.ImageBase if opt else 0
    subsys_val = opt.Subsystem if opt else 0
    subsystem_str = pefile.SUBSYSTEM_TYPE.get(subsys_val, f"UNKNOWN ({subsys_val})")

    os_ver = f"{opt.MajorOperatingSystemVersion}.{opt.MinorOperatingSystemVersion}" if opt else "N/A"
    subsys_ver = f"{opt.MajorSubsystemVersion}.{opt.MinorSubsystemVersion}" if opt else "N/A"
    checksum_str = f"0x{opt.CheckSum:08X}" if opt else "N/A"

    dll_char_flags: list[str] = []
    if opt and hasattr(opt, "DllCharacteristics"):
        for flag, bit in pefile.DLL_CHARACTERISTICS:
            if opt.DllCharacteristics & bit:
                dll_char_flags.append(flag)

    header_info = PEHeaderInfo(
        format_type=format_type,
        machine=machine_name,
        machine_hex=f"0x{machine_val:04X}",
        number_of_sections=coff.NumberOfSections,
        timestamp=ts_val,
        timestamp_iso=ts_iso,
        timestamp_note=ts_note,
        entry_point_rva=entry_point,
        entry_point_hex=f"0x{entry_point:08X}",
        image_base=image_base,
        image_base_hex=f"0x{image_base:016X}" if is_pe64 else f"0x{image_base:08X}",
        subsystem=subsystem_str,
        subsystem_version=subsys_ver,
        os_version=os_ver,
        characteristics=char_flags,
        dll_characteristics=dll_char_flags,
        checksum=checksum_str,
        is_pe64=is_pe64,
        is_dll=is_dll,
        is_driver=is_driver,
    )

    # 2. Sections Table Inspection
    sections_list: list[PESectionInfo] = []
    for sec in pe.sections:
        # Decode section name
        raw_name = sec.Name.rstrip(b"\x00")
        try:
            sec_name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            sec_name = raw_name.decode("latin1", errors="replace")

        # Characteristics & Permissions
        char = sec.Characteristics
        r = "R" if (char & 0x40000000) else "-"
        w = "W" if (char & 0x80000000) else "-"
        x = "X" if (char & 0x20000000) else "-"
        perms = f"{r}{w}{x}"

        # Section Entropy
        sec_data = sec.get_data()
        entropy = calculate_entropy(sec_data)

        # Flag warnings for suspicious permissions or packed sections
        if perms == "RWX":
            warnings.append(f"Security Alert: Section '{sec_name}' has RWX (Read/Write/Execute) permissions.")
        if "X" in perms and entropy > 7.2:
            warnings.append(
                f"Notice: Executable section '{sec_name}' has high entropy ({entropy:.2f}), suggesting packing or encryption."
            )

        # Extract flags
        sec_flags: list[str] = []
        for flag, bit in pefile.SECTION_CHARACTERISTICS:
            if char & bit:
                sec_flags.append(flag)

        sections_list.append(
            PESectionInfo(
                name=sec_name,
                virtual_address=sec.VirtualAddress,
                virtual_address_hex=f"0x{sec.VirtualAddress:08X}",
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                raw_data_offset=sec.PointerToRawData,
                raw_data_offset_hex=f"0x{sec.PointerToRawData:08X}",
                entropy=entropy,
                characteristics_hex=f"0x{char:08X}",
                permissions=perms,
                flags=sec_flags,
            )
        )

    # 3. Import Table (IAT) Inspection
    imported_libs: list[ImportedLibrary] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "Unknown DLL"
            symbols: list[ImportedSymbol] = []

            for imp in entry.imports:
                sym_name = imp.name.decode("utf-8", errors="replace") if imp.name else None
                symbols.append(
                    ImportedSymbol(
                        name=sym_name,
                        ordinal=imp.ordinal,
                        address_rva=imp.address if hasattr(imp, "address") else 0,
                        address_rva_hex=f"0x{imp.address:08X}" if hasattr(imp, "address") else "0x00000000",
                    )
                )

            imported_libs.append(ImportedLibrary(name=dll_name, symbols=symbols))

    # 4. Export Table (EAT) Inspection
    exported_symbols: list[ExportedSymbol] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode("utf-8", errors="replace") if exp.name else None
            forwarder_str = exp.forwarder.decode("utf-8", errors="replace") if hasattr(exp, "forwarder") and exp.forwarder else None
            exported_symbols.append(
                ExportedSymbol(
                    name=exp_name,
                    ordinal=exp.ordinal,
                    address_rva=exp.address,
                    address_rva_hex=f"0x{exp.address:08X}",
                    forwarder=forwarder_str,
                )
            )

    # 5. Resource Directory Summary
    res_summary = ResourceSummary(total_resources=0, type_counts={})
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        type_counts: dict[str, int] = {}
        total_res = 0

        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(res_type, "name") and res_type.name:
                t_name = str(res_type.name)
            elif hasattr(res_type, "id"):
                t_name = pefile.RESOURCE_TYPE.get(res_type.id, f"RT_{res_type.id}")
            else:
                t_name = "Unknown"

            count = len(res_type.directory.entries) if hasattr(res_type, "directory") else 0
            type_counts[t_name] = count
            total_res += count

        res_summary = ResourceSummary(total_resources=total_res, type_counts=type_counts)

    # 6. Debug Directory Inspection
    debug_entries: list[DebugDirectoryEntry] = []
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            type_val = dbg.struct.Type
            type_name = pefile.DEBUG_TYPE.get(type_val, f"UNKNOWN ({type_val})")

            dbg_ts = dbg.struct.TimeDateStamp
            try:
                dbg_ts_iso = datetime.datetime.fromtimestamp(dbg_ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                dbg_ts_iso = "N/A"

            pdb_path = None
            guid_str = None

            if hasattr(dbg, "entry") and dbg.entry:
                cv = dbg.entry
                if hasattr(cv, "PdbFileName"):
                    pdb_path = cv.PdbFileName.decode("utf-8", errors="replace").rstrip("\x00")
                if hasattr(cv, "Signature"):
                    guid_str = str(cv.Signature)

            debug_entries.append(
                DebugDirectoryEntry(
                    type_name=type_name,
                    timestamp_iso=dbg_ts_iso,
                    guid=guid_str,
                    pdb_path=pdb_path,
                )
            )

    # 7. Certificate / Security Directory Inspection
    cert_info = CertificateInfo(has_certificate=False)
    if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        sec_dir_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
            if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                cert_info = CertificateInfo(
                    has_certificate=True,
                    certificate_type="PKCS#7 Authenticode",
                    length=sec_dir.Size,
                    revision="WIN_CERT_REVISION_2_0",
                )

    # Close PE handle
    pe.close()

    return PEAnalysisResult(
        header=header_info,
        sections=sections_list,
        imports=imported_libs,
        exports=exported_symbols,
        resources=res_summary,
        debug_entries=debug_entries,
        certificate=cert_info,
        warnings=warnings,
    )
