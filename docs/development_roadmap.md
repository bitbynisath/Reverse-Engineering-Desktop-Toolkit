# PyRE Studio Development Roadmap

This document tracks the phased implementation gates of PyRE Studio. Each phase must be completed, tested, and documented before the next phase begins.

---

## Phase Status Summary

| Phase | Title | Status | Gate Completion Criteria |
| :---: | :--- | :---: | :--- |
| **0** | Project Planning & Environment | **COMPLETED** | Python 3.12+ confirmed, virtual environment, gitignore, pyproject.toml established. |
| **1** | Desktop Application Foundation | **COMPLETED** | PySide6 shell, sidebar navigation, dashboard, dark/light themes, settings. |
| **2** | File Analysis Engine | **COMPLETED** | Metadata, magic byte signatures, chunked hashing (MD5/SHA1/SHA256/SHA512), extension mismatch detection, JSON export. |
| **3** | Hexadecimal Viewer | **COMPLETED** | Memory-bounded reads, mmap streaming, paged hex/ASCII table, go-to-offset, hex/text pattern search, interactive byte inspector. |
| **4** | String Extraction | **COMPLETED** | Printable ASCII, UTF-16LE, and UTF-8 extraction, offset tracking, real-time filtering, TXT/CSV export. |
| **5** | Windows PE Analysis | **COMPLETED** | DOS/PE headers, sections, imports (IAT), exports (EAT), resources, debug directories, Authenticode certificate metadata, 75/75 tests passing. |
| **6** | Capstone Disassembly | **READY TO START** | Static x86 / x86-64 machine code disassembly and instruction mapping. |
| **7** | Python Bytecode Analysis | PENDING | .pyc header inspection, code objects, names, constants, and dis disassembly. |
| **8** | Advanced Analyzers | PENDING | ELF, APK, Mach-O, Shannon entropy visualization, YARA pattern scanning. |
| **9** | Reports & History | PENDING | SQLite session database, history search, JSON/CSV/HTML/PDF reporting. |
| **10** | Release & Packaging | PENDING | Full test suite, Windows standalone PyInstaller executable packaging. |

---

## Phase 5 Acceptance Verification

- [x] Integration with `pefile` library for robust static inspection of Portable Executables.
- [x] Parsing of DOS Header, COFF File Header, and Optional Header (PE32 vs PE32+).
- [x] Machine architecture detection (x86, x86-64, ARM, ARM64) and Subsystem identification (GUI, CUI, Native, POSIX).
- [x] Compilation timestamp parsing accompanied by clear warnings regarding timestamp spoofing/hash reproducibility.
- [x] DLL characteristics inspection (ASLR / HighEntropyVA, DEP / NX_COMPAT, SafeSEH, ControlFlowGuard).
- [x] Section Table analysis: Virtual Address, Virtual Size, Raw Size, Raw Offset, Permissions (R/W/X), Characteristics flags, and Shannon Entropy (0.0 to 8.0).
- [x] Detection of anomalies: RWX permissions and high-entropy executable sections suggesting packing/encryption.
- [x] Import Table (IAT) resolution: listing imported dynamic libraries and symbols/ordinals with instant search filtering.
- [x] Export Table (EAT) resolution: listing exported functions, ordinals, RVAs, and forwarders with instant search filtering.
- [x] Resource Directory breakdown, Debug Directory CodeView PDB extraction, and Authenticode Digital Signature metadata.
- [x] Non-blocking background worker (`PEWorker` on `QThread`) with graceful handling of corrupted or non-PE binaries.
- [x] Comprehensive test suite with 75 passing unit and integration tests including programmatic PE fixtures.
