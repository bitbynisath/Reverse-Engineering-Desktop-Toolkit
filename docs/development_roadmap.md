# PyRE Studio Development Roadmap

This document tracks the phased implementation gates of PyRE Studio. Each phase must be completed, tested, and documented before the next phase begins.

---

## Phase Status Summary

| Phase | Title | Status | Gate Completion Criteria |
| :---: | :--- | :---: | :--- |
| **0** | Project Planning & Environment | **COMPLETED** | Python 3.12+ confirmed, virtual environment, gitignore, pyproject.toml established. |
| **1** | Desktop Application Foundation | **COMPLETED** | PySide6 shell, sidebar navigation, dashboard, dark/light themes, settings. |
| **2** | File Analysis Engine | **COMPLETED** | Metadata, magic byte signatures, chunked hashing (MD5/SHA1/SHA256/SHA512), extension mismatch detection, JSON export. |
| **3** | Hexadecimal Viewer | **COMPLETED** | Memory-bounded reads, mmap streaming, paged hex/ASCII table, go-to-offset, hex/text pattern search, interactive byte inspector, 56/56 tests passing. |
| **4** | String Extraction | **READY TO START** | ASCII, UTF-8, UTF-16LE extraction, filtering, offset tracking, CSV/TXT export. |
| **5** | Windows PE Analysis | PENDING | DOS/PE headers, sections, imports, exports, certificate metadata parsing. |
| **6** | Capstone Disassembly | PENDING | Static x86 / x86-64 machine code disassembly and instruction mapping. |
| **7** | Python Bytecode Analysis | PENDING | .pyc header inspection, code objects, names, constants, and dis disassembly. |
| **8** | Advanced Analyzers | PENDING | ELF, APK, Mach-O, Shannon entropy visualization, YARA pattern scanning. |
| **9** | Reports & History | PENDING | SQLite session database, history search, JSON/CSV/HTML/PDF reporting. |
| **10** | Release & Packaging | PENDING | Full test suite, Windows standalone PyInstaller executable packaging. |

---

## Phase 3 Acceptance Verification

- [x] Memory-bounded binary reads via `BinaryReader` using `mmap` with buffered stream fallback.
- [x] High-performance paged table viewing with custom configurable bytes per row (8, 16, 24, 32).
- [x] Three-column layout: Offset address (hex), hexadecimal byte tokens, and printable ASCII representation.
- [x] Paging controls (`<< First`, `< Prev`, Page SpinBox, `Next >`, `Last >>`).
- [x] Safe "Go to Offset" navigation accepting both hexadecimal (`0x...`) and decimal values with boundary checks.
- [x] Background asynchronous pattern search for raw hex sequences (`4D 5A ...`) and text strings with Next/Previous match cycling.
- [x] Interactive Byte Inspector displaying offset, decimal value, hex byte, binary bitmask (8-bit), ASCII character, signed int8, uint16 (LE), and uint32 (LE).
- [x] Comprehensive test coverage with 56 passing unit and integration tests.
