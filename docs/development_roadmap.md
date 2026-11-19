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
| **4** | String Extraction | **COMPLETED** | Printable ASCII, UTF-16LE, and UTF-8 extraction, offset tracking, real-time filtering, TXT/CSV export, 65/65 tests passing. |
| **5** | Windows PE Analysis | **READY TO START** | DOS/PE headers, sections, imports, exports, certificate metadata parsing. |
| **6** | Capstone Disassembly | PENDING | Static x86 / x86-64 machine code disassembly and instruction mapping. |
| **7** | Python Bytecode Analysis | PENDING | .pyc header inspection, code objects, names, constants, and dis disassembly. |
| **8** | Advanced Analyzers | PENDING | ELF, APK, Mach-O, Shannon entropy visualization, YARA pattern scanning. |
| **9** | Reports & History | PENDING | SQLite session database, history search, JSON/CSV/HTML/PDF reporting. |
| **10** | Release & Packaging | PENDING | Full test suite, Windows standalone PyInstaller executable packaging. |

---

## Phase 4 Acceptance Verification

- [x] High-performance extraction of printable ASCII, UTF-16LE, and multibyte UTF-8 strings.
- [x] Precise byte offset calculation (`0x...`) for every extracted string.
- [x] Configurable minimum string length (default 4 characters, validated >= 3).
- [x] Overlapped memory-bounded chunked scanning (`512 KB` chunks) preventing missed strings across boundaries.
- [x] Non-blocking background worker (`StringWorker` on `QThread`) with progress bar and cooperative cancellation.
- [x] Real-time table filtering by text query and encoding type ("All", "ASCII", "UTF-16LE", "UTF-8").
- [x] Numeric sorting by file offset and string length.
- [x] Export to formatted plain text (`.txt`) and comma-separated values (`.csv`).
- [x] Safe string rendering ensuring untrusted extracted content is treated strictly as plain text.
- [x] Comprehensive test suite with 65 passing unit and integration tests.
