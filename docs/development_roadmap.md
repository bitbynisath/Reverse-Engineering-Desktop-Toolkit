# PyRE Studio Development Roadmap

This document tracks the phased implementation gates of PyRE Studio. Each phase must be completed, tested, and documented before the next phase begins.

---

## Phase Status Summary

| Phase | Title | Status | Gate Completion Criteria |
| :---: | :--- | :---: | :--- |
| **0** | Project Planning & Environment | **COMPLETED** | Python 3.12+ confirmed, virtual environment, gitignore, pyproject.toml established. |
| **1** | Desktop Application Foundation | **COMPLETED** | PySide6 shell, sidebar navigation, dashboard, dark/light themes, settings. |
| **2** | File Analysis Engine | **COMPLETED** | Metadata, magic byte signatures, chunked hashing (MD5/SHA1/SHA256/SHA512), extension mismatch detection, JSON export, 40/40 tests passing. |
| **3** | Hexadecimal Viewer | **READY TO START** | Paged memory-bounded reads, hex/ASCII columns, offset navigation, pattern search. |
| **4** | String Extraction | PENDING | ASCII, UTF-8, UTF-16LE extraction, filtering, offset tracking, CSV/TXT export. |
| **5** | Windows PE Analysis | PENDING | DOS/PE headers, sections, imports, exports, certificate metadata parsing. |
| **6** | Capstone Disassembly | PENDING | Static x86 / x86-64 machine code disassembly and instruction mapping. |
| **7** | Python Bytecode Analysis | PENDING | .pyc header inspection, code objects, names, constants, and dis disassembly. |
| **8** | Advanced Analyzers | PENDING | ELF, APK, Mach-O, Shannon entropy visualization, YARA pattern scanning. |
| **9** | Reports & History | PENDING | SQLite session database, history search, JSON/CSV/HTML/PDF reporting. |
| **10** | Release & Packaging | PENDING | Full test suite, Windows standalone PyInstaller executable packaging. |

---

## Phase 2 Acceptance Verification

- [x] File selection through native file dialog and drag-and-drop.
- [x] Extraction of filename, full path, extension, file size, timestamps, and permissions.
- [x] Signature detection for Windows PE, ELF, Mach-O, Python Bytecode (.pyc), ZIP/APK, PDF, Images (PNG, JPEG, GIF, BMP), Archives (7z, GZIP, BZIP2, RAR), XML, and Scripts.
- [x] Declared extension vs. detected signature comparison with mismatch detection (e.g. PE binary disguised as document/image).
- [x] Chunked memory-bounded calculation of MD5, SHA-1, SHA-256, and SHA-512 hashes.
- [x] Non-blocking background worker (`AnalysisWorker` on `QThread`) with progress bar and cancellation.
- [x] Full UI result rendering on `FileAnalyzerPage` with copy actions and JSON report export.
- [x] Comprehensive test coverage with 40 passing tests including NIST/RFC test vectors and UI integration.
