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
| **6** | Capstone Disassembly | **COMPLETED** | Static x86 / x86-64 disassembly via Capstone 5.x, PE section integration, colour-coded instruction table, jump/call navigation, export. |
| **7** | Python Bytecode Analysis | **COMPLETED** | .pyc header inspection, magic numbers, code objects, constants, names, flags, and dis disassembly. |
| **8** | Advanced Analyzers | **READY TO START** | ELF, APK, Mach-O, Shannon entropy visualization, YARA pattern scanning. |
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


---

## Phase 6 Acceptance Verification

- [x] Capstone 5.x integrated as the disassembly engine for x86 / x86-64.
- [x] `disassemble_bytes()` decodes raw byte sequences with configurable base address, file offset, and instruction cap.
- [x] `disassemble_pe_section()` reads named PE sections from disk using bounded I/O and auto-detects 32/64-bit mode from PE optional header.
- [x] `list_disassemblable_sections()` returns executable sections first for smart UI pre-selection.
- [x] `DisassembledInstruction` model classifies every instruction as jump / call / ret / privileged.
- [x] `DisassemblyResult` tracks total_bytes, decoded_bytes, coverage_percent, truncated flag, and warnings.
- [x] `DisasmWorker` runs on a `QThread`, emits `progress`, `sections_available`, `status_message`, `finished`, and `error` signals.
- [x] Worker supports cancellation before result emission.
- [x] `DisassemblerPage` replaces placeholder with fully active UI:
  - File browse button and drag-and-drop support.
  - Architecture mode combo (Auto / x86 32-bit / x86 64-bit).
  - PE section selector combo (populated via `sections_available` signal).
  - Raw binary mode toggle.
  - Non-blocking disassembly with progress bar and cancel.
  - Colour-coded sortable table (jumps=rose, calls=blue, rets=green, privileged=peach).
  - Monospaced (Consolas 9pt) instruction display.
  - Live search/filter that hides non-matching rows.
  - Double-click jump/call navigation to target instruction.
  - Export full disassembly to plain text.
- [x] `MainWindow` auto-syncs the current file into `DisassemblerPage` on page navigation.
- [x] `requirements.txt` updated: `capstone>=5.0.0`.
- [x] `test_placeholder_pages_integrity` updated to remove `PAGE_DISASSEMBLER` from placeholder list.
- [x] `test_disassembler_page_active` added confirming active page contract.
- [x] Full unit and integration test coverage for disassembly analyzer and UI widget.


---

## Phase 7 Acceptance Verification

- [x] Python Bytecode static analysis engine implemented in `analyzers/python_analyzer.py` with zero execution risk.
- [x] Comprehensive magic number table mapping 2-byte little-endian magic ints to Python versions (2.0 through 3.14+).
- [x] PEP 552 pyc header parsing supporting timestamp-based and hash-based (checked/unchecked) modes with SipHash extraction.
- [x] Recursive code object traversal discovering `<module>`, functions, methods, inner closures, generators, and lambdas.
- [x] Complete decoding of `co_flags` bitmasks into descriptive human-readable names (`CO_OPTIMIZED`, `CO_NEWLOCALS`, etc.).
- [x] Disassembly via standard library `dis` module extracting line numbers, offsets, opcodes, arguments, and jump indicators.
- [x] Constants (`co_consts`) inspection displaying indices, types, representations, and code object flags.
- [x] Variable tables for `co_names`, `co_varnames`, `co_freevars`, and `co_cellvars`.
- [x] Support for compiling and disassembling raw `.py` source files statically without execution.
- [x] Non-blocking background worker (`PythonWorker` on `QThread`) with progress reporting, status messages, and cancellation.
- [x] `PythonAnalyzerPage` UI with summary cards, code object dropdown, 4 tabbed panels, live search filter, and plain text export.
- [x] `MainWindow` integration with file sync on page navigation and `.pyc`/`.py` filter options.
- [x] Comprehensive unit and integration test coverage with synthetic fixtures.
