# PyRE Studio

**All-in-One Python Reverse Engineering Desktop Toolkit**

PyRE Studio is an extensible, modular, professional desktop application engineered for legitimate static file inspection, binary analysis, reverse engineering education, debugging, interoperability research, and authorized defensive security analysis.

Built with Python 3.12+ and PySide6 (Qt 6), PyRE Studio operates in a **strictly non-executing, read-only mode**, guaranteeing safe analysis of untrusted binaries.

---

## Current Status: Phase 7 Completed (Python Bytecode Analyzer Active)

- **Architecture:** Layered, decoupled desktop architecture separating UI from analysis services.
- **GUI Engine:** PySide6 with custom dark charcoal/navy and light themes.
- **Navigation:** Integrated sidebar with categorized access to all core modules.
- **File Analyzer (Phase 2):** Fully active static analysis engine:
  - File system metadata (exact byte sizes, timestamps, permissions).
  - Binary signature & magic byte identification (Windows PE, ELF, Mach-O, Python `.pyc`, ZIP/APK, PDF, images, archives, scripts).
  - Format vs. extension mismatch detection (surfaces disguised executables).
  - Chunked, memory-bounded cryptographic hashing (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`).
  - Background multi-threaded processing with progress reporting and cancellation.
  - JSON metadata report export.
- **Hexadecimal Viewer (Phase 3):** Fully active high-performance binary viewer:
  - Memory-bounded reads via `BinaryReader` using `mmap` with buffered fallback.
  - Paged viewing (e.g. 32 rows/page) supporting multi-gigabyte files without memory spikes.
  - Configurable bytes per row (8, 16, 24, 32).
  - Offset column, spaced hex byte columns, and printable ASCII column.
  - Direct "Go to Offset" navigation (hex `0x...` or decimal).
  - Background asynchronous pattern search for raw hex sequences and text with Next/Prev cycling.
  - Interactive Byte Inspector displaying decimal, hex, 8-bit binary, ASCII char, signed int8, uint16 (LE), and uint32 (LE).
- **String Extractor (Phase 4):** Fully active string extraction and classification engine:
  - Printable ASCII, UTF-16LE, and multibyte UTF-8 extraction.
  - Precise byte offset mapping (`0x...`) and length calculation.
  - Configurable minimum string length (default: 4).
  - Overlapped chunked scanning (`512 KB` chunks) preventing missed boundary strings.
  - Real-time instant search filter and encoding filter dropdown.
  - Sortable results table (by offset, length, encoding, string value).
  - Export to plain text (`.txt`) and comma-separated values (`.csv`).
- **Windows PE Analyzer (Phase 5):** Fully active static PE analysis engine:
  - DOS Header, COFF File Header, and Optional Header (PE32 / PE32+).
  - Architecture, Subsystem, Image Base, Entry Point RVA, and Checksum.
  - Security Mitigations & DLL Characteristics (ASLR, DEP/NX, SafeSEH, CFG).
  - Section Table with Shannon entropy calculations and RWX/anomaly warnings.
  - Import Table (IAT) resolution with library grouping and instant API search.
  - Export Table (EAT) resolution with function names, ordinals, RVAs, and forwarders.
  - Resource Directory, Debug Directory (PDB file path, GUID), and Authenticode certificate metadata.
- **Disassembler (Phase 6):** Fully active static Capstone disassembly engine:
  - x86 32-bit and x86-64 instruction decoding via Capstone 5.x.
  - Automatic architecture detection from PE optional header (PE32 -> 32-bit, PE32+ -> 64-bit).
  - PE section selector — disassembles `.text` or any named section with raw data.
  - Raw binary mode — disassembles any file as a byte stream.
  - Colour-coded instruction table: jumps (rose), calls (blue), rets (green), privileged (peach).
  - Monospaced table: File Offset | Virtual Address | Raw Bytes | Mnemonic | Operands.
  - Live search/filter across all columns.
  - Double-click jump/call navigation to target instruction.
  - Plain text export of full disassembly listing.
  - 100,000-instruction safety cap with explicit truncation warning.
  - Non-blocking `DisasmWorker` on `QThread` with progress bar and cancel.
- **Python Bytecode Analyzer (Phase 7):** Fully active static Python `.pyc` and `.py` inspection engine:
  - `.pyc` header parsing, magic number validation, and Python release version mapping (Python 2.0 through 3.14+).
  - PEP 552 header support: timestamp-based vs hash-based (checked/unchecked) validation and SipHash extraction.
  - Recursive nested code object discovery (`<module>`, inner functions, classes, closures, generators).
  - Code object properties and `co_flags` bitmask decoding (`CO_OPTIMIZED`, `CO_NEWLOCALS`, `CO_VARARGS`, `CO_GENERATOR`, etc.).
  - Constants table (`co_consts`) with type identification and code object cross-referencing.
  - Variable tables for global names (`co_names`), local variables (`co_varnames`), free variables (`co_freevars`), and cell variables (`co_cellvars`).
  - Bytecode instruction disassembly via standard library `dis` module with line numbers, byte offsets, opcode mnemonics, arguments, and jump targets.
  - Non-blocking `PythonWorker` on `QThread` with progress reporting and cancellation.
  - Plain text export of full Python bytecode disassembly listing.
- **Settings & Config:** Persistent configuration stored in standard OS user paths (`~/.pyre-studio/config.json`), theme switcher, logging level preferences, and real-time dependency status.
- **Upcoming Modules:** Transparently labeled placeholder screens detailing planned capabilities and target dependencies for Phases 8 through 10.

---

## Planned Module Roadmap

| Phase | Module | Status | Planned Capabilities |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Desktop Foundation** | **Completed** | PySide6 shell, navigation sidebar, dashboard, dark/light themes, settings |
| **Phase 2** | **File Analysis Engine** | **Completed** | Signatures, chunked hashes (MD5, SHA-1, SHA-256, SHA-512), metadata, extension validation, JSON export |
| **Phase 3** | **Hexadecimal Viewer** | **Completed** | Bounded reads, mmap paging, go-to-offset, hex/ASCII search, interactive byte inspector |
| **Phase 4** | **String Extraction** | **Completed** | ASCII, UTF-16LE, UTF-8 extraction, filtering, sorting, TXT/CSV export |
| **Phase 5** | **Windows PE Analyzer** | **Completed** | DOS/PE headers, sections, imports (IAT), exports (EAT), resources, debug/PDB, Authenticode certificates |
| **Phase 6** | **Capstone Disassembler** | **Completed** | Static x86 / x86-64 machine code disassembly, colour-coded instruction table, search/filter, jump navigation, export |
| **Phase 7** | **Python Bytecode Analyzer** | **Completed** | .pyc header inspection, magic numbers, code objects, constants, names, flags, and dis disassembly |
| **Phase 8** | Advanced Analyzers | Next Up | ELF, APK, Mach-O, Shannon entropy visualization, YARA scanning |
| **Phase 9** | Reports & History | Planned | SQLite session history, JSON/CSV/HTML/PDF reporting |
| **Phase 10** | Release & Packaging | Planned | Windows standalone installer / packaging (PyInstaller) |

---

## Quick Start & Installation

### Requirements
- Windows 10 or Windows 11 (Cross-platform Linux/macOS compatible)
- Python 3.12+ (tested on Python 3.14)

### Setup

```bash
# Clone or navigate to the repository
cd "desktop toolkit"

# Optional: Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Launching the Application

```bash
python main.py
```

### Running Tests

```bash
pytest
```

---

## Safe Static Analysis Policy

PyRE Studio treats all inspected files as untrusted:
1. **Zero Execution:** Never executes or executes sub-processes of analyzed binaries.
2. **Read-Only Access:** All file handles are opened in read-only binary mode (`rb`).
3. **Memory Safety:** Files are processed using chunked, bounded reads (default 64 KB/512 KB) and memory mapping (`mmap`) rather than full RAM loads.
3. **Memory Safety:** Files are processed using chunked, bounded reads (default 64 KB/512 KB) and memory mapping (`mmap`) rather than full RAM loads.
4. **Data Isolation:** User files are never modified, moved, or deleted by session cleanup.

---

## Documentation Links

- [Architecture Guide](docs/architecture.md)
- [Installation Guide](docs/installation.md)
- [User Guide](docs/user_guide.md)
- [User Guide](docs/user_guide.md)
- [Development Roadmap](docs/development_roadmap.md)
- [Security & Safe Analysis Design](docs/security.md)
