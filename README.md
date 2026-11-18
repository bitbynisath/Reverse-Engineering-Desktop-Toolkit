# PyRE Studio

**All-in-One Python Reverse Engineering Desktop Toolkit**

PyRE Studio is an extensible, modular, professional desktop application engineered for legitimate static file inspection, binary analysis, reverse engineering education, debugging, interoperability research, and authorized defensive security analysis.

Built with Python 3.12+ and PySide6 (Qt 6), PyRE Studio operates in a **strictly non-executing, read-only mode**, guaranteeing safe analysis of untrusted binaries.

---

## Current Status: Phase 3 Completed (Hex Viewer Active)

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
- **Settings & Config:** Persistent configuration stored in standard OS user paths (`~/.pyre-studio/config.json`), theme switcher, logging level preferences, and real-time dependency status.
- **Upcoming Modules:** Transparently labeled placeholder screens detailing planned capabilities and target dependencies for Phases 4 through 9.

---

## Planned Module Roadmap

| Phase | Module | Status | Planned Capabilities |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Desktop Foundation** | **Completed** | PySide6 shell, navigation sidebar, dashboard, dark/light themes, settings |
| **Phase 2** | **File Analysis Engine** | **Completed** | Signatures, chunked hashes (MD5, SHA-1, SHA-256, SHA-512), metadata, extension validation, JSON export |
| **Phase 3** | **Hexadecimal Viewer** | **Completed** | Bounded reads, mmap paging, go-to-offset, hex/ASCII search, interactive byte inspector |
| **Phase 4** | String Extraction | Next Up | ASCII, UTF-8, UTF-16LE extraction, filtering, sorting, TXT/CSV export |
| **Phase 5** | Windows PE Analyzer | Planned | DOS/PE headers, sections, imports, exports, certificate metadata |
| **Phase 6** | Capstone Disassembler | Planned | Static x86 / x86-64 machine code disassembly and instruction mapping |
| **Phase 7** | Python Bytecode Analyzer | Planned | .pyc header inspection, code objects, names, constants, and dis assembly |
| **Phase 8** | Advanced Analyzers | Planned | ELF, APK, Mach-O, Shannon entropy visualization, YARA scanning |
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
3. **Memory Safety:** Files are processed using chunked, bounded reads (default 64 KB) and memory mapping (`mmap`) rather than full RAM loads.
4. **Data Isolation:** User files are never modified, moved, or deleted by session cleanup.

---

## Documentation Links

- [Architecture Guide](docs/architecture.md)
- [Installation Guide](docs/installation.md)
- [User Guide](docs/user_guide.md)
- [Development Roadmap](docs/development_roadmap.md)
- [Security & Safe Analysis Design](docs/security.md)
