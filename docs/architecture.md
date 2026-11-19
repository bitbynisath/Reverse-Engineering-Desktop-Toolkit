# PyRE Studio Architecture

## System Overview

PyRE Studio follows a modular, layered desktop architecture separating the user interface from core analysis services. The design isolates UI widgets from analysis algorithms, ensuring that backend services remain testable without requiring a running GUI or active display server.

```
+-------------------------------------------------------------+
|                      Presentation Layer                     |
|  - MainWindow (Top Header, Status Bar, Resizing, Shortcuts)  |
|  - SidebarNavigation (Categorized Navigation Bar)           |
|  - DashboardPage (Metric Cards, Quick Launch, System Info)  |
|  - FileAnalyzerPage (Metadata, Signatures, Hashes, Export)  |
|  - HexViewerPage (Paged Hex/ASCII Table, Inspector, Search) |
|  - StringExtractorPage (ASCII, UTF-16, UTF-8 Table & Export)|
|  - SettingsPage & AboutDialog                               |
|  - Module Placeholder Pages (Phases 5-9)                    |
|  - ThemeManager (QSS Dark / Light stylesheets)              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Concurrency & Worker Layer                     |
|  - AnalysisWorker (File analysis on dedicated QThread)      |
|  - HexSearchWorker (Byte/text search on dedicated QThread)  |
|  - StringWorker (String extraction on dedicated QThread)    |
|  - Progress, Finished, and Error Signals                    |
|  - Non-blocking cooperative cancellation                    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                      Application Core                       |
|  - AppConfig (Dataclass, user preferences, JSON persistence)|
|  - LoggingConfig (Dual console & file logging)              |
|  - Bootstrap (Qt setup, High-DPI, App lifecycle)            |
|  - DependencyChecker (Runtime inspection of optional libs)   |
|  - Validators (Path validation, file readability & limits)  |
|  - Exceptions (Typed exception hierarchy)                   |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 Analysis Services & Engines                 |
|  - FileService (Metadata, stat, human formatting, headers)  |
|  - FileDetectionService (Magic bytes, PE/ELF/ZIP/PDF rules) |
|  - HashingService (Streaming chunked MD5/SHA1/SHA256/SHA512)|
|  - BinaryReader (Memory-bounded reads, mmap, byte search)   |
|  - HexService (HexRow formatting, paging, byte inspection)  |
|  - StringService (Overlapped regex extraction, TXT/CSV exp) |
|  - AnalysisService (Unified orchestration & JSON exporter)  |
+-------------------------------------------------------------+
                              |
                              v (Phases 5 - 9)
+-------------------------------------------------------------+
|              Downstream Analysis Engines (Planned)          |
|  - PE / ELF / Mach-O Parsers (pefile, LIEF) (Phases 5, 8)   |
|  - Capstone Disassembly Engine (Phase 6)                    |
|  - Python Bytecode (.pyc) Analyzer (Phase 7)                |
|  - SQLite Session & History Database (Phase 9)              |
|  - Multi-Format Report Exporters (Phase 9)                  |
+-------------------------------------------------------------+
```

## Module Separation

1. **`app/`**: Contains bootstrapping routines, global constants, configuration dataclasses, and logging setup.
2. **`ui/`**: Pure PySide6 presentation components. Does not contain raw file analysis or parsing logic.
3. **`workers/`**: Dedicated `QThread` workers isolating CPU-intensive hashing, streaming, pattern searching, and string scanning from the GUI.
4. **`core/`**:
   - `core/models/`: Strongly-typed dataclasses (`FileMetadata`, `FileSignature`, `HashResults`, `FileAnalysisResult`, `HexRow`, `ByteSelection`, `HexSearchResult`, `ExtractedString`).
   - `core/services/`: Pure Python static analysis and reading logic with zero PySide6 dependencies (`StringService`, `BinaryReader`, `HexService`, `FileService`, `HashingService`, `FileDetectionService`, `AnalysisService`).
5. **`tests/`**: Unit tests for services and integration tests for UI startup, navigation, and worker pipelines.

## Memory-Bounded Design Principle

To prevent memory bloat or out-of-memory crashes when inspecting multi-gigabyte executable or firmware files:
1. File handles are accessed via `BinaryReader` using OS-level read-only memory mapping (`mmap`).
2. Display widgets render strictly one page of data (default: 32 rows × 16 bytes = 512 bytes) at a time.
3. Hash calculations stream through files in bounded 64 KB buffers.
4. String extraction scans through files in bounded 512 KB chunks with safe boundary overlap, eliminating excessive memory allocations.
