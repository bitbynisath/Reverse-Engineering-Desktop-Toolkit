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
|  - SettingsPage & AboutDialog                               |
|  - Module Placeholder Pages (Phases 3-9)                    |
|  - ThemeManager (QSS Dark / Light stylesheets)              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Concurrency & Worker Layer                     |
|  - AnalysisWorker (QObject running on dedicated QThread)    |
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
|  - AnalysisService (Unified orchestration & JSON exporter)  |
+-------------------------------------------------------------+
                              |
                              v (Phases 3 - 9)
+-------------------------------------------------------------+
|              Downstream Analysis Engines (Planned)          |
|  - Bounded Binary Reader & Hex Paging (Phase 3)             |
|  - String Extraction Engine (Phase 4)                       |
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
3. **`workers/`**: Dedicated `QThread` workers isolating CPU-intensive hashing and disk reading from the GUI.
4. **`core/`**:
   - `core/models/`: Strongly-typed dataclasses (`FileMetadata`, `FileSignature`, `HashResults`, `FileAnalysisResult`).
   - `core/services/`: Pure Python static analysis logic with zero PySide6 dependencies.
5. **`tests/`**: Unit tests for services and integration tests for UI startup, navigation, and worker pipelines.

## Concurrency Model

All analysis operations taking more than a few milliseconds are executed off the Qt GUI thread using `QThread` and dedicated worker objects. Worker threads communicate with the UI purely through Qt signals (`progress`, `finished`, `error`), preventing UI lockups and keeping the interface responsive.
