# PyRE Studio Architecture

## System Overview

PyRE Studio follows a modular, layered desktop architecture separating the user interface from core analysis services. The design isolates UI widgets from analysis algorithms, ensuring that backend services remain testable without requiring a running GUI or active display server.

```
+-------------------------------------------------------------+
|                      Presentation Layer                     |
|  - MainWindow (Top Header, Status Bar, Resizing, Shortcuts)  |
|  - SidebarNavigation (Categorized Navigation Bar)           |
|  - DashboardPage (Metric Cards, Quick Launch, System Info)  |
|  - SettingsPage & AboutDialog                               |
|  - Module Placeholder Pages (Phases 2-9)                    |
|  - ThemeManager (QSS Dark / Light stylesheets)              |
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
                              v (Phases 2 - 9)
+-------------------------------------------------------------+
|                 Analysis Services & Engines                 |
|  - File & Hashing Services (MD5, SHA-1, SHA-256)            |
|  - Bounded Binary Reader & Hex Paging                       |
|  - String Extraction Engine                                 |
|  - PE / ELF / Mach-O Parsers (pefile, LIEF)                 |
|  - Capstone Disassembly Engine                              |
|  - Python Bytecode (.pyc) Analyzer                          |
|  - Background QThread Workers & Progress Signals            |
+-------------------------------------------------------------+
                              |
                              v (Phase 9)
+-------------------------------------------------------------+
|                   Storage & Reporting Layer                 |
|  - SQLite Session & History Database                        |
|  - JSON / CSV / HTML / PDF Exporters                        |
+-------------------------------------------------------------+
```

## Module Separation

1. **`app/`**: Contains bootstrapping routines, global constants, configuration dataclasses, and logging setup.
2. **`ui/`**: Pure PySide6 presentation components. Does not contain raw file analysis or parsing logic.
3. **`core/`**: Shared services, input validators, exceptions, and dependency inspection. Free of PySide6 widget logic.
4. **`tests/`**: Unit tests for core logic and integration tests for UI startup and navigation.

## Concurrency Model

All analysis operations taking more than a few milliseconds are planned to run off the Qt GUI thread using `QThread` and dedicated worker objects. Worker threads communicate with the UI purely through Qt signals (`progress`, `completed`, `error`), preventing UI lockups and keeping the interface responsive.
