# PyRE Studio User Guide (Phase 1)

This guide documents the user interface and functionality implemented in **Phase 1: Desktop Application Foundation**.

## Overview

PyRE Studio is an all-in-one desktop environment for static reverse engineering and binary analysis. In Phase 1, the core user interface shell, navigation system, theme manager, settings panel, and environment inspectors are fully functional.

---

## Navigating the Interface

The interface is structured into three primary visual zones:
1. **Top Header Bar:**
   - Application branding and quick module search.
   - **Theme:** One-click toggle between Dark and Light interface themes.
   - **Settings:** Quick shortcut to the configuration panel.
   - **Help:** Opens the About & Security policy dialog.
2. **Left Navigation Sidebar:**
   - **Overview:** Dashboard.
   - **ANALYSIS Section:** File Analyzer, Hex Viewer, String Extractor, PE Analyzer, Disassembler, Python Analyzer, and Advanced Analysis.
   - **MANAGEMENT Section:** Reports, Analysis History, Settings, and About.
3. **Main Content Area:**
   - Displays the active module page with smooth switching and honest development state indicators.
4. **Bottom Status Bar:**
   - Current application activity state (`Ready`, `Viewing ...`).
   - Selected target file name.
   - Engine mode indicator (`v0.1.0 | Static Mode`).

---

## Implemented Features in Phase 1

### 1. Dashboard (`DashboardPage`)
- **Open File for Analysis:** Prompts native OS file dialog to select a target file.
- **Safety Disclaimer:** Highlights that PyRE Studio operates in a read-only, non-executing mode.
- **Metric Cards:** Displays honest baseline metrics (Total Files Analyzed, Active Modules, Engine Mode).
- **Core Modules Grid:** Quick-access cards allowing direct navigation to analysis modules.
- **Environment Status:** Shows Python runtime, Qt/PySide6 version, and host operating system details.

### 2. Settings Panel (`SettingsPage`)
- **Theme Selection:** Choose between Dark (Charcoal/Navy default) and Light themes.
- **Hex View Preferences:** Configure default bytes-per-row (8, 16, 24, 32).
- **Analysis Directory:** Set and browse the default directory opened by file dialogs.
- **String Length:** Configure default minimum string extraction length (default: 4).
- **Max File Size:** Warning threshold for large binaries (default: 100 MB).
- **Logging Level:** Adjust logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
- **Dependency Status Table:** Real-time inspection of required and optional packages (`PySide6`, `pefile`, `capstone`, `lief`, `yara`, `matplotlib`, `reportlab`) and which development phase introduces them.
- **Save & Reset Actions:** Persist preferences or restore defaults with user confirmation.

### 3. File Selection & Validation
- Press `Ctrl+O` or click **Open File for Analysis**.
- Select a file to inspect.
- The path and readability are validated by core services without crashing.
- Target filename is reflected in the status bar.

### 4. About Dialog
- Accessible via `F1`, the top header **Help** button, or the sidebar **About** item.
- Displays version info, license details, architecture highlights, and security policies.

### 5. Keyboard Shortcuts
- `Ctrl+O`: Open File Dialog
- `Ctrl+,`: Open Settings Page
- `F1`: Open About Dialog
