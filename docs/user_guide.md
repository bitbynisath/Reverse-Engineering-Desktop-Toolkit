# PyRE Studio User Guide

This guide documents the user interface and functionality implemented across PyRE Studio.

---

## 1. Overview & Interface Layout

PyRE Studio is an all-in-one desktop environment for static reverse engineering and binary analysis.

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
   - Current application activity state (`Ready`, `Viewing ...`, `Analysis complete`).
   - Selected target file name.
   - Engine mode indicator (`v0.1.0 | Static Mode`).

---

## 2. File Analyzer Module (Phase 2)

The **File Analyzer** is a core static analysis module designed to inspect, identify, and verify files before deeper analysis.

### How to Analyze a File:
1. **Selection:**
   - Click **Select File to Analyze...** or press `Ctrl+O`.
   - Alternatively, drag and drop any file directly onto the File Analyzer window.
2. **Background Processing:**
   - Processing runs on a background `QThread` without freezing the interface.
   - A real-time progress bar indicates validation and chunked cryptographic hashing progress.
   - You may click **Cancel** at any time to abort large file processing.
3. **Inspection Results:**
   - **File System Metadata:** Displays file name, absolute path, size (human-readable and exact byte count), UNIX/Windows permissions mode, creation timestamp, and last modification timestamp. Click **Copy Path** to copy the resolved absolute path to the clipboard.
   - **File Signature & Format Identification:**
     - Identifies target binary signatures (Windows PE, ELF, Mach-O, Python Bytecode `.pyc`, ZIP containers, PDF, raster images, compressed archives, scripts).
     - **Extension Verification:** Compares the declared extension against detected magic bytes. If a binary is disguised (e.g. an `.exe` renamed to `.pdf` or `.png`), a prominent **HIGH RISK MISMATCH** warning is surfaced.
     - **Magic Bytes Preview:** Formats the first 32 header bytes into both Hex and printable ASCII representations.
   - **Cryptographic Hashes:**
     - Computes MD5, SHA-1, SHA-256, and SHA-512 in a single chunked pass.
     - Click **Copy** next to any hash to copy the hexadecimal digest to the clipboard.
     - Displays precise execution time in seconds.
   - **Exporting JSON Reports:**
     - Click **Export JSON Report** to export all findings, metadata, signatures, and hashes into a structured `.json` document.

---

## 3. Settings Panel

- **Theme Selection:** Choose between Dark (Charcoal/Navy default) and Light themes.
- **Hex View Preferences:** Configure default bytes-per-row (8, 16, 24, 32).
- **Analysis Directory:** Set and browse the default directory opened by file dialogs.
- **String Length:** Configure default minimum string extraction length (default: 4).
- **Max File Size:** Warning threshold for large binaries (default: 100 MB).
- **Logging Level:** Adjust logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
- **Dependency Status Table:** Real-time inspection of required and optional packages.

---

## 4. Keyboard Shortcuts

- `Ctrl+O`: Open File Dialog (automatically switches to File Analyzer and begins analysis)
- `Ctrl+,`: Open Settings Page
- `F1`: Open About & Security Policy Dialog
