# PyRE Studio User Guide
# PyRE Studio User Guide

This guide documents the user interface and functionality implemented across PyRE Studio.

---

## 1. Overview & Interface Layout
This guide documents the user interface and functionality implemented across PyRE Studio.

---

## 1. Overview & Interface Layout

PyRE Studio is an all-in-one desktop environment for static reverse engineering and binary analysis.
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

## 3. Hexadecimal Viewer Module (Phase 3)

The **Hex Viewer** provides high-performance, memory-bounded binary inspection for files of any size without loading entire files into RAM.

### Features & Usage:
1. **Paging & Navigation:**
   - Files are rendered in pages (default: 32 rows per page) using bounded reads and memory-mapping (`mmap`).
   - Use `<< First`, `< Previous`, `Next >`, and `Last >>` or the Page input spinbox to jump between pages instantly.
   - **Bytes Per Row:** Configure 8, 16, 24, or 32 bytes per row via the dropdown.
2. **Go to Offset:**
   - Enter any byte offset in hexadecimal (e.g., `0x1000`, `7F`) or decimal (e.g., `4096`).
   - Press Enter or click **Go** to immediately calculate the target page, jump to it, and select the corresponding row.
3. **Pattern Searching:**
   - Enter raw hexadecimal byte sequences (e.g., `4D 5A 90 00`, `CAFE BABE`, `\x4d\x5a`) or readable UTF-8 text.
   - Select search mode (**Hex Bytes** or **Text**) and click **Find All**.
   - Searching runs asynchronously on a background worker thread.
   - Use **▲ Prev** and **▼ Next** to cycle through all match locations.
4. **Interactive Byte Inspector:**
   - Clicking any row in the table populates the Byte Inspector panel at the bottom.
   - Displays offset, byte value (decimal/hex), 8-bit binary bitmask, printable ASCII character, signed int8, uint16 (LE), and uint32 (LE).

---

## 4. String Extractor Module (Phase 4)

The **String Extractor** extracts human-readable text sequences embedded within binaries, shared libraries, firmware, or scripts.

### Features & Usage:
1. **Extraction Options:**
   - **Min Length:** Filter out noise by adjusting the minimum string length (default: 4 chars, range: 3–64).
   - **Encoding Selection:** Extract **ASCII**, **UTF-16LE** (common in Windows binaries and resource directories), and **UTF-8** multibyte strings independently or concurrently.
   - Click **Extract Strings** to launch multi-threaded extraction on a background worker.
2. **Search & Real-time Filtering:**
   - Filter results in real time using the **Filter** search box (matches string content or hex offsets).
   - Filter by encoding using the **Encoding** dropdown (`All`, `ASCII`, `UTF-16LE`, `UTF-8`).
   - Statistics bar displays total matches and per-encoding breakdowns.
3. **Sorting & Navigation:**
   - Click any column header (**Offset**, **Length**, **Encoding**, **String Value**) to sort numerically or alphabetically.
   - Double-click any row to copy the string value to the clipboard.
4. **Exporting Strings:**
   - **Export TXT:** Exports filtered or all strings to a plain text file (with file offsets and encoding labels).
   - **Export CSV:** Exports tabular results to CSV with `Offset`, `Offset_Hex`, `Encoding`, `Length`, and `Value` columns for spreadsheet or automated ingestion.

---

## 5. Windows PE Analyzer Module (Phase 5)

The **Windows PE Analyzer** performs static structural inspection of Portable Executable files (EXE, DLL, SYS, OCX) without executing target code.

### Features & Usage:
1. **Headers & Flags Tab:**
   - **Architecture & Format:** Distinguishes between PE32 (32-bit) and PE32+ (64-bit) formats, target machine CPU (AMD64, i386, ARM64), subsystem (GUI, Console, Driver), Entry Point RVA, Image Base, Checksum, and Section count.
   - **Timestamp Note:** Displays linker timestamp with an explicit note highlighting that timestamps can be forged, zeroed, or set to reproducible build hashes.
   - **Security Mitigations:** Highlights DLL characteristics including ASLR (`DYNAMIC_BASE`, `HIGH_ENTROPY_VA`), DEP/NX (`NX_COMPAT`), SafeSEH (`NO_SEH`), and Control Flow Guard (`GUARD_CF`).
   - **Anomalies Banner:** Warns when dangerous section configurations (such as RWX permissions) or high-entropy executable sections are detected.
2. **Section Table Tab:**
   - Displays all defined sections (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`).
   - Inspect Virtual Address, Virtual Size, Raw Size, Raw Offset, Characteristics, and Shannon Entropy (0.0 to 8.0).
   - High entropy (> 7.0) is highlighted in yellow as an indicator of packed or encrypted code.
   - RWX (Read/Write/Execute) permissions are flagged in red.
3. **Imports (IAT) Tab:**
   - Two-pane view: Left panel lists imported dynamic link libraries (e.g., `KERNEL32.dll`, `USER32.dll`, `ntdll.dll`) with symbol count badges.
   - Right panel lists imported symbol names, ordinals, and RVAs.
   - Instant search filter enables searching for specific APIs (e.g., `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).
4. **Exports (EAT) Tab:**
   - Displays all exported functions, ordinals, entry point RVAs, and forwarders (common in proxy DLLs).
   - Instant search filter for exported API names.
5. **Resources & Security Tab:**
   - **Resource Directory:** Breakdown of embedded resources by type (icons, cursors, dialogs, version manifests, bitmap assets).
   - **Debug Directory:** Extracts CodeView records, timestamp, GUID, and original PDB symbol file path.
   - **Authenticode Security Directory:** Reports digital certificate presence, certificate size, and revision.

---

## 6. Disassembler Module (Phase 6)

The **Disassembler** provides static x86 / x86-64 machine code disassembly via the Capstone engine. Target files are **never executed** — all analysis is strictly read-only.

### Opening a File

1. Click **Browse...** to open a native file dialog, or drag-and-drop any binary file onto the page.
2. The file path label updates to confirm the selection.
3. The **Disassemble** button becomes active.

### Architecture Mode

| Mode | Description |
|------|-------------|
| **Auto (from PE header)** | Reads the PE Optional Header magic value — `0x010B` selects 32-bit; `0x020B` selects 64-bit. |
| **x86 32-bit** | Forces Capstone `CS_MODE_32` regardless of PE header. |
| **x86 64-bit** | Forces Capstone `CS_MODE_64` regardless of PE header. |

### Section Selector

When a PE file is loaded and parsed, the **Section** dropdown lists all sections that have raw data on disk — executable sections (R-X, RWX) are sorted first. Select `.text` for the main code section, or any other section you wish to inspect.

Enable **Raw File** mode to treat the entire file as a flat byte stream instead (useful for shellcode or unknown binary blobs).

### Running Disassembly

Click **⚙ Disassemble**. A progress bar appears and the status bar reports activity. Click **Cancel** to abort mid-run. When complete:

- The instruction table populates with decoded instructions.
- The status bar shows instruction count, section, mode, and byte coverage percentage.
- If results were capped at the 100,000-instruction safety limit, a truncation warning appears.

### Instruction Table Columns

| Column | Description |
|--------|-------------|
| **Offset** | Raw file byte offset of the instruction (`0x00000400`) |
| **Virtual Address** | Computed VA = image_base + section VA + relative offset |
| **Raw Bytes** | Uppercase hex bytes, space-separated (`55 48 89 E5`) |
| **Mnemonic** | Decoded opcode mnemonic (`push`, `mov`, `call`, `ret`) |
| **Operands** | Decoded operand string (`rbp`, `rax, [rbp - 8]`) |

### Colour Coding

| Colour | Instruction type |
|--------|-----------------|
| 🔵 Blue | `call` instructions |
| 🌹 Rose | Conditional and unconditional `jmp` / `je` / `jne` etc. |
| 🟢 Green | `ret` / `retn` / `iret` family |
| 🟠 Peach | Privileged instructions (`in`, `out`, `hlt`, `cli`, etc.) |
| Teal | All other normal instructions |

### Jump / Call Navigation

Double-click any jump or call instruction to scroll and highlight its target row (when the target address is within the disassembled region). Indirect jumps (e.g. `jmp [rax]`) cannot be resolved statically and display an informational message.

### Search & Filter

Type any text into the **search bar** to instantly hide non-matching rows. The filter applies across all five columns (offset, VA, bytes, mnemonic, operands). Click **Clear** to restore all rows.

### Export

Click **Export TXT** to save the full disassembly listing as a plain text file.

---

## 7. Python Bytecode Analyzer Module (Phase 7)

The **Python Bytecode Analyzer** performs static structural inspection of compiled Python binaries (`.pyc`) and Python source scripts (`.py`). The module operates in a **strictly non-executing mode** via Python's standard `marshal` and `dis` libraries.

### Opening a File

1. Click **Select Python File...** or drag-and-drop any `.pyc` or `.py` file onto the page.
2. The summary cards populate with target Python version, magic number/validation mode, total code objects, and instruction count.

### Header & Compatibility Inspection

- **Magic Number:** Identifies source Python version (e.g. Python 2.0 through 3.14+).
- **PEP 552 Validation:** Identifies whether the file is timestamp-based (with source mtime and size) or hash-based (with 64-bit SipHash).
- **Version Compatibility Warning:** If bytecode was compiled on a different Python release than the running interpreter, a clear status banner highlights potential unmarshalling nuances while still displaying parsed metadata.

### Code Object Hierarchy & Navigation

Compiled Python files often contain nested code objects (functions, methods, classes, lambdas, comprehensions). Use the **Target Code Object** dropdown to switch between:
- Root module (`<module>`)
- Top-level and nested functions (`<module> -> my_func`)
- Classes and member methods (`<module> -> MyClass -> __init__`)

### Tabbed Analysis Views:

1. **Bytecode Disassembly Tab:**
   - Monospaced instruction listing: Line number, byte offset, opcode mnemonic, raw argument, argument representation, and jump targets.
   - Colour-coded mnemonics: Jumps (magenta/rose), Returns (green), Calls (cyan/blue), Loads/Stores (yellow/peach).
   - Live search bar that filters instructions in real time.
2. **Code Object Properties & Flags Tab:**
   - Properties: Name, source filename, first line number, total argument count, pos-only args, kw-only args, local variable count, and VM stack size.
   - `co_flags` badge pills: Visual decoding of active flags (e.g. `CO_OPTIMIZED`, `CO_NEWLOCALS`, `CO_VARARGS`, `CO_VARKEYWORDS`, `CO_GENERATOR`, `CO_COROUTINE`).
3. **Constants (`co_consts`) Tab:**
   - Displays all embedded constants with indices, Python data types, and string representations.
   - Highlights nested code objects with cyan badges.
4. **Names & Variables Tab:**
   - Categorized tables for Global/Attribute Names (`co_names`), Local Variables (`co_varnames`), Free Variables (`co_freevars`), and Cell Variables (`co_cellvars`).

### Exporting Disassembly

Click **Export Disassembly** to save a plain text disassembly listing of all code objects or the selected code object.

---

## 8. Settings Panel

- **Theme Selection:** Choose between Dark (Charcoal/Navy default) and Light themes.
- **Hex View Preferences:** Configure default bytes-per-row (8, 16, 24, 32).
- **Analysis Directory:** Set and browse the default directory opened by file dialogs.
- **String Length:** Configure default minimum string extraction length (default: 4).
- **Max File Size:** Warning threshold for large binaries (default: 100 MB).
- **Logging Level:** Adjust logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
- **Dependency Status Table:** Real-time inspection of required and optional packages.

---

## 9. Keyboard Shortcuts

- `Ctrl+O`: Open File Dialog (automatically switches to File Analyzer and begins analysis)
- `Ctrl+,`: Open Settings Page
- `F1`: Open About & Security Policy Dialog
