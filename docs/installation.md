# Installation Guide

This document describes how to install, configure, and set up the development environment for PyRE Studio.

## Prerequisites

- **Operating System:** Windows 10 or Windows 11 (64-bit). Compatible with Linux and macOS.
- **Python Version:** Python 3.12 or newer (Python 3.14 verified).
- **Package Manager:** `pip` (included with standard Python).

## Step-by-Step Environment Setup

### 1. Clone or Open the Project
Open a terminal in the root folder of PyRE Studio:

```bash
cd "desktop toolkit"
```

### 2. Create a Virtual Environment (Recommended)
Creating an isolated virtual environment prevents conflicts with system packages:

```bash
python -m venv .venv
```

Activate the virtual environment:
- **Windows (PowerShell):**
  ```powershell
  .venv\Scripts\Activate.ps1
  ```
- **Windows (Command Prompt):**
  ```cmd
  .venv\Scripts\activate.bat
  ```

### 3. Install Dependencies
Install the required dependencies for Phase 1:

```bash
pip install -r requirements.txt
```

To install development and testing tools:
```bash
pip install pytest pytest-qt
```

### 4. Verify Installation
Execute the automated test suite to verify your setup:

```bash
pytest
```
Expected output: `18 passed in ...s`.

### 5. Launch PyRE Studio
Start the desktop application:

```bash
python main.py
```
