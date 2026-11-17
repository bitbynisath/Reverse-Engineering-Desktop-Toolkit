"""Dependency detection and environment status inspection."""

from __future__ import annotations

import importlib.util
import logging
import platform
import sys
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DependencyInfo:
    """Status information for an external dependency."""

    name: str
    required: bool
    installed: bool
    version: str | None
    description: str
    target_phase: str


def check_module_installed(module_name: str) -> tuple[bool, str | None]:
    """Check if a Python module is installed and retrieve its version safely."""
    spec = importlib.util.find_spec(module_name)
    if spec is None:
        return False, None

    try:
        mod = importlib.import_module(module_name)
        version = getattr(mod, "__version__", None)
        if version is None and hasattr(mod, "version"):
            v = mod.version
            version = str(v) if not callable(v) else str(v())
        return True, str(version) if version else "Installed (no version tag)"
    except Exception as exc:
        logger.debug("Error checking version for %s: %s", module_name, exc)
        return True, "Installed"


def get_all_dependencies_status() -> list[DependencyInfo]:
    """Inspect and return the status of core and optional dependencies."""
    deps = [
        # Core
        ("PySide6", True, "Desktop GUI framework (Qt 6 bindings)", "Phase 1"),
        ("pytest", False, "Automated unit and integration test framework", "Phase 1"),
        # Future Analyzers
        ("pefile", False, "Windows PE header and structure parser", "Phase 5"),
        ("capstone", False, "Multi-architecture disassembly engine", "Phase 6"),
        ("lief", False, "Multi-format binary parser (PE/ELF/Mach-O)", "Phase 8"),
        ("yara", False, "Pattern-matching swiss army knife for binaries", "Phase 8"),
        ("matplotlib", False, "Entropy and visualization plotting", "Phase 8"),
        ("reportlab", False, "PDF export and document generation", "Phase 9"),
    ]

    results: list[DependencyInfo] = []
    for mod_name, is_req, desc, phase in deps:
        installed, ver = check_module_installed(mod_name)
        results.append(
            DependencyInfo(
                name=mod_name,
                required=is_req,
                installed=installed,
                version=ver,
                description=desc,
                target_phase=phase,
            )
        )

    return results


def get_system_environment_info() -> dict[str, str]:
    """Return dictionary of OS and Python execution environment details."""
    return {
        "python_version": sys.version.split()[0],
        "python_compiler": platform.python_compiler(),
        "platform": platform.platform(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
    }
