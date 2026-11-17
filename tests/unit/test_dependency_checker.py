"""Unit tests for environment and dependency inspection."""

from core.dependency_checker import (
    check_module_installed,
    get_all_dependencies_status,
    get_system_environment_info,
)


def test_check_module_installed_existing():
    """Verify detection of an existing module like pytest or sys."""
    installed, version = check_module_installed("pytest")
    assert installed is True
    assert version is not None


def test_check_module_installed_nonexistent():
    """Verify detection of a definitely non-existent module."""
    installed, version = check_module_installed("definitely_nonexistent_mod_xyz")
    assert installed is False
    assert version is None


def test_get_all_dependencies_status():
    """Verify comprehensive dependency status returns valid metadata."""
    statuses = get_all_dependencies_status()
    assert len(statuses) >= 6
    names = [s.name for s in statuses]
    assert "PySide6" in names
    assert "pytest" in names
    assert "pefile" in names
    assert "capstone" in names


def test_get_system_environment_info():
    """Verify system environment info dictionary contains required keys."""
    env = get_system_environment_info()
    assert "python_version" in env
    assert "platform" in env
    assert "os_name" in env
