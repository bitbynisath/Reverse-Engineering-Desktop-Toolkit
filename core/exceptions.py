"""Application exception hierarchy for PyRE Studio."""

class PyREStudioError(Exception):
    """Base class for all PyRE Studio exceptions."""


class ConfigurationError(PyREStudioError):
    """Raised when application configuration is invalid or inaccessible."""


class ValidationError(PyREStudioError):
    """Raised when file or user parameter validation fails."""


class FileAccessError(PyREStudioError):
    """Raised when reading or accessing a file fails."""


class AnalysisError(PyREStudioError):
    """Base class for errors occurring during analysis."""


class UnsupportedFormatError(AnalysisError):
    """Raised when a file format or architecture is not supported."""
