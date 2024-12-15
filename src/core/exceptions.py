"""
Custom exceptions for Argus.

Provides a hierarchy of exceptions for different error types.
"""


class ArgusError(Exception):
    """Base exception for all Argus errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class ConfigurationError(ArgusError):
    """Raised when there's a configuration issue."""

    pass


class ScanError(ArgusError):
    """Raised when a scan fails."""

    def __init__(
        self, message: str, scan_type: str | None = None, details: dict | None = None
    ):
        super().__init__(message, details)
        self.scan_type = scan_type


class AWSError(ArgusError):
    """Raised when AWS API operations fail."""

    def __init__(
        self,
        message: str,
        service: str | None = None,
        operation: str | None = None,
        details: dict | None = None,
    ):
        super().__init__(message, details)
        self.service = service
        self.operation = operation


