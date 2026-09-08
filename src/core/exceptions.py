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


class DatabaseError(ArgusError):
    """Raised when database operations fail."""

    pass


class ValidationError(ArgusError):
    """Raised when input validation fails."""

    def __init__(self, message: str, field: str | None = None, details: dict | None = None):
        super().__init__(message, details)
        self.field = field


class GitError(ArgusError):
    """Raised when Git operations fail."""

    def __init__(
        self, message: str, repository: str | None = None, details: dict | None = None
    ):
        super().__init__(message, details)
        self.repository = repository


class Neo4jError(ArgusError):
    """Raised when Neo4j operations fail."""

    pass


class SecretScanError(ScanError):
    """Raised when secret scanning fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, scan_type="secret", details=details)


class IaCScanError(ScanError):
    """Raised when IaC scanning fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, scan_type="iac", details=details)


class CloudScanError(ScanError):
    """Raised when cloud scanning fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, scan_type="cloud", details=details)


class IAMAnalysisError(ScanError):
    """Raised when IAM analysis fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, scan_type="iam", details=details)
