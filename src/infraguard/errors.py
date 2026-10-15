"""Domain exceptions and stable CLI exit categories."""


class InfraGuardError(Exception):
    """Base error for expected InfraGuard failures."""


class ToolNotFoundError(InfraGuardError):
    """Raised when an external validator is unavailable."""


class ToolError(InfraGuardError):
    """Raised when an external tool exits unexpectedly."""


class ClusterUnreachableError(InfraGuardError):
    """Raised when Kubernetes cannot be contacted."""


class PolicyCatalogError(InfraGuardError):
    """Raised for invalid or inconsistent policy metadata."""


class ReadOnlyViolation(InfraGuardError):
    """Raised when an MCP operation attempts mutation."""


class PathGuardError(InfraGuardError):
    """Raised when a path escapes the configured allowed root."""

