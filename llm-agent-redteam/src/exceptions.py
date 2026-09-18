"""Custom exceptions for the LLM Agent Red-Teaming & Security Evaluation Framework.

This module defines domain-specific exceptions to provide clear, actionable error
messages without leaking sensitive system internals or obscuring root causes.
"""

from typing import Any


class RedTeamFrameworkError(Exception):
    """Base exception for all framework-specific errors."""

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details is not None:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigError(RedTeamFrameworkError):
    """Raised when mandatory configuration is missing or invalid."""
    pass


class ToolExecutionError(RedTeamFrameworkError):
    """Raised when a mock tool fails validation, encounters a security boundary, or faults.

    Examples include path traversal attempts, non-SELECT SQL queries, malformed email
    recipients, or missing target files.
    """
    pass


class AgentError(RedTeamFrameworkError):
    """Raised when an error occurs during agent orchestration or model API calls."""
    pass
