from typing import Any


class RedTeamFrameworkError(Exception):
    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details is not None:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigError(RedTeamFrameworkError):
    pass


class ToolExecutionError(RedTeamFrameworkError):
    pass


class AgentError(RedTeamFrameworkError):
    pass
