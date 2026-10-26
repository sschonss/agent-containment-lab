"""Clean failures for the lab agent. Messages are safe to print."""


class ToolError(Exception):
    """Expected tool failure. The message must not include secrets or tracebacks."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
