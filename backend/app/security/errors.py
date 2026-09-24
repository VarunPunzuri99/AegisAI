"""Preprocessing exceptions — reportable, not final ALLOW/BLOCK decisions."""


class PreprocessingError(Exception):
    """Raised when input cannot enter the normalization pipeline."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)
