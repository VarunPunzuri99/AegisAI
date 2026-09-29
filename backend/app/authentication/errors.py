"""Authentication errors — HTTP 401/403 without leaking tokens."""

from __future__ import annotations

from app.api.errors import AppError


class AuthenticationError(AppError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code=code, message=message, status_code=401)


class AuthorizationDeniedError(AppError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code=code, message=message, status_code=403)
