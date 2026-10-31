"""Typed failures shared by every offline REA reader.

Each error carries a stable machine-readable ``code`` so callers can react
without matching human text, following REA's typed-failure convention.
"""

from __future__ import annotations

from typing import Any


class ReaError(Exception):
    """Base class for all recoverable CLI failures."""

    code = "error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        hint: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.hint = hint
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
            },
        }
        if self.hint:
            payload["error"]["hint"] = self.hint
        if self.detail:
            payload["error"]["detail"] = self.detail
        return payload


class InvalidRequest(ReaError):
    code = "invalid_request"


class UnsupportedFormat(ReaError):
    code = "unsupported_format"


class FormatError(ReaError):
    code = "malformed_artifact"


class LimitError(ReaError):
    code = "limit_exceeded"


class NetworkRefused(ReaError):
    code = "network_refused"


class EngineUnavailable(ReaError):
    code = "engine_unavailable"
