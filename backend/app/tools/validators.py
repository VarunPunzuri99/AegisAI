"""Per-tool parameter validators (strict schema — reject extras)."""

from __future__ import annotations

from typing import Any

from app.tools.types import ToolDefinition, ToolReasonCode


class ParameterValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


_FORBIDDEN_KEYS = frozenset(
    {
        "shell_command",
        "command",
        "url",
        "smtp_server",
        "headers",
        "credential",
        "credentials",
        "password",
        "api_key",
        "delete_all",
        "send_to",
    }
)


def validate_parameters(
    tool: ToolDefinition,
    parameters: dict[str, Any],
) -> None:
    """Raise ParameterValidationError on invalid params. Deterministic."""
    if not isinstance(parameters, dict):
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            "Parameters must be a dict.",
        )

    keys = set(parameters.keys())
    forbidden = keys & _FORBIDDEN_KEYS
    if forbidden:
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            f"Forbidden parameter(s): {sorted(forbidden)}",
        )

    extra = keys - set(tool.allowed_parameters)
    if extra:
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            f"Unexpected parameter(s): {sorted(extra)}",
        )

    missing = set(tool.required_parameters) - keys
    if missing:
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            f"Missing required parameter(s): {sorted(missing)}",
        )

    # Tool-specific constraints
    name = tool.tool_name
    if name in {"search_public_documents", "search_private_documents"}:
        _validate_search(parameters)
    elif name in {"read_public_document", "read_private_document"}:
        _validate_read(parameters)
    elif name == "write_record":
        _validate_write(parameters)
    elif name == "send_email":
        _validate_email(parameters)
    elif name == "delete_record":
        _validate_delete(parameters)


def _validate_search(params: dict[str, Any]) -> None:
    query = params.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            "query must be a non-empty string.",
        )
    if "limit" in params:
        limit = params["limit"]
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ParameterValidationError(
                ToolReasonCode.INVALID_PARAMETERS.value,
                "limit must be an integer.",
            )
        if limit < 1 or limit > 50:
            raise ParameterValidationError(
                ToolReasonCode.INVALID_PARAMETERS.value,
                "limit must be between 1 and 50.",
            )


def _validate_read(params: dict[str, Any]) -> None:
    doc_id = params.get("document_id")
    if not isinstance(doc_id, str) or not doc_id.strip():
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            "document_id must be a non-empty string.",
        )


def _validate_write(params: dict[str, Any]) -> None:
    for key in ("record_id", "content"):
        val = params.get(key)
        if not isinstance(val, str) or not val.strip():
            raise ParameterValidationError(
                ToolReasonCode.INVALID_PARAMETERS.value,
                f"{key} must be a non-empty string.",
            )


def _validate_email(params: dict[str, Any]) -> None:
    for key in ("recipient", "subject", "body"):
        val = params.get(key)
        if not isinstance(val, str) or not val.strip():
            raise ParameterValidationError(
                ToolReasonCode.INVALID_PARAMETERS.value,
                f"{key} must be a non-empty string.",
            )
    recipient = params["recipient"]
    if "@" not in recipient or " " in recipient.strip():
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            "recipient must look like an email address.",
        )
    if "attachment_ids" in params:
        aids = params["attachment_ids"]
        if not isinstance(aids, list) or not all(isinstance(x, str) for x in aids):
            raise ParameterValidationError(
                ToolReasonCode.INVALID_PARAMETERS.value,
                "attachment_ids must be a list of strings.",
            )


def _validate_delete(params: dict[str, Any]) -> None:
    record_id = params.get("record_id")
    if not isinstance(record_id, str) or not record_id.strip():
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            "record_id must be a non-empty string.",
        )
    if params.get("delete_all") is True:
        raise ParameterValidationError(
            ToolReasonCode.INVALID_PARAMETERS.value,
            "delete_all is not supported.",
        )
