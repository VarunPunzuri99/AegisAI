"""Domain enumerations for the scan pipeline."""

from enum import StrEnum


class SourceType(StrEnum):
    """Origin channel for inspected content (file processing planned later)."""

    USER_MESSAGE = "USER_MESSAGE"
    WEB_PAGE = "WEB_PAGE"
    PDF = "PDF"
    DOCX = "DOCX"
    EMAIL = "EMAIL"
    MARKDOWN = "MARKDOWN"
    HTML = "HTML"
    API_RESPONSE = "API_RESPONSE"
    OCR = "OCR"
    SOURCE_CODE = "SOURCE_CODE"
    IMAGE = "IMAGE"


class ScanStatus(StrEnum):
    """Lifecycle status of a scan record."""

    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanDecision(StrEnum):
    """Policy decision outcome persisted on Scan metadata."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    SANITIZE = "SANITIZE"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"
    ERROR = "ERROR"


class Severity(StrEnum):
    """Risk severity label (not computed in Phase 2)."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuditEventType(StrEnum):
    """Known audit event types for future pipeline instrumentation."""

    SCAN_CREATED = "SCAN_CREATED"
    CONTENT_NORMALIZED = "CONTENT_NORMALIZED"
    RULE_DETECTED = "RULE_DETECTED"
    PROMPT_GUARD_RESULT = "PROMPT_GUARD_RESULT"
    LLM_CLASSIFICATION = "LLM_CLASSIFICATION"
    RISK_EVALUATED = "RISK_EVALUATED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    DECISION_MADE = "DECISION_MADE"
    SECURITY_EVENT_RECORDED = "SECURITY_EVENT_RECORDED"
    TOOL_BLOCKED = "TOOL_BLOCKED"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
