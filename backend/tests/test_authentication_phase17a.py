"""Phase 17A authentication + protected API tests."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.conftest import (
    DEMO_AGENT_TOKEN,
    DEMO_DISABLED_TOKEN,
    DEMO_READONLY_TOKEN,
    DEMO_TENANT_B_TOKEN,
    DEMO_USER_TOKEN,
)


def test_health_remains_public(raw_client: TestClient) -> None:
    r = raw_client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_missing_token_audit_401(raw_client: TestClient) -> None:
    r = raw_client.get("/api/v1/audit")
    assert r.status_code == 401
    body = r.json()
    assert body["error"]["code"] in {
        "MISSING_AUTHORIZATION_HEADER",
        "AUTHENTICATION_REQUIRED",
    }


def test_invalid_token_401(raw_client: TestClient) -> None:
    r = raw_client.get(
        "/api/v1/audit",
        headers={"Authorization": "Bearer totally-invalid-token"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_TOKEN"


def test_malformed_header_401(raw_client: TestClient) -> None:
    r = raw_client.get(
        "/api/v1/audit",
        headers={"Authorization": "NotBearer xyz"},
    )
    assert r.status_code == 401


def test_disabled_principal_401(raw_client: TestClient) -> None:
    r = raw_client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {DEMO_DISABLED_TOKEN}"},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "PRINCIPAL_DISABLED"


def test_valid_token_session(raw_client: TestClient) -> None:
    r = raw_client.get(
        "/api/v1/auth/session",
        headers={"Authorization": f"Bearer {DEMO_USER_TOKEN}"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["principal_id"] == "user:demo"
    assert data["tenant_id"] == "tenant-a"
    assert "audit:read:own-tenant" in data["permissions"]


def test_audit_with_valid_auth(client: TestClient) -> None:
    r = client.get("/api/v1/audit")
    assert r.status_code == 200
    assert "items" in r.json()


def test_agent_no_audit_access(raw_client: TestClient) -> None:
    r = raw_client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {DEMO_AGENT_TOKEN}"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "CAPABILITY_MISSING"


def test_readonly_audit_ok(raw_client: TestClient) -> None:
    r = raw_client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {DEMO_READONLY_TOKEN}"},
    )
    assert r.status_code == 200


def test_cross_tenant_audit_detail_deny(client: TestClient, db_session) -> None:
    from app.core.enums import SourceType
    from app.models import SecurityEvent
    from app.services.hashing import sha256_hex

    event = SecurityEvent(
        source_type=SourceType.USER_MESSAGE.value,
        content_hash=sha256_hex("x"),
        content_length=1,
        detection_label="BENIGN",
        attack_types=[],
        policy_decision="ALLOW",
        reason_codes=[],
        detector_summary={},
        pipeline_stages=[],
        risk_factors=[],
        simulated=True,
        event_metadata={"tenant_id": "tenant-b", "principal_id": "user:tenant-b"},
    )
    db_session.add(event)
    db_session.commit()

    r = client.get(f"/api/v1/audit/{event.id}")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "TENANT_MISMATCH"


def test_client_cannot_override_tenant_on_audit(client: TestClient) -> None:
    # Query tenant_id is ignored; still 200 for own tenant listing
    r = client.get("/api/v1/audit?tenant_id=tenant-b")
    assert r.status_code == 200


def test_dashboard_requires_auth(raw_client: TestClient) -> None:
    assert raw_client.get("/api/v1/dashboard/status").status_code == 401


def test_inspect_requires_auth(raw_client: TestClient) -> None:
    r = raw_client.post(
        "/api/v1/inspect",
        json={"content": "hello", "source_type": "USER_MESSAGE", "demo_tool": False},
    )
    assert r.status_code == 401


def test_token_not_in_audit_metadata(client: TestClient) -> None:
    r = client.post(
        "/api/v1/inspect",
        json={
            "content": "What is the PTO policy?",
            "source_type": "USER_MESSAGE",
            "demo_tool": False,
        },
    )
    assert r.status_code == 200
    event_id = r.json().get("event_id")
    assert event_id
    detail = client.get(f"/api/v1/audit/{event_id}").json()
    meta = detail.get("metadata") or {}
    blob = str(meta) + str(detail)
    assert DEMO_USER_TOKEN not in blob
    assert "Bearer" not in blob
    assert meta.get("tenant_id") == "tenant-a"
    assert meta.get("principal_id") == "user:demo"


def test_authenticate_bearer_unit() -> None:
    from app.authentication.authenticator import authenticate_bearer

    ok = authenticate_bearer(f"Bearer {DEMO_USER_TOKEN}")
    assert ok.authenticated is True
    assert ok.principal_id == "user:demo"
    # Result must never contain the raw token
    assert DEMO_USER_TOKEN not in ok.model_dump_json()

    bad = authenticate_bearer(None)
    assert bad.authenticated is False


def test_openapi_exposes_bearer_authorize_scheme(raw_client: TestClient) -> None:
    schema = raw_client.get("/openapi.json").json()
    scheme = schema["components"]["securitySchemes"]["BearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"
    operation = schema["paths"]["/api/v1/dashboard/evaluation"]["get"]
    assert {"BearerAuth": []} in operation["security"]
    param_names = [p["name"].lower() for p in operation.get("parameters", [])]
    assert "authorization" not in param_names
