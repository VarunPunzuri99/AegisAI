"""Pytest configuration and shared fixtures.

Uses an isolated in-memory SQLite database so tests do not require PostgreSQL.
Production remains PostgreSQL + Alembic.

Phase 17A: default TestClient attaches a development bearer token so existing
API tests remain green. Auth-negative tests use `raw_client` without headers.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import StaticPool, create_engine
from sqlalchemy.orm import Session, sessionmaker

# Configure demo tokens BEFORE importing app/settings (cached Settings).
_TEST_TOKENS = {
    "AEGIS_AUTH_MODE": "development",
    "AEGIS_DEMO_TOKEN_USER": "test-token-user-demo",
    "AEGIS_DEMO_TOKEN_READONLY": "test-token-user-readonly",
    "AEGIS_DEMO_TOKEN_AGENT": "test-token-agent-demo",
    "AEGIS_DEMO_TOKEN_SERVICE": "test-token-service-runtime",
    "AEGIS_DEMO_TOKEN_DISABLED": "test-token-user-disabled",
    "AEGIS_DEMO_TOKEN_TENANT_B": "test-token-user-tenant-b",
}
for _k, _v in _TEST_TOKENS.items():
    os.environ[_k] = _v  # force test tokens (do not inherit empty .env placeholders)


from app.core.config import get_settings
from app.core.database import get_db
from app.main import app
from app.models import Base

get_settings.cache_clear()

DEMO_USER_TOKEN = os.environ["AEGIS_DEMO_TOKEN_USER"]
DEMO_READONLY_TOKEN = os.environ["AEGIS_DEMO_TOKEN_READONLY"]
DEMO_AGENT_TOKEN = os.environ["AEGIS_DEMO_TOKEN_AGENT"]
DEMO_TENANT_B_TOKEN = os.environ["AEGIS_DEMO_TOKEN_TENANT_B"]
DEMO_DISABLED_TOKEN = os.environ["AEGIS_DEMO_TOKEN_DISABLED"]


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def db_session(db_engine) -> Generator[Session, None, None]:
    TestingSessionLocal = sessionmaker(
        bind=db_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def raw_client(db_session: Session) -> Generator[TestClient, None, None]:
    """TestClient without Authorization header."""

    def _override_get_db() -> Generator[Session, None, None]:
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def client(raw_client: TestClient) -> Generator[TestClient, None, None]:
    """Authenticated as user:demo (tenant-a) by default."""
    raw_client.headers.update({"Authorization": f"Bearer {DEMO_USER_TOKEN}"})
    yield raw_client
