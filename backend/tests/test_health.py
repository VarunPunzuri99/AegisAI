"""Health and root endpoint tests."""


def test_root_returns_application_info(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "AegisAI"
    assert payload["status"] == "running"
    assert "version" in payload


def test_health_returns_healthy(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["service"] == "aegisai-backend"
