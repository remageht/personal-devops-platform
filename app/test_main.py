"""Personal DevOps Platform — Complete Test Suite.

Tests cover all 13 required scenarios:
1. 401 Unauthorized without token for protected endpoints.
2. 403 Forbidden for non-admin users attempting admin actions.
3. 404 Not Found for path traversal or unapproved script names.
4. 422 Unprocessable Entity for query parameter validation failure (lines > 1000).
5. 429 Too Many Requests with 'Retry-After' header upon rate limit breach.
6. 403 Forbidden for clean-docker.sh when ALLOW_PRUNE=0.
7. 403 Forbidden for devops-platform-app stop when ALLOW_SELF_STOP=0.
8. 200 OK for /health with status 'ok' and uptime_seconds.
9. 200 OK for /ready on docker success, and 503 on docker daemon failure.
10. Presence of security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
11. 200 OK on /auth/login with valid credentials, 401 on invalid credentials.
12. 200 OK on /auth/refresh with valid refresh token, 401 on invalid token.
13. Legacy X-API-Token behavior: 401 when LEGACY_TOKEN_ALLOW=0, 200 when LEGACY_TOKEN_ALLOW=1.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Ensure repo root is on python path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import (
    _hits,
    _resolve_script,
    app,
    create_access_token,
    create_refresh_token,
)

# ---------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset the sliding window rate limiter before and after each test."""
    _hits.clear()
    yield
    _hits.clear()


@pytest.fixture
def mock_docker(monkeypatch):
    """Safely mock the Docker client and container operations."""
    client_mock = MagicMock()
    container_mock = MagicMock()
    container_mock.short_id = "c1234567"
    container_mock.name = "test-container"
    container_mock.status = "running"
    container_mock.image.tags = ["test-image:v1.0"]
    container_mock.logs.return_value = b"2026-09-27T12:00:00Z INFO starting app...\n2026-09-27T12:00:01Z INFO ready\n"

    client_mock.containers.list.return_value = [container_mock]
    client_mock.containers.get.return_value = container_mock
    client_mock.ping.return_value = True

    monkeypatch.setattr("app.main.get_docker", lambda: client_mock)
    return client_mock, container_mock


@pytest.fixture
def mock_subprocess(monkeypatch):
    """Safely mock subprocess.run so scripts are never executed destructively."""
    proc_mock = subprocess.CompletedProcess(
        args=["bash", "test.sh"],
        returncode=0,
        stdout="Mock script output OK\n",
        stderr="",
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: proc_mock)
    return proc_mock


@pytest.fixture
def client(mock_docker, mock_subprocess):
    """Provide a TestClient with mocked docker and subprocess."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers():
    """Generate authorization headers for admin role."""
    token = create_access_token(username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_headers():
    """Generate authorization headers for standard user role."""
    token = create_access_token(username="dev_user", role="user")
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- Test 1: 401 without token


def test_1_unauthenticated_endpoints_return_401(client):
    """Verify protected endpoints return 401 when accessed without an auth token."""
    protected_get_endpoints = [
        "/api/status",
        "/api/scripts",
        "/api/container/test-container/logs",
    ]
    for endpoint in protected_get_endpoints:
        response = client.get(endpoint)
        assert response.status_code == 401, f"Expected 401 for GET {endpoint}, got {response.status_code}"
        assert "detail" in response.json()

    protected_post_endpoints = [
        ("/api/run-script", {"script_name": "system-info.sh"}),
        ("/api/container/test-container/action", {"action": "restart"}),
    ]
    for endpoint, payload in protected_post_endpoints:
        response = client.post(endpoint, json=payload)
        assert response.status_code == 401, f"Expected 401 for POST {endpoint}, got {response.status_code}"
        assert "detail" in response.json()


# ---------------------------------------------------------------- Test 2: 403 user -> admin


def test_2_user_role_forbidden_from_admin_endpoints(client, user_headers):
    """Verify user token (role='user') receives 403 on admin-only endpoints, but 200 on read endpoints."""
    # User can read status and script list
    res_status = client.get("/api/status", headers=user_headers)
    assert res_status.status_code == 200, f"User should access /api/status, got {res_status.status_code}"

    res_scripts = client.get("/api/scripts", headers=user_headers)
    assert res_scripts.status_code == 200, f"User should access /api/scripts, got {res_scripts.status_code}"

    # User cannot run scripts -> 403
    res_run = client.post("/api/run-script", json={"script_name": "system-info.sh"}, headers=user_headers)
    assert res_run.status_code == 403, f"User running script should return 403, got {res_run.status_code}"
    assert "detail" in res_run.json()

    # User cannot perform container actions -> 403
    res_action = client.post("/api/container/c1/action", json={"action": "restart"}, headers=user_headers)
    assert res_action.status_code == 403, f"User container action should return 403, got {res_action.status_code}"

    # User cannot read container logs -> 403
    res_logs = client.get("/api/container/c1/logs", headers=user_headers)
    assert res_logs.status_code == 403, f"User reading logs should return 403, got {res_logs.status_code}"


# ---------------------------------------------------------------- Test 3: 404 path traversal & unapproved script


def test_3_path_traversal_and_unapproved_script_handled(client, admin_headers):
    """Verify path traversal (../../x.sh) and unapproved script names are rejected."""
    # 1. Unapproved script name that matches regex but is not in ALLOWED_SCRIPTS -> 404
    resp_unapproved = client.post(
        "/api/run-script",
        json={"script_name": "unapproved-script.sh"},
        headers=admin_headers,
    )
    assert resp_unapproved.status_code == 404
    assert "detail" in resp_unapproved.json()

    # 2. Path traversal in API request is rejected (404 or 422 depending on schema/regex layer)
    resp_traversal = client.post(
        "/api/run-script",
        json={"script_name": "../../x.sh"},
        headers=admin_headers,
    )
    assert resp_traversal.status_code in (404, 422)

    # 3. Direct unit check on script resolver confirms 404 for traversal and unlisted scripts
    with pytest.raises(HTTPException) as exc_traversal:
        _resolve_script("../../x.sh")
    assert exc_traversal.value.status_code == 404

    with pytest.raises(HTTPException) as exc_unapproved:
        _resolve_script("hack.sh")
    assert exc_unapproved.value.status_code == 404


# ---------------------------------------------------------------- Test 4: 422 lines=5000 validation


def test_4_container_logs_validation_lines_limit_returns_422(client, admin_headers):
    """Verify validation error 422 when lines parameter exceeds maximum allowed (1000) or is < 1."""
    # lines=5000 exceeds maximum of 1000
    res_over = client.get("/api/container/test-container/logs?lines=5000", headers=admin_headers)
    assert res_over.status_code == 422, f"Expected 422 for lines=5000, got {res_over.status_code}"

    # lines=0 is less than minimum of 1
    res_under = client.get("/api/container/test-container/logs?lines=0", headers=admin_headers)
    assert res_under.status_code == 422, f"Expected 422 for lines=0, got {res_under.status_code}"

    # Valid lines within [1, 1000] succeeds
    res_valid = client.get("/api/container/test-container/logs?lines=150", headers=admin_headers)
    assert res_valid.status_code == 200


# ---------------------------------------------------------------- Test 5: 429 flood rate limit


def test_5_rate_limit_flood_returns_429_with_retry_after(client, monkeypatch):
    """Simulate requests exceeding rate limit, verify 429 status code and 'Retry-After' header present."""
    _hits.clear()
    limit = 20  # Unauthenticated rate limit per minute

    # Mock pwd verification so 20 rapid requests run in milliseconds without slow bcrypt derivation
    monkeypatch.setattr("app.main.pwd_context.verify", lambda *args: False)

    # Fire requests up to the allowed limit
    for _ in range(limit):
        res = client.post("/auth/login", json={"username": "wrong", "password": "wrong"})
        assert res.status_code == 401

    # The (limit + 1)th request must trigger rate limit
    res_limited = client.post("/auth/login", json={"username": "wrong", "password": "wrong"})
    assert res_limited.status_code == 429, f"Expected 429, got {res_limited.status_code}"
    assert "retry-after" in [k.lower() for k in res_limited.headers]
    assert res_limited.headers.get("Retry-After") == "60" or res_limited.headers.get("retry-after") == "60"


# ---------------------------------------------------------------- Test 6: 403 clean-docker without ALLOW_PRUNE=1


def test_6_clean_docker_requires_allow_prune(client, admin_headers, monkeypatch):
    """Verify clean-docker.sh returns 403 when ALLOW_PRUNE is 0, and succeeds when ALLOW_PRUNE is 1."""
    # 1. When ALLOW_PRUNE is False (default)
    monkeypatch.setattr("app.main.ALLOW_PRUNE", False)
    res_blocked = client.post(
        "/api/run-script",
        json={"script_name": "clean-docker.sh"},
        headers=admin_headers,
    )
    assert res_blocked.status_code == 403
    assert "ALLOW_PRUNE=1" in res_blocked.json()["detail"]

    # 2. When ALLOW_PRUNE is True
    monkeypatch.setattr("app.main.ALLOW_PRUNE", True)
    res_allowed = client.post(
        "/api/run-script",
        json={"script_name": "clean-docker.sh"},
        headers=admin_headers,
    )
    assert res_allowed.status_code == 200
    assert res_allowed.json()["status"] == "success"


# ---------------------------------------------------------------- Test 7: 403 self-stop without ALLOW_SELF_STOP=1


def test_7_self_stop_requires_allow_self_stop(client, admin_headers, monkeypatch):
    """Verify stopping devops-platform-app returns 403 when ALLOW_SELF_STOP is 0."""
    # 1. Stop action on devops-platform-app is blocked when ALLOW_SELF_STOP is False
    monkeypatch.setattr("app.main.ALLOW_SELF_STOP", False)
    res_stop_blocked = client.post(
        "/api/container/devops-platform-app/action",
        json={"action": "stop"},
        headers=admin_headers,
    )
    assert res_stop_blocked.status_code == 403
    assert "ALLOW_SELF_STOP=1" in res_stop_blocked.json()["detail"]

    # 2. Restart action on devops-platform-app is permitted
    res_restart = client.post(
        "/api/container/devops-platform-app/action",
        json={"action": "restart"},
        headers=admin_headers,
    )
    assert res_restart.status_code == 200

    # 3. Stop action on other containers is permitted
    res_other_stop = client.post(
        "/api/container/other-container/action",
        json={"action": "stop"},
        headers=admin_headers,
    )
    assert res_other_stop.status_code == 200

    # 4. When ALLOW_SELF_STOP is True, stop action succeeds
    monkeypatch.setattr("app.main.ALLOW_SELF_STOP", True)
    res_stop_allowed = client.post(
        "/api/container/devops-platform-app/action",
        json={"action": "stop"},
        headers=admin_headers,
    )
    assert res_stop_allowed.status_code == 200


# ---------------------------------------------------------------- Test 8: /health returns 200


def test_8_health_endpoint_returns_ok_and_uptime(client):
    """Verify /health returns 200 with status 'ok' and uptime_seconds float >= 0."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], (int, float))
    assert data["uptime_seconds"] >= 0


# ---------------------------------------------------------------- Test 9: /ready with docker ping / failure


def test_9_ready_endpoint_success_and_failure(client, monkeypatch):
    """Verify /ready returns 200 when docker ping succeeds and 503 when docker is unavailable."""
    # 1. Success case: docker ping succeeds
    mock_cli = MagicMock()
    mock_cli.ping.return_value = True
    monkeypatch.setattr("app.main.get_docker", lambda: mock_cli)

    res_ok = client.get("/ready")
    assert res_ok.status_code == 200
    assert res_ok.json() == {"status": "ready"}

    # 2. Failure case: docker raises exception
    def failing_docker():
        raise HTTPException(status_code=503, detail="Docker daemon недоступен")

    monkeypatch.setattr("app.main.get_docker", failing_docker)
    res_fail = client.get("/ready")
    assert res_fail.status_code == 503
    assert "Docker" in res_fail.json()["detail"]


# ---------------------------------------------------------------- Test 10: Security headers present


def test_10_security_headers_present_on_responses(client):
    """Verify standard security headers are present on responses."""
    res = client.get("/health")
    assert res.status_code == 200

    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"
    assert "Content-Security-Policy" in res.headers


# ---------------------------------------------------------------- Test 11: /auth/login credentials


def test_11_auth_login_valid_and_invalid_credentials(client, monkeypatch):
    """Verify /auth/login returns access & refresh tokens on valid credentials, 401 on invalid."""
    # Ensure standard admin credentials for test
    monkeypatch.setattr("app.main.ADMIN_USER", "admin")

    # 1. Valid credentials
    res_valid = client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert res_valid.status_code == 200
    data = res_valid.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"

    # 2. Invalid password
    res_wrong_pass = client.post(
        "/auth/login",
        json={"username": "admin", "password": "incorrect-password"},
    )
    assert res_wrong_pass.status_code == 401

    # 3. Invalid username
    res_wrong_user = client.post(
        "/auth/login",
        json={"username": "wrong_user", "password": "admin"},
    )
    assert res_wrong_user.status_code == 401


# ---------------------------------------------------------------- Test 12: /auth/refresh tokens


def test_12_auth_refresh_valid_and_invalid_tokens(client):
    """Verify /auth/refresh returns new access token with valid refresh token, 401 on invalid."""
    # 1. Valid refresh token
    refresh_tok = create_refresh_token(username="admin", role="admin")
    res_refresh = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_tok},
    )
    assert res_refresh.status_code == 200
    data = res_refresh.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # 2. Invalid / corrupted token
    res_invalid = client.post(
        "/auth/refresh",
        json={"refresh_token": "invalid.jwt.token.here"},
    )
    assert res_invalid.status_code == 401

    # 3. Supplying an access token instead of a refresh token -> 401
    access_tok = create_access_token(username="admin", role="admin")
    res_wrong_type = client.post(
        "/auth/refresh",
        json={"refresh_token": access_tok},
    )
    assert res_wrong_type.status_code == 401
    assert "refresh" in res_wrong_type.json()["detail"]


# ---------------------------------------------------------------- Test 13: Legacy token behavior


def test_13_legacy_token_allow_behavior(client, monkeypatch):
    """Verify legacy X-API-Token: 401 when LEGACY_TOKEN_ALLOW=0, 200 when LEGACY_TOKEN_ALLOW=1."""
    legacy_secret = "ci-test-mock-token-xyz"
    monkeypatch.setattr("app.main.API_TOKEN", legacy_secret)

    # 1. When LEGACY_TOKEN_ALLOW is False (default)
    monkeypatch.setattr("app.main.LEGACY_TOKEN_ALLOW", False)
    res_disallowed = client.get(
        "/api/status",
        headers={"X-API-Token": legacy_secret},
    )
    assert res_disallowed.status_code == 401
    assert "Legacy" in res_disallowed.json()["detail"] or "авторизация" in res_disallowed.json()["detail"]

    # 2. When LEGACY_TOKEN_ALLOW is True and valid token provided
    monkeypatch.setattr("app.main.LEGACY_TOKEN_ALLOW", True)
    res_allowed = client.get(
        "/api/status",
        headers={"X-API-Token": legacy_secret},
    )
    assert res_allowed.status_code == 200
    assert res_allowed.json()["status"] == "healthy"

    # 3. When LEGACY_TOKEN_ALLOW is True but incorrect token provided -> 401
    res_wrong = client.get(
        "/api/status",
        headers={"X-API-Token": "wrong-legacy-token"},
    )
    assert res_wrong.status_code == 401
