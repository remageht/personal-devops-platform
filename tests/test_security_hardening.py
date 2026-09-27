"""Security Hardening Integration Tests."""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient
from jose import jwt

# Set env before importing app
os.environ["JWT_SECRET"] = "test-secret-at-least-32-chars-for-dev-and-testing-12345"
os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1,testserver"
os.environ["LEGACY_TOKEN_ALLOW"] = "0"
os.environ["API_TOKEN"] = "legacy-secret-token"
os.environ["ADMIN_USER"] = "admin"
os.environ["ALLOW_PRUNE"] = "0"
os.environ["ALLOW_SELF_STOP"] = "0"

from app import main
from app.main import (
    ALGORITHM,
    JWT_SECRET,
    _hits,
    app,
    create_access_token,
    create_refresh_token,
    mask_sensitive,
)


@pytest.fixture(autouse=True)
def clean_rate_limit_state():
    _hits.clear()
    main.LEGACY_TOKEN_ALLOW = False
    main.ALLOW_PRUNE = False
    main.ALLOW_SELF_STOP = False


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


def test_requirements_file_has_security_deps():
    req_path = Path(__file__).resolve().parent.parent / "app" / "requirements.txt"
    content = req_path.read_text(encoding="utf-8")
    assert "python-jose[cryptography]==3.5.0" in content
    assert "passlib[bcrypt]==1.7.4" in content
    assert "bcrypt==4.0.1" in content


def test_auth_login_success(client):
    res = client.post("/auth/login", json={"username": "admin", "password": "admin"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"

    payload = jwt.decode(data["access_token"], JWT_SECRET, algorithms=[ALGORITHM])
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


def test_auth_login_invalid_password(client):
    res = client.post("/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Неверное имя пользователя или пароль"


def test_auth_login_invalid_username(client):
    res = client.post("/auth/login", json={"username": "notadmin", "password": "admin"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Неверное имя пользователя или пароль"


def test_auth_refresh_flow(client):
    refresh_tok = create_refresh_token(username="admin", role="admin")
    res = client.post("/auth/refresh", json={"refresh_token": refresh_tok})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Cannot use access token as refresh token
    access_tok = create_access_token(username="admin", role="admin")
    res_err = client.post("/auth/refresh", json={"refresh_token": access_tok})
    assert res_err.status_code == 401
    assert "Неверный тип токена" in res_err.json()["detail"]


def test_auth_refresh_expired_or_invalid(client):
    res = client.post("/auth/refresh", json={"refresh_token": "invalid.jwt.token"})
    assert res.status_code == 401


def test_unauthenticated_request_rejected(client):
    res = client.get("/api/status")
    assert res.status_code == 401
    assert res.json()["detail"] == "Требуется авторизация"


def test_legacy_token_blocked_when_disallowed(client):
    main.LEGACY_TOKEN_ALLOW = False
    res = client.get("/api/status", headers={"X-API-Token": "legacy-secret-token"})
    assert res.status_code == 401
    assert "Legacy X-API-Token запрещен" in res.json()["detail"]


def test_legacy_token_allowed_when_enabled(client):
    main.LEGACY_TOKEN_ALLOW = True
    main.API_TOKEN = "legacy-secret-token"

    # Mock docker so /api/status does not fail
    with patch("app.main.get_docker") as mock_docker:
        mock_cli = MagicMock()
        mock_cli.containers.list.return_value = []
        mock_docker.return_value = mock_cli

        res = client.get("/api/status", headers={"X-API-Token": "legacy-secret-token"})
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"

    # Invalid legacy token
    res_bad = client.get("/api/status", headers={"X-API-Token": "wrong-token"})
    assert res_bad.status_code == 401


def test_rbac_user_vs_admin(client):
    user_tok = jwt.encode({"sub": "devuser", "role": "user", "type": "access"}, JWT_SECRET, algorithm=ALGORITHM)
    admin_tok = jwt.encode({"sub": "admin", "role": "admin", "type": "access"}, JWT_SECRET, algorithm=ALGORITHM)

    with patch("app.main.get_docker") as mock_docker:
        mock_cli = MagicMock()
        mock_cli.containers.list.return_value = []
        mock_docker.return_value = mock_cli

        # 1. User can access status and scripts
        res_user_status = client.get("/api/status", headers={"Authorization": f"Bearer {user_tok}"})
        assert res_user_status.status_code == 200

        res_user_scripts = client.get("/api/scripts", headers={"Authorization": f"Bearer {user_tok}"})
        assert res_user_scripts.status_code == 200

        # 2. User CANNOT run script (require_admin -> 403)
        res_user_run = client.post(
            "/api/run-script",
            json={"script_name": "system-info.sh"},
            headers={"Authorization": f"Bearer {user_tok}"},
        )
        assert res_user_run.status_code == 403
        assert "Недостаточно прав" in res_user_run.json()["detail"]

        # 3. User CANNOT execute container action
        res_user_act = client.post(
            "/api/container/nginx/action",
            json={"action": "restart"},
            headers={"Authorization": f"Bearer {user_tok}"},
        )
        assert res_user_act.status_code == 403

        # 4. User CANNOT read container logs
        res_user_logs = client.get(
            "/api/container/nginx/logs",
            headers={"Authorization": f"Bearer {user_tok}"},
        )
        assert res_user_logs.status_code == 403

        # 5. Admin CAN execute container action
        mock_cnt = MagicMock()
        mock_cli.containers.get.return_value = mock_cnt
        res_admin_act = client.post(
            "/api/container/nginx/action",
            json={"action": "restart"},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert res_admin_act.status_code == 200


def test_restrictions_clean_docker_prune(client):
    admin_tok = create_access_token(username="admin", role="admin")

    # Prune blocked by default
    main.ALLOW_PRUNE = False
    res = client.post(
        "/api/run-script",
        json={"script_name": "clean-docker.sh"},
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 403
    assert "clean-docker.sh заблокирован" in res.json()["detail"]


def test_restrictions_self_stop(client):
    admin_tok = create_access_token(username="admin", role="admin")

    main.ALLOW_SELF_STOP = False
    res = client.post(
        "/api/container/devops-platform-app/action",
        json={"action": "stop"},
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 403
    assert "Остановка самого себя заблокирована" in res.json()["detail"]


def test_validation_container_name_regex(client):
    admin_tok = create_access_token(username="admin", role="admin")

    res = client.get(
        "/api/container/invalid;name$/logs",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 400
    assert "Некорректное имя контейнера" in res.json()["detail"]


def test_validation_script_run_pydantic_regex(client):
    admin_tok = create_access_token(username="admin", role="admin")

    # Path traversal attack
    res = client.post(
        "/api/run-script",
        json={"script_name": "../etc/passwd"},
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 422  # Pydantic pattern validation error


def test_validation_container_logs_query_range(client):
    admin_tok = create_access_token(username="admin", role="admin")

    res = client.get(
        "/api/container/valid-container/logs?lines=5000",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 422


def test_rate_limiting_unauthenticated(client):
    _hits.clear()
    for _ in range(20):
        r = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    # 21st unauthenticated request to rate-limited endpoint
    r21 = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert r21.status_code == 429
    assert r21.headers.get("Retry-After") == "60"


def test_security_headers_and_trusted_host(client):
    res = client.get("/health")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")

    # Host header spoofing
    res_bad_host = client.get("/health", headers={"Host": "malicious-hacker.com"})
    assert res_bad_host.status_code == 400


def test_global_exception_handler_masking(client):
    # Test mask_sensitive helper
    raw_bearer = "Authorization: Bearer secret-token-xyz and password='supersecret'"
    masked_bearer = mask_sensitive(raw_bearer)
    assert "[TOKEN_MASKED]" in masked_bearer
    assert "supersecret" not in masked_bearer

    raw_jwt = "Token was eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.signature"
    masked_jwt = mask_sensitive(raw_jwt)
    assert "eyJ" not in masked_jwt
    assert "[JWT_MASKED]" in masked_jwt

    with patch("app.main._resolve_script", side_effect=RuntimeError("Secret database token 12345")):
        admin_tok = create_access_token(username="admin", role="admin")
        res = client.post(
            "/api/run-script",
            json={"script_name": "system-info.sh"},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        # Should return 500 with generic message and no stacktrace
        assert res.status_code == 500
        assert res.json() == {"detail": "Внутренняя ошибка"}
