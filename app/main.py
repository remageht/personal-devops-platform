"""Personal DevOps Platform — hardened FastAPI backend with JWT & RBAC.

Hardening features:
- JWT Authentication (HS256) with 15m access token and 7d refresh token.
- Passlib bcrypt password hashing with configurable ADMIN_USER and ADMIN_PASSWORD_HASH.
- RBAC: 'admin' role required for script execution and container modifications/logs;
        'user' or 'admin' authenticated role for status and script listings.
- Dual-token support: Bearer JWT token or legacy X-API-Token ONLY when LEGACY_TOKEN_ALLOW=1.
  If LEGACY_TOKEN_ALLOW=0 and X-API-Token is sent, HTTP 401 is returned.
- Strict Pydantic models (ScriptRun, ContainerAction, LoginRequest, RefreshRequest).
- Strict regex and path traversal validation on scripts and containers.
- Tiered sliding-window rate limiting:
    * 20 requests/minute per IP for unauthenticated requests.
    * 60 requests/minute per user for authenticated requests.
    * HTTP 429 with 'Retry-After: 60' header when rate limit is exceeded.
- Security Middlewares:
    * TrustedHostMiddleware (configured via ALLOWED_HOSTS).
    * CORSMiddleware (configured via CORS_ORIGINS).
    * Security headers middleware: X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
      Referrer-Policy: no-referrer, Content-Security-Policy.
- Global unhandled exception handler returning generic HTTP 500 without leaking stack traces,
  with sensitive tokens and credentials masked in logs.
- Guard rails: clean-docker.sh requires ALLOW_PRUNE=1, self-stop requires ALLOW_SELF_STOP=1.
- Lazy Docker client with asyncio.to_thread non-blocking calls.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import docker
from docker.errors import DockerException, NotFound
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

# ---------------------------------------------------------------- config

BASE_DIR = Path(__file__).resolve().parent

# Support container path with local fallback for testing
FRONTEND_FILE = Path(os.getenv("FRONTEND_FILE", "/app/frontend/index.html"))
if not FRONTEND_FILE.is_file():
    _local_frontend = (BASE_DIR.parent / "frontend" / "index.html").resolve()
    if _local_frontend.is_file():
        FRONTEND_FILE = _local_frontend

SCRIPTS_DIR = Path(os.getenv("SCRIPTS_DIR", "/app/scripts")).resolve()
if not SCRIPTS_DIR.is_dir():
    _local_scripts = (BASE_DIR.parent / "scripts").resolve()
    if _local_scripts.is_dir():
        SCRIPTS_DIR = _local_scripts

log = logging.getLogger("devops-platform")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# Security & Auth Configuration
DEFAULT_DEV_SECRET = "dev-insecure-jwt-secret-key-change-me-in-production-devops-platform-32b"
JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
if not JWT_SECRET:
    JWT_SECRET = DEFAULT_DEV_SECRET
    log.warning("JWT_SECRET is not set! Using default insecure fallback key. Set JWT_SECRET in production!")
elif len(JWT_SECRET) < 32:
    log.warning("JWT_SECRET is shorter than 32 characters; recommend using a 256-bit secret in production.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ADMIN_USER = os.getenv("ADMIN_USER", "admin").strip()
_env_admin_hash = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
if _env_admin_hash:
    ADMIN_PASSWORD_HASH = _env_admin_hash
else:
    # Safe dev fallback: default password is 'admin'
    ADMIN_PASSWORD_HASH = pwd_context.hash("admin")
    log.warning("ADMIN_PASSWORD_HASH is not set! Using default dev password 'admin'. Set ADMIN_PASSWORD_HASH in production!")

API_TOKEN = os.getenv("API_TOKEN", "").strip()
LEGACY_TOKEN_ALLOW = os.getenv("LEGACY_TOKEN_ALLOW", "0").strip() == "1"
if LEGACY_TOKEN_ALLOW and not API_TOKEN:
    log.warning("LEGACY_TOKEN_ALLOW=1, but API_TOKEN is empty. Legacy auth will fail.")

# Rate Limiting
RATE_LIMIT_UNAUTH = int(os.getenv("RATE_LIMIT_UNAUTH_PER_MIN", "20"))
RATE_LIMIT_AUTH = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))

# Host & CORS
ALLOWED_HOSTS_RAW = os.getenv("ALLOWED_HOSTS", "").strip()
if ALLOWED_HOSTS_RAW:
    ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS_RAW.split(",") if h.strip()]
else:
    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]

CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

# Scripts & System limits
SCRIPT_TIMEOUT = int(os.getenv("SCRIPT_TIMEOUT", "30"))
MAX_OUTPUT_CHARS = int(os.getenv("MAX_OUTPUT_CHARS", "50000"))
ALLOW_PRUNE = os.getenv("ALLOW_PRUNE", "0").strip() == "1"
ALLOW_SELF_STOP = os.getenv("ALLOW_SELF_STOP", "0").strip() == "1"

ALLOWED_SCRIPTS = frozenset(
    s.strip()
    for s in os.getenv("ALLOWED_SCRIPTS", "system-info.sh,clean-docker.sh,update-system.sh").split(",")
    if s.strip()
)

SCRIPT_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]*\.sh$")
CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]+$")

# ---------------------------------------------------------------- app & middlewares

app = FastAPI(title="Personal DevOps Platform", version="0.6.0-hardened")

# 1. TrustedHostMiddleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# 2. CORSMiddleware
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Token"],
        max_age=600,
    )

# ---------------------------------------------------------------- metrics & security headers

requests_total = Counter("http_requests_total", "Total HTTP requests", ["method", "path", "code"])
app_uptime = Gauge("app_uptime_seconds", "Application uptime in seconds")
start_time = time.time()


@app.middleware("http")
async def _metrics_and_security_headers(request: Request, call_next):
    resp = await call_next(request)
    try:
        route = request.scope.get("route")
        path = route.path if route else request.url.path
        requests_total.labels(request.method, path, str(resp.status_code)).inc()
    except Exception as exc:  # noqa: BLE001
        log.debug("Metrics record skipped: %s", exc)

    # Security headers
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return resp


# ---------------------------------------------------------------- exception handling & masking

def mask_sensitive(text: str) -> str:
    """Mask tokens, passwords, and sensitive credentials in logs."""
    text = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", r"\1[TOKEN_MASKED]", text, flags=re.IGNORECASE)
    text = re.sub(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "[JWT_MASKED]", text)
    text = re.sub(r'("password"\s*:\s*)"[^"]+"', r'\1"***"', text, flags=re.IGNORECASE)
    text = re.sub(r'(password\s*=\s*)[^\s,]+', r'\1***', text, flags=re.IGNORECASE)
    text = re.sub(r'(x-api-token:\s*)[^\s,]+', r'\1[TOKEN_MASKED]', text, flags=re.IGNORECASE)
    return text


@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions, log masked error details, return generic 500."""
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )
    safe_log_msg = mask_sensitive(f"{type(exc).__name__}: {exc}")
    log.error("Unhandled exception at %s %s: %s", request.method, request.url.path, safe_log_msg)
    return JSONResponse(status_code=500, content={"detail": "Внутренняя ошибка"})


# ---------------------------------------------------------------- pydantic models

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    role: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"


class ContainerAction(BaseModel):
    action: Literal["start", "stop", "restart"]


class ScriptRun(BaseModel):
    script_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_\-]*\.sh$")


class AuthUser(BaseModel):
    username: str
    role: str


# ---------------------------------------------------------------- tokens & auth helpers

def create_access_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def create_refresh_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": username,
        "role": role,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def get_optional_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> AuthUser | None:
    """Extract authenticated user if valid token is provided; otherwise returns None."""
    # Handle legacy X-API-Token
    if x_api_token is not None:
        if not LEGACY_TOKEN_ALLOW:
            return None
        if API_TOKEN and secrets.compare_digest(x_api_token.strip(), API_TOKEN):
            return AuthUser(username="legacy-admin", role="admin")
        return None

    # Handle Bearer JWT
    if authorization is not None:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            try:
                payload = jwt.decode(parts[1], JWT_SECRET, algorithms=[ALGORITHM])
                if payload.get("type") == "access":
                    username = payload.get("sub")
                    role = payload.get("role")
                    if username and role in ("admin", "user"):
                        return AuthUser(username=username, role=role)
            except JWTError:
                return None
    return None


def require_authenticated(
    user: AuthUser | None = Depends(get_optional_user),  # noqa: B008
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> AuthUser:
    """Ensure request is authenticated with either Bearer JWT or legacy X-API-Token when allowed."""
    if x_api_token is not None and not LEGACY_TOKEN_ALLOW:
        raise HTTPException(
            status_code=401,
            detail="Legacy X-API-Token запрещен. Используйте Bearer токен.",
        )
    if user is None:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return user


def require_admin(user: AuthUser = Depends(require_authenticated)) -> AuthUser:  # noqa: B008
    """Ensure authenticated user has 'admin' role."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Недостаточно прав (требуется роль admin)")
    return user


# ---------------------------------------------------------------- rate limit (sliding-window)

_hits: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request, user: AuthUser | None = Depends(get_optional_user)):  # noqa: B008
    """Rate limit requests: 20 req/min unauthenticated (by IP), 60 req/min authenticated (by user)."""
    ip = request.client.host if request.client else "unknown"
    key = f"user:{user.username}" if user else f"ip:{ip}"
    limit = RATE_LIMIT_AUTH if user else RATE_LIMIT_UNAUTH
    now = time.monotonic()
    window = _hits[key]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Слишком много запросов, попробуйте позже",
            headers={"Retry-After": "60"},
        )
    window.append(now)


# ---------------------------------------------------------------- docker client (lazy)

MOCK_DOCKER = os.getenv("MOCK_DOCKER", "0").strip() == "1"


class _MockContainer:
    def __init__(self, name: str, status: str, image_tag: str):
        self.short_id = name[:8]
        self.name = name
        self.status = status
        self.image = type("Image", (), {"tags": [image_tag]})()

    def logs(self, tail=150, timestamps=True):
        return f"2026-09-27T21:00:00Z [INFO] {self.name} is healthy and running\n".encode()

    def restart(self, timeout=10):
        pass

    def stop(self, timeout=10):
        pass

    def start(self):
        pass


class _MockContainers:
    def list(self, all=True):
        return [
            _MockContainer("devops-platform-app", "running", "devops-platform-app:latest"),
            _MockContainer("prometheus", "running", "prom/prometheus:v3.1.0"),
            _MockContainer("grafana", "running", "grafana/grafana:11.3.0"),
            _MockContainer("cadvisor", "running", "gcr.io/cadvisor/cadvisor:v0.49.1"),
            _MockContainer("node-exporter", "running", "prom/node-exporter:v1.8.2"),
        ]

    def get(self, name: str):
        for c in self.list():
            if c.name == name:
                return c
        raise NotFound(f"Container {name} not found")


class _MockDockerClient:
    def __init__(self):
        self.containers = _MockContainers()

    def ping(self):
        return True


_docker_client = None


def get_docker():
    global _docker_client
    if MOCK_DOCKER:
        if _docker_client is None:
            _docker_client = _MockDockerClient()
        return _docker_client
    if _docker_client is None:
        try:
            _docker_client = docker.from_env(timeout=10)
            _docker_client.ping()
        except DockerException as e:
            log.error("Docker daemon unavailable: %s", type(e).__name__)
            raise HTTPException(503, "Docker daemon недоступен")
    return _docker_client


# ---------------------------------------------------------------- validation helpers

def _resolve_script(name: str) -> Path:
    if name not in ALLOWED_SCRIPTS or not SCRIPT_RE.match(name):
        raise HTTPException(404, "Скрипт не найден")
    candidate = (SCRIPTS_DIR / name).resolve()
    try:
        candidate.relative_to(SCRIPTS_DIR)
    except ValueError:
        raise HTTPException(404, "Скрипт не найден")
    if not candidate.is_file():
        raise HTTPException(404, "Скрипт не найден")
    return candidate


def _check_container_name(name: str):
    if not CONTAINER_RE.match(name) or len(name) > 128:
        raise HTTPException(400, "Некорректное имя контейнера")


# ---------------------------------------------------------------- routes: auth

@app.post("/auth/login", response_model=TokenResponse, dependencies=[Depends(rate_limit)])
async def auth_login(req: LoginRequest):
    """Authenticate with username and password, return JWT access and refresh tokens."""
    valid_user = secrets.compare_digest(req.username, ADMIN_USER)
    valid_pass = False
    try:
        valid_pass = pwd_context.verify(req.password, ADMIN_PASSWORD_HASH)
    except Exception:
        log.exception("Password verification error")

    if not (valid_user and valid_pass):
        raise HTTPException(status_code=401, detail="Неверное имя пользователя или пароль")

    access_token = create_access_token(username=req.username, role="admin")
    refresh_token = create_refresh_token(username=req.username, role="admin")
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        role="admin",
    )


@app.post("/auth/refresh", response_model=RefreshResponse, dependencies=[Depends(rate_limit)])
async def auth_refresh(req: RefreshRequest):
    """Refresh access token using a valid refresh token."""
    try:
        payload = jwt.decode(req.refresh_token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Недействительный или истекший refresh токен")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Неверный тип токена (ожидается refresh)")

    username = payload.get("sub")
    role = payload.get("role", "admin")
    if not username:
        raise HTTPException(status_code=401, detail="Некорректный токен")

    new_access_token = create_access_token(username=username, role=role)
    return RefreshResponse(
        access_token=new_access_token,
        token_type="bearer",
    )


# ---------------------------------------------------------------- routes: system & metrics

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    try:
        return FRONTEND_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<h1>Personal DevOps Platform — frontend не смонтирован</h1>"


@app.get("/health")
async def health():
    app_uptime.set(time.time() - start_time)
    return {"status": "ok", "uptime_seconds": round(time.time() - start_time, 1)}


@app.get("/ready")
async def ready():
    try:
        client = get_docker()
        await asyncio.to_thread(client.ping)
        return {"status": "ready"}
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("Ready check failed: %s", exc)
        raise HTTPException(503, "Docker не готов")


@app.get("/metrics")
async def metrics():
    app_uptime.set(time.time() - start_time)
    return JSONResponse(
        content={"hint": "Prometheus exposition at /metrics/prom"},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/metrics/prom")
async def metrics_prom():
    app_uptime.set(time.time() - start_time)
    data = generate_latest()
    return HTMLResponse(content=data.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------- routes: api

@app.get("/api/status", dependencies=[Depends(rate_limit), Depends(require_authenticated)])
async def api_status():
    uptime = round(time.time() - start_time, 1)
    app_uptime.set(time.time() - start_time)

    def _list():
        out = []
        cli = get_docker()
        for c in cli.containers.list(all=True):
            tags = getattr(c.image, "tags", None) or []
            out.append({
                "id": c.short_id,
                "name": c.name,
                "status": c.status,
                "image": tags[0] if tags else "unknown",
            })
        return out

    try:
        containers = await asyncio.to_thread(_list)
    except HTTPException:
        containers = []
        log.warning("Docker недоступен в /api/status")
    except Exception:
        log.exception("Ошибка листинга контейнеров")
        containers = []
    return {"status": "healthy", "uptime_seconds": uptime, "containers": containers}


@app.get("/api/scripts", dependencies=[Depends(rate_limit), Depends(require_authenticated)])
async def list_scripts():
    return {"scripts": sorted(ALLOWED_SCRIPTS)}


@app.post("/api/run-script", dependencies=[Depends(rate_limit), Depends(require_admin)])
async def run_script(script: ScriptRun):
    script_path = _resolve_script(script.script_name)
    if script.script_name == "clean-docker.sh" and not ALLOW_PRUNE:
        raise HTTPException(
            status_code=403,
            detail="clean-docker.sh заблокирован: задайте ALLOW_PRUNE=1 для разрешения prune",
        )
    try:
        def _run():
            return subprocess.run(
                ["bash", str(script_path)],
                capture_output=True,
                text=True,
                timeout=SCRIPT_TIMEOUT,
                cwd=str(SCRIPTS_DIR),
                check=False,
            )
        result = await asyncio.to_thread(_run)
        output = (result.stdout or "") + (result.stderr or "")
        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f"\n… [обрезано, лимит {MAX_OUTPUT_CHARS}]"
        prefix = "✅ Выполнено успешно" if result.returncode == 0 else f"❌ Ошибка (код {result.returncode})"
        return {"status": "success", "output": f"{prefix}:\n{output}", "return_code": result.returncode}
    except subprocess.TimeoutExpired:
        raise HTTPException(504, f"Скрипт превысил таймаут {SCRIPT_TIMEOUT}с")
    except HTTPException:
        raise
    except Exception:
        log.exception("Ошибка запуска скрипта")
        raise HTTPException(500, "Внутренняя ошибка при запуске скрипта")


@app.post("/api/container/{container_name}/action",
          dependencies=[Depends(rate_limit), Depends(require_admin)])
async def container_action(container_name: str, action: ContainerAction):
    _check_container_name(container_name)
    if container_name in ("devops-platform-app",) and action.action == "stop" and not ALLOW_SELF_STOP:
        raise HTTPException(
            status_code=403,
            detail="Остановка самого себя заблокирована (ALLOW_SELF_STOP=1 чтобы разрешить)",
        )
    try:
        def _do():
            cli = get_docker()
            c = cli.containers.get(container_name)
            if action.action == "restart":
                c.restart(timeout=10)
                return f"✅ {container_name} перезапущен"
            if action.action == "stop":
                c.stop(timeout=10)
                return f"⏹ {container_name} остановлен"
            c.start()
            return f"▶ {container_name} запущен"
        msg = await asyncio.to_thread(_do)
        return {"status": "success", "message": msg}
    except NotFound:
        raise HTTPException(404, "Контейнер не найден")
    except HTTPException:
        raise
    except Exception:
        log.exception("Ошибка container action")
        raise HTTPException(500, "Не удалось выполнить действие")


@app.get("/api/container/{container_name}/logs",
         dependencies=[Depends(rate_limit), Depends(require_admin)])
async def container_logs(
    container_name: str,
    lines: int = Query(default=150, ge=1, le=1000),
):
    _check_container_name(container_name)
    try:
        def _logs():
            cli = get_docker()
            c = cli.containers.get(container_name)
            raw = c.logs(tail=lines, timestamps=True)
            text = raw.decode("utf-8", errors="ignore")
            if len(text) > MAX_OUTPUT_CHARS:
                text = text[-MAX_OUTPUT_CHARS:]
            return text
        return {"logs": await asyncio.to_thread(_logs)}
    except NotFound:
        raise HTTPException(404, "Контейнер не найден")
    except HTTPException:
        raise
    except Exception:
        log.exception("Ошибка чтения логов")
        raise HTTPException(500, "Не удалось получить логи")
