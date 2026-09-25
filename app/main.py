"""Personal DevOps Platform — hardened FastAPI backend.

Исправления по скиллам hardening-security + devops-docker:
- allowlist скриптов + защита от path traversal
- валидация имён контейнеров / действий / лимитов
- опциональный API-токен (env API_TOKEN) для /api/*
- простой in-memory rate-limit (без новых зависимостей)
- docker-клиент ленивый, вызовы через asyncio.to_thread (не блокируют loop)
- лимиты вывода subprocess и логов, generic 500 без утечек
- security headers + строгий CORS из env
- /health без зависимости от docker, /ready с проверкой docker
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Literal

import docker
from docker.errors import DockerException, NotFound
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from pydantic import BaseModel, Field

# ---------------------------------------------------------------- config

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_FILE = Path(os.getenv("FRONTEND_FILE", "/app/frontend/index.html"))
SCRIPTS_DIR = Path(os.getenv("SCRIPTS_DIR", "/app/scripts")).resolve()

API_TOKEN = os.getenv("API_TOKEN", "").strip()  # если пуст — auth отключён (dev), но в лог идёт warning
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
SCRIPT_TIMEOUT = int(os.getenv("SCRIPT_TIMEOUT", "30"))
MAX_OUTPUT_CHARS = int(os.getenv("MAX_OUTPUT_CHARS", "50000"))
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))

# Allowlist — единственный способ запускать скрипты. Новый скрипт = +1 строка сюда + файл.
ALLOWED_SCRIPTS = frozenset(
    s.strip()
    for s in os.getenv("ALLOWED_SCRIPTS", "system-info.sh,clean-docker.sh,update-system.sh").split(",")
    if s.strip()
)

SCRIPT_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]*\.sh$")
CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]+$")

log = logging.getLogger("devops-platform")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI(title="Personal DevOps Platform", version="0.5.0-hardened")

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Token"],
        max_age=600,
    )

# ---------------------------------------------------------------- metrics

requests_total = Counter("http_requests_total", "Total HTTP requests", ["method", "path", "code"])
app_uptime = Gauge("app_uptime_seconds", "Application uptime in seconds")
start_time = time.time()


@app.middleware("http")
async def _metrics_and_headers(request: Request, call_next):
    resp = await call_next(request)
    try:
        route = request.scope.get("route")
        path = route.path if route else request.url.path
        requests_total.labels(request.method, path, str(resp.status_code)).inc()
    except Exception:  # метрики никогда не должны ронять запрос
        pass
    # security headers (hardening-security)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


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


# ---------------------------------------------------------------- rate limit (простой, без redis)

_hits: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window = _hits[ip]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= RATE_LIMIT_PER_MIN:
        raise HTTPException(429, "Слишком много запросов, попробуйте позже")
    window.append(now)


# ---------------------------------------------------------------- auth

if not API_TOKEN:
    log.warning("API_TOKEN не задан — /api/* открыты. Задайте API_TOKEN в .env для продакшена.")


def require_token(x_api_token: str | None = Header(default=None, alias="X-API-Token")):
    if not API_TOKEN:
        return  # dev-режим
    if x_api_token != API_TOKEN:
        raise HTTPException(401, "Неавторизовано")


# ---------------------------------------------------------------- docker (ленивый, не крашит импорт)

_docker_client = None


def get_docker():
    global _docker_client
    if _docker_client is None:
        try:
            _docker_client = docker.from_env(timeout=10)
            _docker_client.ping()
        except DockerException as e:
            log.error("Docker недоступен: %s", type(e).__name__)
            raise HTTPException(503, "Docker daemon недоступен")
    return _docker_client


# ---------------------------------------------------------------- models

class ContainerAction(BaseModel):
    action: Literal["start", "stop", "restart"]


class ScriptRun(BaseModel):
    script_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_\-]*\.sh$")


def _resolve_script(name: str) -> Path:
    if name not in ALLOWED_SCRIPTS or not SCRIPT_RE.match(name):
        raise HTTPException(404, "Скрипт не найден")
    candidate = (SCRIPTS_DIR / name).resolve()
    # защита от traversal + абсолютных путей: файл обязан лежать строго в SCRIPTS_DIR
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


# ---------------------------------------------------------------- routes

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
    except Exception:
        raise HTTPException(503, "Docker не готов")


@app.get("/api/status", dependencies=[Depends(rate_limit), Depends(require_token)])
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


@app.get("/api/scripts", dependencies=[Depends(rate_limit), Depends(require_token)])
async def list_scripts():
    return {"scripts": sorted(ALLOWED_SCRIPTS)}


@app.post("/api/run-script", dependencies=[Depends(rate_limit), Depends(require_token)])
async def run_script(script: ScriptRun):
    script_path = _resolve_script(script.script_name)
    # Запрет особо опасной операции без явного подтверждения флага
    if script.script_name == "clean-docker.sh" and os.getenv("ALLOW_PRUNE", "0") != "1":
        raise HTTPException(403, "clean-docker.sh заблокирован: задайте ALLOW_PRUNE=1 для разрешения prune")
    try:
        def _run():
            return subprocess.run(
                ["bash", str(script_path)],
                capture_output=True, text=True, timeout=SCRIPT_TIMEOUT,
                cwd=str(SCRIPTS_DIR),
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
          dependencies=[Depends(rate_limit), Depends(require_token)])
async def container_action(container_name: str, action: ContainerAction):
    _check_container_name(container_name)
    # never allow self-destruction without explicit flag
    if container_name in ("devops-platform-app",) and action.action == "stop" \
            and os.getenv("ALLOW_SELF_STOP", "0") != "1":
        raise HTTPException(403, "Остановка самого себя заблокирована (ALLOW_SELF_STOP=1 чтобы разрешить)")
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
         dependencies=[Depends(rate_limit), Depends(require_token)])
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
