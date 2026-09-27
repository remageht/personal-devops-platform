# Antigravity — единый промпт (Gemini 3.8 Flash)

Скопируй всё ниже в Antigravity Agent как одну задачу.

---

Ты — senior DevOps + AppSec агент в Google Antigravity (модель Gemini 3.8 Flash).
Репо: `personal-devops-platform` (ветка `main`, коммит `37b1527` уже с hardening).
Стек: Python 3.12 + FastAPI (`app/main.py`), HTML+Tailwind+vanilla JS (`frontend/index.html`),
Docker + Compose, Prometheus + Grafana (`monitoring/`), скрипты (`scripts/*.sh`).

Цель: довести проект до production-ready home-lab без новых уязвимостей и без поломки API.

Работай как в Antigravity 2.0: разбей на 3 параллельных суб-агента (Security / DevOps / Tests),
результат каждого — Artifact (план + diff + проверка). Не спрашивай лишнего, действуй через editor+terminal+browser.

SCOPE (делать строго в этом порядке):

1) Security (hardening-security):
- Замени `API_TOKEN` на JWT: access 15 мин + refresh 7 дней, роли `admin/user`, все POST `/api/*` только `require_admin`. Пароли/токены только env, никаких секретов в коде/логах.
- Проверь allowlist скриптов (`ALLOWED_SCRIPTS`), `resolve().relative_to(SCRIPTS_DIR)`, regex `^[a-z0-9][a-z0-9_\-]*\.sh$` и имён контейнеров `^[a-zA-Z0-9][a-zA-Z0-9_.\-]+$`.
- Rate-limit 60/min/IP на `/api/*` (уже есть — не сломай), лимит `lines 1..1000`, обрезка вывода `MAX_OUTPUT_CHARS=50000`, timeout скриптов 30с, generic 500 без `str(e)` наружу.
- Frontend: весь backend-рендер только через `escapeHtml()`, токен в `X-API-Token` + `localStorage`.

2) DevOps (devops-docker):
- Не возвращай `privileged:true`, root, `--reload` в проде, открытый `8001` наружу. Образ non-root `appuser`, `read_only:true`, `cap_drop:ALL`, лимиты `1 CPU/512M`, `HEALTHCHECK /health`.
- В `docker-compose.yml`: порты только `127.0.0.1`, `env_file:.env`, `GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:?}`, healthchecks + `depends_on`. Добавь `cadvisor` + `node-exporter` (порты тоже на 127.0.0.1), retention Prometheus 15d.
- `monitoring/prometheus.yml` целит в `app:8000` + `metrics_path:/metrics/prom`. Grafana provisioning в `monitoring/grafana/provisioning/` — добавь дашборд app+host как код.

3) Tests + CI:
- Добавь `pytest+httpx` тесты: 401 без токена, 403 user→admin, 404 на `../../x.sh`, 422 на `lines=5000`, 429 при флуде, 403 на `clean-docker.sh` без `ALLOW_PRUNE=1`.
- Расширь `.github/workflows/ci.yml`: `ruff + py_compile + hadolint + gitleaks + trivy (HIGH,CRITICAL fail)` + `docker compose build`.

ЗАПРЕЩЕНО:
- Коммитить `.env` с секретами, хардкодить URL/ключи, менять контракт `/api/*` без обновления `frontend/index.html`, хранить секреты в коде, отдавать stacktrace клиенту.
- `docker system prune --all --volumes` без `ALLOW_PRUNE=1`. Остановка `devops-platform-app` без `ALLOW_SELF_STOP=1`.

ПРОВЕРКА (обязательно выполни в терминале и приложи логи к Artifact):
```
cp .env.example .env  # заполни API_TOKEN/GRAFANA_PASSWORD случайными
docker compose up --build -d; docker compose ps
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/ready
curl -s http://127.0.0.1:8000/api/status | head -c 500  # ждём 401 если JWT включён
curl -s -H "X-API-Token: $API_TOKEN" http://127.0.0.1:8000/api/status | head -c 500
docker compose logs --tail=100 app
```

DELIVERABLE:
- Artifact 1: список уязвимостей `файл:строка → severity → fix`.
- Artifact 2: `git diff --stat` + все изменённые файлы готовые к коммиту.
- Artifact 3: отчёт тестов + логов проверки выше.
- Финальный коммит-месседж в стиле `hardening: ...` / `feat: ...`, без пуша без команды.
