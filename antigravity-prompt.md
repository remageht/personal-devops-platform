# Antigravity — полноценный промпт (Gemini 3.8 Flash, copy-paste одной задачей)

> Вставь всё ниже черты в Antigravity 2.0 → New Project → выбери папку `personal-devops-platform`, модель `Gemini 3.8 Flash`.

---

ROLE:
Ты — autonomous senior DevOps + AppSec агент в Google Antigravity 2.0, модель Gemini 3.8 Flash.
Умеешь работать через Editor + Terminal + Browser, запускать параллельных суб-агентов, создавать Artifacts (план, diff, скриншоты, логи).
Не задаёшь уточняющих вопросов — принимаешь разумные defaults для home-lab и фиксируешь их в Artifact.

PROJECT MAP (факт на main `66bb645`):
```
personal-devops-platform/
├── app/main.py                 # FastAPI, уже hardened: allowlist, API_TOKEN, rate-limit, to_thread
├── app/requirements.txt        # fastapi, uvicorn, prometheus-client, docker, dotenv
├── frontend/index.html         # Tailwind CDN + vanilla JS, уже escapeHtml + X-API-Token
├── Dockerfile                  # python:3.12-slim, non-root appuser, HEALTHCHECK, без --reload
├── docker-compose.yml          # app+prometheus+grafana, без privileged, 127.0.0.1, read_only
├── docker-compose.override.yml # только dev: --reload
├── monitoring/prometheus.yml   # app:8000 + /metrics/prom
├── monitoring/grafana/provisioning/datasources/prometheus.yml
├── scripts/system-info.sh, clean-docker.sh (ALLOW_PRUNE=1 gate), update-system.sh
├── .env.example                # API_TOKEN, GRAFANA_*, ALLOW_PRUNE=0, ALLOW_SELF_STOP=0
└── .github/workflows/ci.yml    # ruff+hadolint+gitleaks+trivy+compose build
```

BASELINE (уже сделано, не откатывать):
- `app/main.py`: `ALLOWED_SCRIPTS`, `resolve().relative_to(SCRIPTS_DIR)`, `SCRIPT_RE`, `CONTAINER_RE`, `lines 1..1000`, `MAX_OUTPUT 50000`, `SCRIPT_TIMEOUT 30`, `asyncio.to_thread`, generic 500, security headers, `/health|/ready|/metrics/prom|/api/scripts`.
- `compose`: нет `privileged:true`, нет root, нет `8001 наружу`, `read_only:true`, `cap_drop:ALL`, лимиты `1CPU/512M`.
- `frontend`: `escapeHtml()` везде в `innerHTML`, `apiHeaders()` с `X-API-Token`.
- `clean-docker.sh`: `set -euo pipefail`, gate `ALLOW_PRUNE`, только `prune -f` без `--all --volumes`.

MISSION:
Доведи до production-ready home-lab: JWT + полный мониторинг + тесты. Не сломай контракт `GET /`, `GET /health|/ready|/metrics/prom`, `GET /api/status|/api/scripts|/api/container/{name}/logs`, `POST /api/run-script|/api/container/{name}/action`.

HOW TO WORK (Antigravity-специфика):
1. Создай Task-план из 3 параллельных суб-агентов: A=Security, B=Observability/Compose, C=Tests/CI. Веди их в Agent Manager.
2. Каждый суб-агент обязан: прочитать свои файлы → сделать минимальный diff → прогнать свою проверку → вернуть Artifact.
3. Browser-агента используй для открытия `http://127.0.0.1:8000`, `:9090/-/healthy`, `:3000` и скриншота дашборда в Artifact.
4. Все секреты только через `.env` (создай из `.env.example` локально, не коммить). Случайные значения: `openssl rand -hex 32`.
5. Финальный ответ — только после зелёных проверок из раздела VERIFY.

WORKSTREAM A — SECURITY (skill hardening-security):
A1. Замени `API_TOKEN` на JWT: `python-jose + passlib[bcrypt]`, `POST /auth/login` (login+password из env `ADMIN_USER`/`ADMIN_PASSWORD_HASH`), `access 15м + refresh 7д`, `require_admin` на все POST `/api/*` и `GET /api/container/*/logs`. Старый `X-API-Token` оставь как fallback только если `LEGACY_TOKEN_ALLOW=1`, по умолчанию `0`.
A2. Усиль валидацию: pydantic `Field(pattern, max_length)` на все модели, `Query(ge=1,le=1000)` уже есть — не расширять. PII (имена контейнеров с email) маскируй в логах. Полный RAG-контекст не применимо — не логируй вывод скриптов целиком выше `MAX_OUTPUT`.
A3. Rate-limit вынеси в `RATE_LIMIT_PER_MIN` (default 60), ответ 429 с `Retry-After`. Добавь `TrustedHostMiddleware` + CORS только из `CORS_ORIGINS`.
Accept: `401 без токена, 403 user→admin, 404 ../../x.sh, 422 lines=5000, 429 флуд, 403 clean-docker без ALLOW_PRUNE=1`.

WORKSTREAM B — DEVOPS/OBSERVABILITY (skill devops-docker):
B1. В `docker-compose.yml` добавь `cadvisor` (`gcr.io/cadvisor/cadvisor:v0.49.1`, `127.0.0.1:8080`) и `node-exporter` (`prom/node-exporter:v1.8.2`, `127.0.0.1:9100`), оба `restart:unless-stopped`, лимиты памяти. Prometheus job'ы для них + `scrape_interval 15s`, `retention 15d` уже есть — не дублируй.
B2. Grafana: добавь `provisioning/dashboards/dashboard.yml` + JSON-дашборд `app-host.json` (панели: uptime, http_requests_total, cpu, mem, контейнеры). Datasource уже есть — используй его.
B3. Раздели прод/dev: прод `docker compose up --build -d` без override; dev `docker compose -f docker-compose.yml -f docker-compose.override.yml up`. Проверь `docker compose config` без ошибок.
Запрещено: возвращать `privileged`, `network_mode:host`, `ports 8001:8001`, `GF_SECURITY_ADMIN_PASSWORD=admin` в коде.

WORKSTREAM C — TESTS/CI:
C1. Добавь `app/test_main.py` (pytest+httpx+pytest-asyncio): тесты из Accept A3 + `GET /health 200`, `GET /ready 200|503`, `POST /api/run-script allowlist`, `output truncation`, `security headers present`.
C2. `app/requirements-dev.txt`: `pytest httpx pytest-asyncio ruff`. В `ci.yml` добавь job `pytest`, кэш pip, `trivy exit-code 1` только на HIGH,CRITICAL.
C3. Обнови `README.md`: бейдж CI, быстрый старт с `.env`, таблица `API_TOKEN→JWT миграция`, порты только localhost, как включить `ALLOW_PRUNE`.

GLOBAL RULES (нарушение = провал задачи):
- Секреты только env, никогда в код/логи/diff/Artifact.
- Не менять контракт `/api/*` без обновления `frontend/index.html` типов и `openapi`.
- Не хранить stacktrace для клиента: `500 → {"detail":"Внутренняя ошибка"}` + полный traceback только в server log.
- Не коммитить `.env`, `*.log`, `grafana_data/`, `prometheus_data/`.
- Маленькие diff'ы: один workstream = один коммит `feat:|hardening:|ci:`.

VERIFY (выполни дословно, логи в Artifact 3):
```bash
cp -n .env.example .env || true
# заполни API_TOKEN/ADMIN_PASSWORD_HASH/GRAFANA_PASSWORD случайными перед запуском
docker compose up --build -d
docker compose ps
docker compose config --quiet && echo CONFIG_OK
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/ready
curl -fsS http://127.0.0.1:9090/-/healthy
python -m pytest app/test_main.py -q
docker compose logs --tail=100 app
```

DELIVERABLES (4 Artifacts):
1. `security-review.md`: таблица `файл:строка → CWE/OWASP → severity → fix → тест`.
2. `compose-diff.md`: `git diff --stat` + ключевые hunks Dockerfile/compose/prometheus/grafana.
3. `verify.log`: вывод блока VERIFY целиком + 3 скриншота browser-агента (app, prometheus, grafana).
4. `commit-plan.md`: 3 готовых `git commit -m "..."` по workstream'ам, без `git push` (пуш только по команде юзера).

DEFINITION OF DONE:
Зелёные `pytest + ruff + compose ps (все healthy) + curl /health|/ready|/-/healthy`, ноль HIGH/CRITICAL от trivy, ноль секретов в `git diff`, контракт фронта не сломан.
