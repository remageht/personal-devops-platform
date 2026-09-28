# 🚀 Personal DevOps Platform

[![CI](https://github.com/remageht/personal-devops-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/remageht/personal-devops-platform/actions/workflows/ci.yml)

Современная защищенная платформа для мониторинга, управления Docker-контейнерами и автоматизации локальной инфраструктуры.

---

## ✨ Возможности

- 🛡 **Харденинг и безопасность:**
  - JWT аутентификация (HS256: Access 15 мин, Refresh 7 дней) с разделением ролей (`admin` / `user`).
  - Passlib + Bcrypt хеширование паролей администратора без хранения открытых паролей в коде.
  - Ограничение частоты запросов (Rate Limiting): 20 req/min для неавторизованных, 60 req/min для пользователей (с заголовком `Retry-After: 60`).
  - Защита от Path Traversal и инъекций (строгий allowlist скриптов и regex-валидация параметров).
  - Защитные флаги (Guard Rails): блокировка `clean-docker.sh` без `ALLOW_PRUNE=1`, блокировка остановки платформы без `ALLOW_SELF_STOP=1`.
  - Security Headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, CSP.
  - Маскирование секретов и токенов в логах, generic HTTP 500 без утечки стектрейсов наружу.
- 📊 **Комплексная наблюдаемость (Observability):**
  - Prometheus экспозиция на `/metrics/prom`.
  - Метрики хоста и контейнеров через **cAdvisor** и **Node Exporter**.
  - Автоматически провижинируемые Grafana-дашборды (`Personal DevOps Platform - App & Host`).
  - Все порты сервисов привязаны строго к `127.0.0.1` (никакого 0.0.0.0 наружу).
- 💻 **Веб-интерфейс (Frontend):**
  - Адаптивный дашборд (HTML5 + Tailwind CSS + Vanilla JS).
  - Поддержка входа по логину/паролю с сохранением JWT и авто-рефрешем токена при 401.
  - Возможность использования Legacy X-API-Token при включенном режиме обратной совместимости.
- ⚡ **CI/CD и тесты:**
  - Автоматизированный пайплайн в GitHub Actions: Ruff linter, Pytest, Hadolint Dockerfile, Gitleaks, Trivy vulnerability scan.
  - Политика Trivy: гейт `HIGH,CRITICAL` с `ignore-unfixed` — падают только *исправляемые* уязвимости; CVE без фикса от апстрима (например, в базовом Debian) не блокируют сборку, но видны в отчёте.

---

## 🛠 Технологический стек

| Слой | Технологии |
|---|---|
| **Backend** | Python 3.12, FastAPI 0.141 (Starlette 1.7), Pydantic v2, python-jose, passlib (bcrypt), Uvicorn |
| **Frontend** | HTML5, Tailwind CSS CDN, Vanilla JS, Font Awesome |
| **Containerization** | Docker, Docker Compose (Non-root `appuser`, read-only FS, cap_drop ALL) |
| **Мониторинг** | Prometheus v3.1, Grafana 11.3, Google cAdvisor, Node Exporter |
| **Тестирование & CI** | Pytest, HTTPX, Ruff, Hadolint, Gitleaks, Trivy |

---

## 🚀 Быстрый старт

### 1. Клонирование репозитория

```bash
git clone https://github.com/remageht/personal-devops-platform.git
cd personal-devops-platform
```

### 2. Настройка переменных окружения (`.env`)

Скопируйте пример файла конфигурации:

```bash
cp .env.example .env
```

#### Генерация секретов:

1. **JWT Secret (`JWT_SECRET`):**
   ```bash
   openssl rand -hex 32
   ```

2. **Хеш пароля администратора (`ADMIN_PASSWORD_HASH`):**
   Сгенерируйте безопасный bcrypt-хеш для вашего пароля с помощью Python:
   ```bash
   python -c "import bcrypt; print(bcrypt.hashpw(b'your_secure_password', bcrypt.gensalt()).decode())"
   ```
   Либо через passlib:
   ```bash
   python -c "from passlib.hash import bcrypt; print(bcrypt.hash('your_secure_password'))"
   ```

3. **Пароль Grafana (`GRAFANA_PASSWORD`):**
   Укажите надежный пароль в переменной `GRAFANA_PASSWORD` в `.env`. Хардкод паролей в коде категорически запрещен!

### 3. Запуск через Docker Compose

Запуск в фоновом режиме:

```bash
docker compose up -d
```

Проверка статуса запущенных контейнеров:

```bash
docker compose ps
```

### 4. Доступ к сервисам (Localhost Only)

Все сервисы платформы слушают исключительно локальный адрес `127.0.0.1`:

- 🌐 **Основной дашборд:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- 📊 **Grafana:** [http://127.0.0.1:3000](http://127.0.0.1:3000) *(логин и пароль берутся из `.env`: `GRAFANA_USER` и `GRAFANA_PASSWORD`)*
- 📈 **Prometheus:** [http://127.0.0.1:9090](http://127.0.0.1:9090)
- 📦 **cAdvisor:** [http://127.0.0.1:8080](http://127.0.0.1:8080)
- 🖥 **Node Exporter:** [http://127.0.0.1:9100](http://127.0.0.1:9100)

---

## 🔄 Руководство по миграции: TOKEN -> JWT

Платформа переведена с единого статического токена `API_TOKEN` на современную ролевую модель аутентификации по стандарту **JWT (JSON Web Token)**.

### Сравнение механизмов аутентификации

| Параметр | Устаревший механизм (Legacy) | Новый механизм (JWT) |
|---|---|---|
| **Заголовок** | `X-API-Token: <token>` | `Authorization: Bearer <token>` |
| **Срок жизни** | Бессрочный | Access: 15 минут, Refresh: 7 дней |
| **Роли** | Единый уровень прав | `admin` (полные права) / `user` (read-only) |
| **Статус по умолчанию** | Отключен (`LEGACY_TOKEN_ALLOW=0`) | Основной метод аутентификации |

### Получение и использование JWT

1. **Вход и получение токенов (`POST /auth/login`):**
   ```bash
   curl -s -X POST http://127.0.0.1:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "your_secure_password"}'
   ```
   Ответ:
   ```json
   {
     "access_token": "<ACCESS_TOKEN_JWT>",
     "refresh_token": "<REFRESH_TOKEN_JWT>",
     "token_type": "bearer",
     "role": "admin"
   }
   ```

2. **Выполнение авторизованных запросов с Access-токеном:**
   ```bash
   curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://127.0.0.1:8000/api/status
   ```

3. **Обновление токена (`POST /auth/refresh`):**
   Когда срок действия Access-токена истекает (через 15 мин), используйте Refresh-токен:
   ```bash
   curl -s -X POST http://127.0.0.1:8000/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refresh_token": "<REFRESH_TOKEN>"}'
   ```

### Включение обратной совместимости (Legacy Token)

Если внешним системам или скриптам требуется временная поддержка статического заголовка `X-API-Token`:
1. Установите в `.env`:
   ```dotenv
   LEGACY_TOKEN_ALLOW=1
   API_TOKEN=your_secure_legacy_token
   ```
2. Перезапустите приложение:
   ```bash
   docker compose up -d
   ```
3. При `LEGACY_TOKEN_ALLOW=0` запросы с `X-API-Token` отклоняются с кодом `401 Unauthorized`.

---

## 🛡 Защитные флаги (Guard Rails)

- **Очистка Docker (`clean-docker.sh`):**
  Скрипт очистки неиспользуемых образов и контейнеров заблокирован по умолчанию. Чтобы разрешить его запуск, установите в `.env`:
  ```dotenv
  ALLOW_PRUNE=1
  ```
- **Остановка контейнера платформы (`devops-platform-app`):**
  Остановка собственного контейнера платформы предотвращается с кодом `403`. Для снятия защиты установите:
  ```dotenv
  ALLOW_SELF_STOP=1
  ```

---

## 🧪 Верификация и тестирование

### 1. Проверка доступности endpoints

```bash
# Проверка жизнеспособности (Liveness)
curl -fsS http://127.0.0.1:8000/health

# Проверка готовности (Readiness, проверяет подключение к Docker)
curl -fsS http://127.0.0.1:8000/ready

# Проверка метрик Prometheus
curl -fsS http://127.0.0.1:8000/metrics/prom
```

### 2. Запуск локального набора тестов

Установите зависимости для разработки:

```bash
pip install -r app/requirements.txt
pip install -r requirements-dev.txt
```

Запустите линтер и тесты:

```bash
# Запуск линтера Ruff
ruff check .

# Запуск полного набора тестов Pytest
pytest app/test_main.py -v
```

### 3. Проверка валидности Docker Compose

```bash
docker compose config --quiet && echo "Compose config is valid"
```

---

## 📁 Структура проекта

```text
personal-devops-platform/
├── .github/
│   └── workflows/
│       └── ci.yml               # CI-пайплайн (Ruff, Pytest, Hadolint, Gitleaks, Trivy)
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI приложение с JWT, RBAC и rate-limiting
│   ├── requirements.txt         # Основные зависимости бэкенда
│   └── test_main.py             # Тесты API (13 сценариев: auth, RBAC, валидация, лимиты)
├── tests/
│   └── test_security_hardening.py # Тесты харденинга (18 сценариев)
├── frontend/
│   └── index.html               # Веб-дашборд с авторизацией и auto-refresh токенов
├── monitoring/
│   ├── grafana/
│   │   └── provisioning/        # Автоматический провижининг дашбордов и источников
│   └── prometheus.yml           # Конфигурация сбора метрик (app, cadvisor, node-exporter)
├── scripts/                     # Разрешенные скрипты (system-info, clean-docker, update-system)
├── .dockerignore
├── .env.example                 # Пример переменных окружения
├── .gitignore
├── docker-compose.yml           # Основной production-манифест
├── docker-compose.override.yml  # Dev-манифест с горячей перезагрузкой
├── Dockerfile                   # Безопасный Dockerfile (non-root appuser, read-only)
├── pytest.ini                   # Конфигурация Pytest
├── requirements-dev.txt         # Dev-зависимости (pytest, httpx, httpx2, ruff)
└── README.md                    # Документация проекта
```

---

## 🔒 Политика безопасности

- Все входящие порты сервисов открыты строго на `127.0.0.1`.
- Приложение работает от имени непривилегированного пользователя `appuser`.
- Корневая файловая система контейнера смонтирована в режиме `read_only: true` с `tmpfs: /tmp`.
- Сброшены все Linux capabilities (`cap_drop: ALL`).
- Пароли и секреты никогда не коммитятся в репозиторий.