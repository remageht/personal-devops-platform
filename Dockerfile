FROM python:3.12-slim AS runtime

# Минимум пакетов: без sudo, без лишнего. curl нужен для healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    procps \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -g root -d /app -s /usr/sbin/nologin appuser

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY frontend/ ./frontend/
COPY scripts/ ./scripts/

RUN chmod +x /app/scripts/*.sh \
    && chown -R appuser:root /app \
    && chmod -R g-w /app

# non-root (devops-docker + hardening-security). Для доступа к docker.sock
# используйте группу docker на хосте (group_add) вместо privileged.
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Без --reload в проде: стабильность + меньше CPU. Для dev — override command в compose.override.yml
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
