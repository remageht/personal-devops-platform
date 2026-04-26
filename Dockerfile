FROM python:3.12-slim

# Устанавливаем только необходимые системные утилиты
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
COPY frontend/ ./frontend/
COPY scripts/ ./scripts/

RUN chmod +x /app/scripts/*.sh

EXPOSE 8000 8001

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]