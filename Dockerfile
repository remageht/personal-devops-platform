FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    curl \
    docker.io \
    sudo \
    gcc \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

# Устанавливаем Python-зависимости
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код и скрипты
COPY app/ .
COPY frontend/ ./frontend/ 
COPY scripts/ ./scripts

# Prometheus metrics будут доступны на порту 8001
EXPOSE 8000 8001

CMD ["python","-m","uvicorn","main:app", "--host", "0.0.0.0", "--port", "8000"]