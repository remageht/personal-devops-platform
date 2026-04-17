FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
COPY frontend/ ./frontend/ 
# Prometheus metrics будут доступны на порту 8001
EXPOSE 8000 8001

CMD ["python","-m","uvicorn","main:app", "--host", "0.0.0.0", "--port", "8000"]