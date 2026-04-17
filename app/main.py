from fastapi import FastAPI
from prometheus_client import start_http_server, Counter, Gauge
import time
import threading

app = FastAPI(title="Personal DevOps Platform")

# Простые метрики
requests_total = Counter('http_requests_total', 'Total HTTP requests')
uptime = Gauge('app_uptime_seconds','Application uptime')

# Запускаем Prometheus HTTP сервер в отдельном потоке (порт 8001)
def start_prometheus():
    start_http_server(8001)

# Запускаем метрики при старте приложения
threading.Thread(target=start_prometheus,daemon=True).start()

start_time = time.time()

@app.get("/")
async def root():
    requests_total.inc()
    return {"message": "Personal DevOps Platform v0.1 - работает!",
            "status": "healthy",
            "uptime_seconds": uptime
            }

@app.get("/health")
async def health():
    requests_total.inc()
    return {"message": "ok",
             "uptime": round(time.time() - start_time, 2)}

@app.get("/containers")
async def list_containers():
    requests_total.inc()
    # Пока заглушка, позже будем вызывать Docker API
    return {"status":"ok","containers": "Пока заглушка. Здесь будет список запущенных контейнеров."}