from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from prometheus_client import start_http_server, Counter, Gauge
import time
import threading
import docker
from typing import List, Dict

app = FastAPI(title="Personal DevOps Platform")

# Монтируем папку frontend как статические файлы
app.mount("/static", StaticFiles(directory="/app/frontend"), name="static")

# Prometheus метрики
requests_total = Counter('http_requests_total', 'Total HTTP requests')
app_uptime = Gauge('app_uptime_seconds', 'Application uptime in seconds')

def start_prometheus():
    start_http_server(8001)

threading.Thread(target=start_prometheus, daemon=True).start()

start_time = time.time()

# Клиент Docker (будет работать внутри контейнера)
try:
    docker_client = docker.from_env()
except Exception:
    docker_client = None

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    requests_total.inc()
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Personal DevOps Platform</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    </head>
    <body class="bg-gray-950 text-gray-100">
        <div class="max-w-7xl mx-auto p-8">
            <h1 class="text-4xl font-bold mb-2 flex items-center gap-3">
                <i class="fas fa-server text-emerald-500"></i>
                Personal DevOps Platform
            </h1>
            <p class="text-gray-400 mb-10">v0.2 • Домашняя DevOps лаборатория</p>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Статус приложения -->
                <div class="bg-gray-900 rounded-2xl p-6">
                    <h2 class="text-xl font-semibold mb-4">📊 Статус приложения</h2>
                    <div id="app-info" class="space-y-2 text-lg"></div>
                </div>

                <!-- Контейнеры -->
                <div class="bg-gray-900 rounded-2xl p-6">
                    <h2 class="text-xl font-semibold mb-4">🐳 Запущенные контейнеры</h2>
                    <div id="containers" class="space-y-3"></div>
                </div>
            </div>

            <div class="mt-10 text-center text-gray-500 text-sm">
                Grafana → <a href="http://localhost:3000" target="_blank" class="text-purple-400 hover:underline">открыть</a> | 
                Prometheus → <a href="http://localhost:9090" target="_blank" class="text-purple-400 hover:underline">открыть</a>
            </div>
        </div>

        <script>
            async function loadData() {
                try {
                    const res = await fetch('/api/status');
                    const data = await res.json();

                    document.getElementById('app-info').innerHTML = `
                        <div class="flex justify-between"><span class="text-gray-400">Статус</span><span class="text-emerald-400">● ${data.status}</span></div>
                        <div class="flex justify-between"><span class="text-gray-400">Uptime</span><span>${data.uptime_seconds} сек</span></div>
                    `;

                    // Контейнеры
                    let html = '';
                    data.containers.forEach(c => {
                        const statusColor = c.status.includes('running') ? 'text-emerald-400' : 'text-red-400';
                        html += `
                            <div class="flex justify-between items-center bg-gray-800 p-3 rounded-xl">
                                <span class="font-medium">${c.name}</span>
                                <span class="${statusColor}">${c.status}</span>
                            </div>`;
                    });
                    document.getElementById('containers').innerHTML = html || '<p class="text-gray-500">Нет запущенных контейнеров</p>';

                } catch (e) {
                    console.error(e);
                }
            }

            setInterval(loadData, 3000);
            window.onload = loadData;
        </script>
    </body>
    </html>
    """

@app.get("/api/status")
async def api_status():
    requests_total.inc()
    uptime = round(time.time() - start_time, 1)

    containers = []
    if docker_client:
        try:
            for container in docker_client.containers.list():
                containers.append({
                    "name": container.name,
                    "status": container.status
                })
        except:
            pass

    return {
        "status": "healthy",
        "uptime_seconds": uptime,
        "containers": containers
    }

@app.get("/health")
async def health():
    requests_total.inc()
    return {"status": "ok", "uptime": round(time.time() - start_time, 2)}