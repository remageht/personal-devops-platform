from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from prometheus_client import start_http_server, Counter, Gauge
import time
import threading
import docker
from pydantic import BaseModel
from pathlib import Path

app = FastAPI(title="Personal DevOps Platform")

# Метрики
requests_total = Counter('http_requests_total', 'Total HTTP requests')
app_uptime = Gauge('app_uptime_seconds', 'Application uptime in seconds')

def start_prometheus():
    start_http_server(8001)

threading.Thread(target=start_prometheus, daemon=True).start()

start_time = time.time()

# Docker client
client = docker.from_env(timeout=10)

class ContainerAction(BaseModel):
    action: str  # "restart", "stop", "start"

class ScriptRun(BaseModel):
    script_name: str

SCRIPTS_DIR=Path("/app/scripts")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    requests_total.inc()
    with open("/app/frontend/index.html", encoding="utf-8") as f:
        return f.read()

@app.get("/api/status")
async def api_status():
    requests_total.inc()
    uptime = round(time.time() - start_time, 1)

    containers = []
    if client:
        try:
            for c in client.containers.list(all=True):  # all=True чтобы видеть stopped тоже
                containers.append({
                    "id": c.short_id,
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else "unknown"
                })
        except Exception as e:
            print(f"Docker error: {e}")

    return {
        "status": "healthy",
        "uptime_seconds": uptime,
        "containers": containers
    }

@app.post("/api/container/{container_name}/action")
async def container_action(container_name: str, action: ContainerAction):
    try:
        container = client.containers.get(container_name)
        
        if action.action == "restart":
            container.restart()
            msg = f"✅ Контейнер **{container_name}** перезапущен"
        elif action.action == "stop":
            container.stop(timeout=10)
            msg = f"⏹ Контейнер **{container_name}** остановлен"
        elif action.action == "start":
            container.start()
            msg = f"▶ Контейнер **{container_name}** запущен"
        else:
            raise HTTPException(400, "Неизвестное действие")

        return {"status": "success", "message": msg}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/container/{container_name}/logs")
async def container_logs(container_name: str, lines: int = 100):
    try:
        container = client.containers.get(container_name)
        logs = container.logs(tail=lines, timestamps=True).decode("utf-8", errors="ignore")
        return {"logs": logs}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/run-script")
async def run_script(script: ScriptRun):
    script_path = SCRIPTS_DIR / script.script_name
    if not script_path.exists():
        raise HTTPException(404, "Скрипт не найден")

    try:
        result = subprocess.run([str(script_path)], capture_output=True, text=True, timeout=60)
        return {
            "status": "success",
            "output": result.stdout + result.stderr,
            "return_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Скрипт выполнялся слишком долго")
    except Exception as e:
        raise HTTPException(500, str(e))
        
@app.get("/health")
async def health():
    return {"status": "ok"}