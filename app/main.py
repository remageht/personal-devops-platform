from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from prometheus_client import start_http_server, Counter, Gauge
import time
import threading
import docker
import subprocess
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
client = docker.from_env(timeout=10)

SCRIPTS_DIR = Path("/app/scripts")

class ContainerAction(BaseModel):
    action: str

class ScriptRun(BaseModel):
    script_name: str

# Главная страница
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    requests_total.inc()
    try:
        with open("/app/frontend/index.html", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1 style='color:white;text-align:center;margin-top:100px'>Personal DevOps Platform<br><br>Frontend загружен</h1>"

@app.get("/api/status")
async def api_status():
    requests_total.inc()
    uptime = round(time.time() - start_time, 1)

    containers = []
    try:
        for c in client.containers.list(all=True):
            containers.append({
                "id": c.short_id,
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else "unknown"
            })
    except:
        pass

    return {
        "status": "healthy",
        "uptime_seconds": uptime,
        "containers": containers
    }

@app.post("/api/run-script")
async def run_script(script: ScriptRun):
    script_path = SCRIPTS_DIR / script.script_name
    if not script_path.exists():
        raise HTTPException(404, f"Скрипт {script.script_name} не найден")

    try:
        result = subprocess.run(["bash", str(script_path)], capture_output=True, text=True, timeout=60, cwd="/app/scripts")
        output = result.stdout + result.stderr
        prefix = "✅ Выполнено успешно" if result.returncode == 0 else f"❌ Ошибка (код {result.returncode})"
        return {"status": "success", "output": f"{prefix}:\n{output}", "return_code": result.returncode}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/container/{container_name}/action")
async def container_action(container_name: str, action: ContainerAction):
    try:
        container = client.containers.get(container_name)
        if action.action == "restart":
            container.restart()
            msg = f"✅ {container_name} перезапущен"
        elif action.action == "stop":
            container.stop(timeout=10)
            msg = f"⏹ {container_name} остановлен"
        elif action.action == "start":
            container.start()
            msg = f"▶ {container_name} запущен"
        else:
            raise HTTPException(400, "Неизвестное действие")
        return {"status": "success", "message": msg}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/api/container/{container_name}/logs")
async def container_logs(container_name: str, lines: int = 150):
    try:
        container = client.containers.get(container_name)
        logs = container.logs(tail=lines, timestamps=True).decode("utf-8", errors="ignore")
        return {"logs": logs}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/health")
async def health():
    return {"status": "ok"}