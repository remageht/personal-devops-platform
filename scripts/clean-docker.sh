#!/bin/bash
set -euo pipefail
echo "=== Очистка Docker ==="

if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Docker CLI не найден внутри контейнера" >&2
    exit 1
fi

if [[ "${ALLOW_PRUNE:-0}" != "1" ]]; then
    echo "⛔ Prune заблокирован. Backend должен выставить ALLOW_PRUNE=1 (см. .env.example)." >&2
    exit 2
fi

echo "Выполняем очистку Docker (только dangling, без --volumes чтобы не снести данные)..."
docker system prune -f

echo ""
echo "✅ Очистка завершена!"
echo "Свободное место на диске:"
df -h /
echo ""
echo "Текущие запущенные контейнеры:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
