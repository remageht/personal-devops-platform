#!/bin/bash
echo "=== Очистка Docker ==="

if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Docker CLI не найден внутри контейнера"
    exit 1
fi

echo "Выполняем очистку Docker..."
docker system prune -f --all --volumes

echo ""
echo "✅ Очистка завершена!"
echo "Свободное место на диске:"
df -h /

echo ""
echo "Текущие запущенные контейнеры:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"