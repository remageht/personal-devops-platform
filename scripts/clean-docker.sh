#!/bin/bash
echo "=== Очистка Docker ==="
docker system prune -f
docker image prune -f
echo "Очистка завершена. Свободное место:"
df -h /
