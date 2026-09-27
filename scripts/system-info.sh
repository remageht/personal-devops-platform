#!/bin/bash
set -euo pipefail
echo "=== Системная информация ==="
echo "Hostname: $(hostname)"
echo "OS: Debian GNU/Linux (inside container)"
if command -v uptime >/dev/null 2>&1; then uptime -p 2>/dev/null || true; fi
echo "CPU cores: $(nproc)"
if command -v free >/dev/null 2>&1; then free -h | awk '/Mem:/ {print "Memory: " $2}'; fi
df -h / | awk 'NR==2 {print "Disk usage: " $5}'
if command -v docker >/dev/null 2>&1; then
    echo "Docker running: $(docker ps -q 2>/dev/null | wc -l)"
fi
