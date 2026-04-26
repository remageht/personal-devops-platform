#!/bin/bash
echo "=== Системная информация ==="
echo "Hostname: $(hostname)"
echo "OS: Debian GNU/Linux (inside container)"
echo "Uptime: $(uptime -p 2>/dev/null || echo 'N/A')"
echo "CPU cores: $(nproc)"
echo "Memory: $(free -h | awk '/Mem:/ {print $2}')"
echo "Disk usage: $(df -h / | awk 'NR==2 {print $5}')"
echo "Docker containers (from host): $(docker ps -q 2>/dev/null | wc -l) running"