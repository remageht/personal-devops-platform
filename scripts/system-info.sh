#!/bin/bash
echo "=== Системная информация ==="
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
echo "Uptime: $(uptime -p)"
echo "CPU: $(nproc) cores"
echo "Memory: $(free -h | awk '/Mem:/ {print $2}')"
echo "Disk usage: $(df -h / | awk 'NR==2 {print $5}')"
echo "Docker containers: $(docker ps -q | wc -l) running"
