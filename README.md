# 🚀 Personal DevOps Platform

**Твоя личная DevOps-лаборатория на Ubuntu 25.10**

Современная веб-платформа для мониторинга, управления и автоматизации твоей домашней инфраструктуры.  
Построена с нуля как учебный проект с реальным практическим применением.

![Dashboard Preview](https://via.placeholder.com/800x400/1f2937/60a5fa?text=Personal+DevOps+Dashboard)

---

## ✨ Возможности (на текущий момент)

- ✅ Современный FastAPI backend
- ✅ Красивый responsive дашборд (HTML + Tailwind + vanilla JS)
- ✅ Встроенный мониторинг через Prometheus + Grafana
- ✅ Автоматический сбор метрик приложения
- ✅ Удобный интерфейс с быстрыми действиями
- ✅ Полностью контейнеризировано через Docker Compose
- ✅ Готово к расширению (CI/CD, Ansible, Terraform, реальное управление контейнерами)

---

## 🛠 Технологический стек

| Слой              | Технологии                              |
|-------------------|-----------------------------------------|
| **Backend**       | Python 3.12 + FastAPI                   |
| **Frontend**      | HTML + Tailwind CSS + Vanilla JS        |
| **Containerization** | Docker + Docker Compose              |
| **Мониторинг**    | Prometheus + Grafana + cAdvisor (скоро) |
| **Метрики**       | prometheus-client                       |
| **CI/CD**         | GitHub Actions (в процессе)             |
| **IaC**           | Ansible + Terraform (следующие этапы)   |

---

## 🚀 Быстрый старт

### 1. Клонируй репозиторий

```bash
git clone <твой-репозиторий>
cd personal-devops-platform

### 2. Запусти платформу
```Bashdocker compose down
docker compose build --no-cache
docker compose up -d
###    3. Открой в браузере

Основной дашборд: http://localhost:8000
Grafana (логин/пароль: admin / admin): http://localhost:3000
Prometheus: http://localhost:9090

📁 Структура проекта
Bashpersonal-devops-platform/
├── app/                    # Backend (FastAPI)
│   ├── main.py
│   └── requirements.txt
├── frontend/               # Веб-интерфейс
│   └── index.html
├── monitoring/             # Конфигурация Prometheus
│   └── prometheus.yml
├── scripts/                # Bash-скрипты и утилиты
├── docker-compose.yml
├── Dockerfile
└── README.md