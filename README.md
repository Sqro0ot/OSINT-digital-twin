# OSINT Digital Twin — Prototype

> **Дипломная работа** | МУИТ | Тема: *Интеграция OSINT-данных в цифровые двойники подсистем умного города*

Прототип демонстрирует интеграцию OSINT-данных в цифровый двойник подсистемы
дорожных камер города Алматы. Цель — визуализация уязвимостей ИКТ-устройств на карте города
в режиме реального времени с алертами при появлении новых CVE.

---

## Архитектура (4 уровня)

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│ Layer 4: Visualization           React + MapLibreGL + Recharts               │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Layer 3: Digital Twin            twin.py + api.py (FastAPI, 16 endpoints)    │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Layer 2: Processing              normalize.py + nvd_client.py                │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Collection              osint_shodan.py (InternetDB)                │
└────────────────────────────────────────────────────────────────────────────────────┘
```

## Технологический стек

| Компонент | Технология |
|-----------|----------|
| Backend API | Python 3.11 + FastAPI + SQLAlchemy |
| База данных | PostgreSQL 14 |
| Планировщик | APScheduler |
| OSINT источник | Shodan InternetDB (free) + NVD NIST |
| Геолокация | mock_locations.py (прототип) / GeoLite2-City.mmdb (production) |
| Фронтенд | React + TypeScript |
| Контейнеризация | Docker Compose |

---

## Быстрый старт

### 1. Настройка окружения

Запустите PostgreSQL:

```bash
cd infra
docker-compose up -d
```

### 2. Настройка backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Создайте `backend/.env`:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/diploma
SHODAN_API_KEY=          # Опционально: для полного Shodan API
NVD_API_KEY=             # Опционально: 50 запросов/сек всто 5
```

```bash
cd backend
uvicorn app.main:app --reload
```

Swagger UI: http://localhost:8000/docs

### 3. Настройка фронтенда

```bash
cd frontend
npm install
npm start
```

Фронтенд: http://localhost:3000

---

## OSINT-пайплайн: запуск вручную

```bash
# 1. Сбор данных через InternetDB
curl -X POST "http://localhost:8000/osint/shodan/fetch?ips=8.8.8.8&ips=1.1.1.1"

# 2. Нормализация сырых данных
curl -X POST "http://localhost:8000/osint/normalize"

# 3. Пополнение CVE-записей
curl -X POST "http://localhost:8000/cve/populate"

# 4. Подтягивание CVSS-оценок из NVD
curl -X POST "http://localhost:8000/cve/backfill"

# 5. Синхронизация с цифровым двойником
curl -X POST "http://localhost:8000/twin/sync"
```

---

## API Reference (16 эндпоинтов)

### OSINT Pipeline
| Метод | URL | Описание |
|--------|-----|----------|
| POST | `/osint/shodan/fetch` | Сбор данных через InternetDB |
| POST | `/osint/normalize` | Нормализация в NormalizedDevice |

### CVE Management
| Метод | URL | Описание |
|--------|-----|----------|
| POST | `/cve/populate` | Извлекает CVE ID из RawCensys |
| POST | `/cve/backfill` | Подтягивает CVSS из NVD NIST |

### Digital Twin
| Метод | URL | Описание |
|--------|-----|----------|
| POST | `/twin/sync` | Синхронизация NormalizedDevice → Asset |
| GET | `/map/cameras` | Список камер (фильтр по risk_level) |
| GET | `/assets/{id}` | Детали актива |
| GET | `/stats/summary` | Сводная статистика |

### Analytics
| Метод | URL | Описание |
|--------|-----|----------|
| GET | `/alerts/recent` | Последние алерты |
| GET | `/analytics/risk-distribution` | Распределение по уровням риска |
| GET | `/analytics/top-cves` | Топ-5 CVE по частоте |

### Simulation (What-If Analysis)
| Метод | URL | Описание |
|--------|-----|----------|
| POST | `/simulate/zero-day` | Моделирование zero-day (CVE-2026-9999, CVSS 10.0) |
| POST | `/simulate/reset` | Сброс симуляции до исходного состояния |

### Admin
| Метод | URL | Описание |
|--------|-----|----------|
| POST | `/admin/alerts/clear` | Удаление всех алертов |
| POST | `/admin/assets/clear` | Удаление активов (требует `?confirm=DELETE`) |
| POST | `/admin/assets/rebuild` | Очистка + пересоздание из NormalizedDevice |

---

## Модули backend

| Файл | Назначение |
|------|----------|
| `osint_shodan.py` | Layer 1: Сбор через InternetDB |
| `normalize.py` | Layer 2: Нормализация + confidence score |
| `nvd_client.py` | Layer 2: Получение CVSS из NVD |
| `risk.py` | Layer 2: Маппинг CVSS v3.1 → risk_level |
| `twin.py` | Layer 3: Синхронизация + алерты |
| `api.py` | Layer 3+4: FastAPI эндпоинты |
| `scheduler.py` | Layer 1-3: Автоматическое расписание |
| `models.py` | ORM: RawCensys, RawCVE, NormalizedDevice, Asset, Alert |
| `mock_locations.py` | Мок координат для 9 точек Алматы |

---

## Схема БД

Автоматически создаётся через SQLAlchemy ORM при старте (`Base.metadata.create_all`).
4 таблицы: `raw_censys`, `raw_cve`, `normalized_device`, `assets`, `alerts`.

---

## Особенности прототипа

- **`CAMERA_LIMIT = 3`** — прототип работает с 3 камерами (достаточно для демонстрации полного цикла)
- **InternetDB vs Shodan API** — бесплатный источник, не возвращает геолокацию
- **mock_locations** — 9 координат в центре Алматы (заменяются GeoLite2 в production)
- **Confidence score** и **risk_level** — два отдельных понятия (не путать!)
- **Scheduler** — для автосбора заполните `TARGET_IPS` в `scheduler.py`

---

## Направления дальнейшего развития

- [ ] Интеграция GeoLite2-City.mmdb вместо mock-координат
- [ ] Переход на полный Shodan API (баннеры, поиск по стране/организации)
- [ ] Заполнение TARGET_IPS из автоматического реестра устройств
- [ ] Добавление unit-тестов (pytest)
- [ ] Расширение на другие подсистемы (энергетика, водоснабжение)
- [ ] ML-модель для предсказания аномалий
