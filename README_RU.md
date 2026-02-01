<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>Фреймворк автоматизированной оркестрации Red Team на основе ИИ</b><br>
  <sub>Кроссплатформенный | 101 MCP инструментов | 2000+ Payload | Полное покрытие ATT&CK | Граф знаний</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md"><b>Русский</b></a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues"><img src="https://img.shields.io/github/issues/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/commits/main"><img src="https://img.shields.io/github/last-commit/Coff0xc/AutoRedTeam-Orchestrator?style=flat-square&logo=github" alt="Последний коммит"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Версия-3.0.1-blue?style=flat-square" alt="Версия">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/Инструменты-101-FF6B6B?style=flat-square" alt="Инструменты">
  <img src="https://img.shields.io/badge/Тесты-1461-4CAF50?style=flat-square" alt="Тесты">
  <img src="https://img.shields.io/badge/Лицензия-MIT-green?style=flat-square" alt="Лицензия">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Сообщество-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Документация-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/actions"><img src="https://img.shields.io/github/actions/workflow/status/Coff0xc/AutoRedTeam-Orchestrator/ci.yml?style=flat-square&logo=github-actions&logoColor=white&label=CI" alt="CI"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/demo.gif" alt="Демо" width="700">
</p>

## Основные возможности

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AutoRedTeam-Orchestrator v3.0.1                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ● 101 MCP инструмент  ● 2000+ Payload        ● 1461 тестовый случай      │
│  ● 10-фазная разведка  ● 19 детекторов уязв.   ● 5-протокольный латерал   │
│  ● MCTS планировщик    ● Граф знаний           ● ИИ-генерация PoC         │
│  ● OOB верификация     ● DI контейнер          ● MCP Security Middleware  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Поддерживаемые ИИ-редакторы: Cursor | Windsurf | Kiro | Claude Desktop   │
│                               | VS Code                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Содержание

- [Обзор проекта](#обзор-проекта)
- [Основные функции](#основные-функции)
- [Философия дизайна](#философия-дизайна)
- [Архитектура](#архитектура)
- [Матрица покрытия ATT&CK](#матрица-покрытия-attck)
- [Быстрый старт](#быстрый-старт)
  - [Системные требования](#системные-требования)
  - [Установка](#установка)
  - [Проверка установки](#проверка-установки)
- [Конфигурация MCP](#конфигурация-mcp)
- [Матрица инструментов](#матрица-инструментов-101-mcp-инструментов)
- [Основные модули](#основные-модули)
- [Интеграция внешних инструментов](#интеграция-внешних-инструментов)
- [Примеры использования](#примеры-использования)
  - [Команды на естественном языке](#команды-на-естественном-языке)
  - [Python API](#python-api)
- [Конфигурация](#конфигурация)
- [Оптимизация производительности](#оптимизация-производительности)
- [Устранение неполадок](#устранение-неполадок)
- [FAQ](#faq)
- [Руководство по разработке](#руководство-по-разработке)
- [История изменений](#история-изменений)
- [Дорожная карта](#дорожная-карта)
- [Руководство по внесению вклада](#руководство-по-внесению-вклада)
- [Политика безопасности](#политика-безопасности)
- [Благодарности](#благодарности)
- [Лицензия](#лицензия)
- [Отказ от ответственности](#отказ-от-ответственности)

---

## Обзор проекта

**AutoRedTeam-Orchestrator** — это фреймворк автоматизированного тестирования на проникновение на основе ИИ, построенный на [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Он инкапсулирует 101 инструмент безопасности как MCP-инструменты, обеспечивая бесшовную интеграцию с MCP-совместимыми ИИ-редакторами (Cursor, Windsurf, Kiro, Claude Desktop) для автоматизированного тестирования безопасности на естественном языке.

### Почему AutoRedTeam-Orchestrator?

| Характеристика | Традиционные инструменты | AutoRedTeam |
|----------------|-------------------------|-------------|
| **Взаимодействие** | Запоминание команд CLI | Диалог на естественном языке |
| **Кривая обучения** | Высокая (много параметров) | Низкая (ИИ выбирает инструменты) |
| **Интеграция инструментов** | Ручное переключение | 101 инструмент в едином интерфейсе |
| **Планирование атак** | Ручное планирование | **Алгоритм MCTS + Граф знаний** |
| **Снижение ложных срабатываний** | Ручная верификация | **OOB + Статистическая верификация** |
| **Создание отчётов** | Ручное написание | Профессиональные отчёты в один клик |
| **Управление сессиями** | Отсутствует | Поддержка контрольных точек/возобновления |
| **Безопасность** | По каждому инструменту отдельно | **MCP Security Middleware — единая защита** |

### Сравнение с аналогами

| Возможность | AutoRedTeam | Nuclei | SQLMap | Metasploit |
|-------------|-------------|--------|--------|------------|
| ИИ-нативный | ✅ | ❌ | ❌ | ❌ |
| MCP-протокол | ✅ | ❌ | ❌ | ❌ |
| Естественный язык | ✅ | ❌ | ❌ | ❌ |
| MCTS планирование атак | ✅ | ❌ | ❌ | ❌ |
| Граф знаний | ✅ | ❌ | ❌ | ❌ |
| Полная автоматизация | ✅ | Частично | Частично | Частично |
| Фильтрация ложных срабатываний | Мульти-метод | Базовая | Средняя | Базовая |

---

## Основные функции

<table>
<tr>
<td width="50%">

### ИИ-нативный дизайн

- **Интеллектуальная идентификация** — Автоматическое определение технологического стека цели (CMS/фреймворки/WAF)
- **MCTS планирование атак** — Оптимальные пути атаки на основе алгоритма Монте-Карло
- **Граф знаний** — Персистентное хранилище знаний с межсессионным обучением
- **Обучение на исторической обратной связи** — Непрерывная оптимизация стратегии
- **Автоматический выбор полезной нагрузки** — Интеллектуальная мутация с учётом WAF
- **ИИ-генерация PoC** — Автоматическая генерация кода эксплойта из описаний CVE

</td>
<td width="50%">

### Полная автоматизация

- **10-фазный конвейер разведки** — DNS/Порты/Отпечатки/WAF/Поддомены/Директории/JS-анализ
- **Обнаружение и верификация уязвимостей** — Автоматическое сканирование + **мульти-метод валидации**
- **Интеллектуальная оркестрация эксплойтов** — Движок обратной связи + автоматический повтор
- **Профессиональные отчёты в один клик** — JSON/HTML/Markdown форматы
- **Контрольные точки восстановления сессий** — Возобновление прерванных сканирований

</td>
</tr>
<tr>
<td width="50%">

### Инструментарий Red Team

- **Латеральное перемещение** — SMB/SSH/WMI/WinRM/PSExec (5 протоколов)
- **C2 коммуникация** — Beacon + DNS/HTTP/WebSocket/ICMP туннели
- **Обфускация и уклонение** — XOR/AES/Base64/Пользовательские кодировщики
- **Персистентность** — Реестр Windows/Планировщик задач/WMI/Linux cron/Webshell
- **Доступ к учётным данным** — Извлечение из памяти/Поиск файлов/Распыление паролей
- **Атаки на AD** — Kerberoasting/AS-REP Roasting/SPN сканирование

</td>
<td width="50%">

### Расширения безопасности

- **Безопасность API** — Тестирование JWT/CORS/GraphQL/WebSocket/OAuth
- **Безопасность цепочки поставок** — Генерация SBOM/Аудит зависимостей/Сканирование CI-CD
- **Облачная нативная безопасность** — K8s RBAC/Безопасность Pod/gRPC/Аудит AWS
- **CVE-разведка** — Мультиисточниковая синхронизация NVD/Nuclei/ExploitDB
- **Обход WAF** — 2000+ полезных нагрузок + 30+ методов кодирования

</td>
</tr>
</table>

---

## Философия дизайна

### Ключевые принципы проектирования

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           Философия дизайна                               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   1. ИИ-нативный                                                          │
│      └─ Не «обёртка ИИ», а архитектурно спроектирован для ИИ             │
│         └─ Нативная поддержка протокола MCP                               │
│         └─ Выбор инструментов на естественном языке                       │
│         └─ Планирование атак на основе алгоритма MCTS                    │
│                                                                            │
│   2. Верифицируемая безопасность                                          │
│      └─ Мульти-метод перекрёстной валидации для снижения ложных          │
│         срабатываний                                                      │
│         └─ Статистическая верификация (тест значимости)                   │
│         └─ Boolean blind верификация (сравнение True/False ответов)       │
│         └─ Time-based blind верификация (обнаружение задержки)            │
│         └─ OOB верификация (DNS/HTTP callback)                            │
│                                                                            │
│   3. Персистентность знаний                                               │
│      └─ Знания об атаках сохраняются между сессиями                      │
│         └─ Граф знаний хранит связи: цель, уязвимость, учётные данные    │
│         └─ Вероятность успеха пути атаки рассчитывается из истории        │
│         └─ Идентификация похожих целей ускоряет тестирование              │
│                                                                            │
│   4. Безопасность по дизайну                                              │
│      └─ Безопасность — часть архитектуры, а не надстройка                │
│         └─ MCP Security Middleware: валидация ввода, ограничение          │
│            скорости                                                       │
│         └─ TOCTOU-безопасность: атомарные операции, защита от гонок      │
│         └─ Безопасность памяти: лимиты ресурсов, автоочистка             │
│                                                                            │
│   5. Расширяемая архитектура                                              │
│      └─ DI-контейнер для гибкой композиции сервисов                      │
│         └─ Модульный дизайн Handler                                       │
│         └─ YAML-конфигурация внешних инструментов                        │
│         └─ Составной паттерн детекторов для произвольных комбинаций      │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Матрица технических решений

| Решение | Варианты | Выбор | Обоснование |
|---------|----------|-------|-------------|
| **Коммуникация** | REST / gRPC / MCP | MCP | Нативная поддержка ИИ-редакторов, бесшовное NLP-взаимодействие |
| **Планирование атак** | Rule Engine / MCTS / RL | MCTS | Онлайн-планирование, не требует предобучения, UCB1 баланс исследования-эксплуатации |
| **Хранение знаний** | SQL / Graph DB / Память | Граф в памяти + опциональный Neo4j | Запуск без зависимостей, высокопроизводительные запросы, опциональная персистентность |
| **Управление зависимостями** | Глобалы / DI | DI-контейнер | Тестируемость, заменяемость, управление жизненным циклом |
| **Параллелизм** | Threading / asyncio / Гибрид | asyncio (основной) | Оптимален для IO-bound, нативная поддержка Python |
| **Хэширование** | MD5 / SHA256 | SHA256 | Более высокая безопасность, современный стандарт |

---

## Архитектура

### Высокоуровневая архитектура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Слой ИИ-редакторов                               │
│        Cursor  │  Windsurf  │  Kiro  │  Claude Desktop  │  VS Code         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ MCP-протокол (JSON-RPC поверх stdio)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Точка входа MCP-сервера                             │
│                      mcp_stdio_server.py                                   │
│                    (101 зарегистрированный инструмент)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                     MCP Security Middleware                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │ Валидация   │  │ Ограничение │  │ Авторизация │  │ @secure_tool│       │
│  │ ввода       │  │ скорости    │  │ операций    │  │             │       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   handlers/       │   │   core/           │   │   modules/        │
│   MCP-обработчики │   │   Основные движки │   │   Модули функций  │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • recon_handlers  │   │ • recon/          │   │ • api_security/   │
│ • detector_hdlrs  │   │   10-фаз. развед.│   │   JWT/CORS/GQL    │
│ • cve_handlers    │   │ • detectors/      │   │ • supply_chain/   │
│ • redteam_hdlrs   │   │   Детект. уязвим. │   │   SBOM/Зависим.  │
│ • lateral_hdlrs   │   │ • mcts_planner    │   │ • cloud_security/ │
│ • external_hdlrs  │   │   MCTS планировщ. │   │   K8s/gRPC/AWS    │
│ • ai_handlers     │   │ • knowledge/      │   │ • payload/        │
│ • session_hdlrs   │   │   Граф знаний     │   │   2000+ Payload   │
└───────────────────┘   │ • container       │   └───────────────────┘
                        │   DI-контейнер    │
                        │ • c2/             │
                        │   C2 коммуникация │
                        │ • lateral/        │
                        │   Латер. перемещ.  │
                        │ • cve/            │
                        │   CVE + PoC       │
                        └───────────────────┘
```

### Структура каталогов

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py          # Точка входа MCP-сервера (101 инструмент)
├── VERSION                      # Файл версии
├── pyproject.toml               # Конфигурация проекта
├── requirements.txt             # Продакшн-зависимости
├── requirements-dev.txt         # Зависимости для разработки
│
├── handlers/                    # MCP-обработчики инструментов (16 модулей)
│   ├── recon_handlers.py        # Инструменты разведки (8)
│   ├── detector_handlers.py     # Детекторы уязвимостей (11)
│   ├── api_security_handlers.py # Безопасность API (7)
│   ├── supply_chain_handlers.py # Цепочка поставок (3)
│   ├── cloud_security_handlers.py # Облачная безопасность (3)
│   ├── cve_handlers.py          # CVE-инструменты (8)
│   ├── redteam_handlers.py      # Основные Red Team (14)
│   ├── lateral_handlers.py      # Латеральное перемещение (9)
│   ├── persistence_handlers.py  # Персистентность (3)
│   ├── ad_handlers.py           # Атаки на AD (3)
│   ├── orchestration_handlers.py # Оркестрация (11)
│   ├── external_tools_handlers.py # Внешние инструменты (8)
│   ├── ai_handlers.py           # ИИ-помощь (3)
│   ├── session_handlers.py      # Сессии (4)
│   ├── report_handlers.py       # Отчёты (2)
│   └── misc_handlers.py         # Разное (3)
│
├── core/                        # Основные движки
│   ├── __init__.py              # Определение версии
│   │
│   ├── security/                # Компоненты безопасности ⭐ v3.0.2
│   │   └── mcp_security.py      # MCP Security Middleware
│   │
│   ├── container.py             # DI-контейнер ⭐ v3.0.2
│   │
│   ├── mcts_planner.py          # MCTS планировщик атак ⭐ v3.0.2
│   │
│   ├── knowledge/               # Граф знаний ⭐ v3.0.2
│   │   ├── __init__.py
│   │   ├── manager.py           # Менеджер знаний
│   │   └── models.py            # Модели данных
│   │
│   ├── recon/                   # Движок разведки (10-фазный конвейер)
│   ├── detectors/               # Детекторы уязвимостей
│   ├── cve/                     # CVE-разведка
│   ├── c2/                      # C2-коммуникационный фреймворк
│   ├── lateral/                 # Латеральное перемещение
│   ├── evasion/                 # Уклонение и обфускация
│   ├── persistence/             # Механизмы персистентности
│   ├── credential/              # Доступ к учётным данным
│   ├── ad/                      # Атаки на AD
│   ├── session/                 # Управление сессиями
│   ├── tools/                   # Управление внешними инструментами
│   └── exfiltration/            # Эксфильтрация данных
│
├── modules/                     # Функциональные модули
│   ├── api_security/            # Безопасность API
│   ├── supply_chain/            # Безопасность цепочки поставок
│   ├── cloud_security/          # Облачная безопасность
│   └── payload/                 # Движок полезных нагрузок
│
├── utils/                       # Вспомогательные функции
├── wordlists/                   # Встроенные словари
├── config/                      # Файлы конфигурации
├── tests/                       # Набор тестов (1461 тестовый случай)
├── poc-templates/               # Шаблоны PoC
├── templates/                   # Шаблоны отчётов
├── scripts/                     # Утилитарные скрипты
└── docs/                        # Документация
```

---

## Матрица покрытия ATT&CK

| Тактическая фаза | Покрытие техник | Кол-во инструментов | Статус |
|------------------|-----------------|---------------------|--------|
| Разведка (Reconnaissance) | Активное сканирование, Пассивный сбор, OSINT, JS-анализ | 12+ | ✅ |
| Разработка ресурсов (Resource Development) | Генерация полезных нагрузок, Обфускация, Генерация PoC | 4+ | ✅ |
| Начальный доступ (Initial Access) | Эксплуатация Web-уязвимостей, CVE-эксплойты, API-уязвимости | 19+ | ✅ |
| Выполнение (Execution) | Инъекция команд, Выполнение кода, Десериализация | 5+ | ✅ |
| Персистентность (Persistence) | Реестр, Планировщик задач, Webshell, WMI | 3+ | ✅ |
| Повышение привилегий (Privilege Escalation) | Обход UAC, Имперсонация токенов, Эксплойты ядра | 2+ | ⚠️ |
| Уклонение от защиты (Defense Evasion) | Обход AMSI, Обход ETW, Обфускация, Мутация трафика | 4+ | ✅ |
| Доступ к учётным данным (Credential Access) | Извлечение из памяти, Поиск файлов, Распыление паролей | 2+ | ✅ |
| Обнаружение (Discovery) | Сканирование сети, Перечисление служб, Перечисление AD | 8+ | ✅ |
| Латеральное перемещение (Lateral Movement) | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Сбор (Collection) | Агрегация данных, Поиск конфиденциальных файлов | 2+ | ✅ |
| Командование и управление (C2) | HTTP/DNS/WebSocket/ICMP туннели | 4+ | ✅ |
| Эксфильтрация (Exfiltration) | DNS/HTTP/ICMP/SMB + AES-шифрование | 4+ | ✅ |

---

## Быстрый старт

### Системные требования

| Компонент | Минимальные | Рекомендуемые |
|-----------|-------------|---------------|
| ОС | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 или 3.12 |
| Память | 4GB | 8GB+ |
| Диск | 500MB | 2GB+ (с базой CVE) |
| Сеть | Доступ в интернет | Низкая задержка |

### Установка

#### Вариант 1: Стандартная установка (рекомендуется)

```bash
# 1. Клонировать репозиторий
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Создать виртуальное окружение (рекомендуется)
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Скопировать шаблон окружения
cp .env.example .env
# Отредактируйте .env и введите ваши API-ключи

# 5. Запустить сервис
python mcp_stdio_server.py
```

#### Вариант 2: Минимальная установка (только основное)

```bash
# Установить только основные зависимости (Разведка + Обнаружение уязвимостей)
pip install -r requirements-core.txt
```

#### Вариант 3: Развёртывание Docker

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### Вариант 4: Среда разработки

```bash
# Установить зависимости разработки (тесты, форматирование, линтинг)
pip install -r requirements-dev.txt

# Установить pre-commit хуки
pre-commit install

# Запустить тесты
pytest tests/ -v
```

### Проверка установки

```bash
# Проверить версию
python mcp_stdio_server.py --version
# Вывод: AutoRedTeam-Orchestrator v3.0.1

# Запустить самопроверку
python -c "from core import __version__; print(f'Core version: {__version__}')"

# Запустить тесты основных модулей
pytest tests/test_mcp_security.py tests/test_container.py tests/test_mcts_planner.py tests/test_knowledge_manager.py tests/test_advanced_verifier.py -v
# Ожидается: 291+ passed
```

---

## Конфигурация MCP

Добавьте следующую конфигурацию в файл конфигурации MCP вашего ИИ-редактора:

### Пути к файлам конфигурации

| Редактор | Путь к конфигурации |
|----------|---------------------|
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro | `~/.kiro/mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| VS Code (MCP расширение) | `.vscode/mcp.json` |

### Примеры конфигурации

<details>
<summary><b>Cursor</b> - <code>~/.cursor/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/абсолютный/путь/к/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windsurf</b> - <code>~/.codeium/windsurf/mcp_config.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/абсолютный/путь/к/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": "/абсолютный/путь/к/AutoRedTeam-Orchestrator"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Kiro</b> - <code>~/.kiro/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/абсолютный/путь/к/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/абсолютный/путь/к/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Пример пути Windows</b></summary>

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["C:\\Users\\ВашеИмя\\AutoRedTeam-Orchestrator\\mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

</details>

---

## Матрица инструментов (101 MCP инструментов)

| Категория | Кол-во | Ключевые инструменты | Описание |
|-----------|--------|---------------------|----------|
| **Разведка** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Сбор информации и обнаружение активов |
| **Обнаружение уязвимостей** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + логические уязвимости |
| **Безопасность API** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Современное тестирование безопасности API |
| **Цепочка поставок** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/Зависимости/CI-CD безопасность |
| **Облачные технологии** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS аудит безопасности |
| **Ядро Red Team** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Постэксплуатация и внутренняя сеть |
| **Латеральное перемещение** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5 протоколов латерального перемещения |
| **Персистентность** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **Атаки на AD** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Полный набор для проникновения в домен |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE-разведка + ИИ-генерация PoC |
| **Оркестрация** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Автоматизированное проникновение |
| **Внешние инструменты** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Интеграция профессиональных инструментов |
| **ИИ-помощь** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Интеллектуальный анализ |
| **Сессии/Отчёты** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Управление сессиями + отчётность |

---

## Основные модули

### 1. MCP Security Middleware (v3.0.2)

**Расположение**: `core/security/mcp_security.py`

Единый уровень защиты для всех вызовов MCP-инструментов:

```python
from core.security.mcp_security import MCPSecurityMiddleware, RateLimitConfig

security = MCPSecurityMiddleware(
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,
        burst_limit=10,
    ),
    max_risk=RiskLevel.HIGH,
)

# Валидация цели
result = security.validate_target("192.168.1.1")
if not result.valid:
    print(f"Отклонено: {result.errors}")

# Декоратор защиты
@security.secure_tool(operation="port_scan", rate_limit_key="scan")
async def port_scan(target: str):
    # ...
```

**Основные возможности**:
- **Валидация ввода**: Проверка IP/Домен/URL/CIDR/Порт/Путь, обнаружение SSRF
- **Ограничение скорости**: Скользящее окно + Token Bucket, предотвращение исчерпания ресурсов
- **Авторизация операций**: Контроль операций на основе уровня риска
- **Защита памяти**: Автоочистка устаревших данных, предотвращение утечек памяти

### 2. MCTS планировщик атак (v3.0.2)

**Расположение**: `core/mcts_planner.py`

Использует алгоритм Монте-Карло для поиска оптимальных путей атаки:

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http"},
)

result = planner.plan(state, iterations=1000)
print(f"Рекомендуемые действия: {result['recommended_actions']}")
```

**Основные возможности**:
- **Алгоритм UCB1**: Баланс между исследованием и эксплуатацией
- **Генерация действий**: Интеллектуальная генерация доступных действий на основе состояния
- **Симуляция атак**: Моделирование выполнения атаки для оценки вероятности успеха
- **Извлечение путей**: Извлечение оптимальных последовательностей атак

### 3. Граф знаний (v3.0.2)

**Расположение**: `core/knowledge/`

Персистентное хранилище знаний об атаках с межсессионным обучением:

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Сохранение цели
target_id = km.store_target("192.168.1.100", "linux_server")

# Сохранение сервиса
service_id = km.store_service(target_id, "nginx", 80)

# Сохранение уязвимости
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Поиск путей атаки
paths = km.get_attack_paths(target_id, credential_id)

# Поиск похожих целей
similar = km.find_similar_targets("192.168.1.100")
```

**Основные возможности**:
- **Хранение сущностей**: Цель, Сервис, Уязвимость, Учётные данные
- **Моделирование связей**: HOSTS, HAS_VULNERABILITY, OBTAINED_FROM
- **BFS-поиск путей**: Поддержка обнаружения нескольких путей
- **Поиск по сходству**: Идентификация целей в одной подсети/домене

### 4. Продвинутый верификатор (v3.0.2 улучшенный)

**Расположение**: `core/detectors/advanced_verifier.py`

Мульти-метод перекрёстной валидации для снижения процента ложных срабатываний:

```python
from core.detectors.advanced_verifier import AdvancedVerifier

verifier = AdvancedVerifier(callback_server="oob.example.com")

results = verifier.multi_method_verify(
    url="http://target.com/api?id=1",
    vuln_type="sqli",
    request_func=make_request,
    methods=["statistical", "boolean_blind", "time_based"],
)

aggregated = verifier.aggregate_results(results)
print(f"Статус: {aggregated.status}, Уверенность: {aggregated.confidence:.2%}")
```

**Методы верификации**:
- **Статистическая верификация**: Анализ значимости различий мульти-сэмпловых ответов
- **Boolean blind верификация**: Сравнение True/False условий
- **Time-based blind верификация**: Обнаружение задержки с компенсацией сетевого джиттера
- **OOB верификация**: Подтверждение через DNS/HTTP out-of-band callback

### 5. DI-контейнер (v3.0.2)

**Расположение**: `core/container.py`

Гибкая композиция сервисов и управление жизненным циклом:

```python
from core.container import Container, singleton, inject

container = Container()

# Регистрация сервисов
container.register_singleton(KnowledgeManager)
container.register_transient(SQLiDetector)

# Использование декораторов
@singleton
class ConfigManager:
    pass

# Инъекция зависимостей
config = inject(ConfigManager)

# Контейнер с областью видимости (уровень запроса)
with container.create_scope() as scope:
    service = scope.resolve(RequestService)
```

**Основные возможности**:
- **Жизненный цикл**: Singleton, Scoped, Transient
- **Автоинъекция**: Автоматическое разрешение параметров конструктора
- **Обнаружение циклов**: Обнаружение и отчёт о циклических зависимостях
- **Очистка ресурсов**: Scoped-контейнеры автоматически вызывают dispose()

---

## Интеграция внешних инструментов

Поддержка интеграции локально установленных профессиональных инструментов безопасности:

| Инструмент | Назначение | MCP-команда | Требования |
|------------|------------|-------------|------------|
| **Nmap** | Сканирование портов + обнаружение служб + NSE-скрипты | `ext_nmap_scan` | Системный PATH или указанный путь |
| **Nuclei** | 7000+ шаблонов сканирования CVE/уязвимостей | `ext_nuclei_scan` | Go-бинарник |
| **SQLMap** | 6 техник SQL-инъекций + обход WAF | `ext_sqlmap_scan` | Python-скрипт |
| **ffuf** | Высокоскоростной фаззинг директорий/параметров | `ext_ffuf_fuzz` | Go-бинарник |
| **Masscan** | Сверхскоростное массовое сканирование портов | `ext_masscan_scan` | Требуются права root/администратора |

### Настройка внешних инструментов

Отредактируйте `config/external_tools.yaml`:

```yaml
# Базовый каталог инструментов
base_path: "/путь/к/вашим/security-tools"

tools:
  nmap:
    enabled: true
    path: "${base_path}/nmap/nmap"
    default_args:
      quick: ["-sT", "-T4", "--open"]
      full: ["-sT", "-sV", "-sC", "-T4", "--open"]
      vuln: ["-sV", "--script=vuln"]

  nuclei:
    enabled: true
    path: "${base_path}/nuclei/nuclei"
    templates_path: "${base_path}/nuclei-templates"

  sqlmap:
    enabled: true
    path: "${base_path}/sqlmap/sqlmap.py"
    python_script: true

  ffuf:
    enabled: true
    path: "${base_path}/ffuf/ffuf"

  masscan:
    enabled: true
    path: "${base_path}/masscan/masscan"
    requires_root: true

# Конфигурация цепочки инструментов
chains:
  full_recon:
    - name: "masscan"
      args: ["--rate=10000", "-p1-10000"]
    - name: "nmap"
      args: ["-sV", "-sC"]
      depends_on: "masscan"

  vuln_scan:
    - name: "nuclei"
      args: ["-severity", "critical,high,medium"]
    - name: "sqlmap"
      condition: "has_params"
```

### Оркестрация цепочки инструментов

```bash
# Полная цепочка разведки: masscan быстрое обнаружение -> nmap детальная идентификация
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Цепочка сканирования уязвимостей: nuclei + sqlmap комбинированное обнаружение
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Проверить статус внешних инструментов
ext_tools_status
```

---

## Примеры использования

### Команды на естественном языке

Общайтесь напрямую в ИИ-редакторе для вызова инструментов:

#### Разведка и сбор информации

```
# Полная разведка
"Выполни полную разведку example.com и сгенерируй отчёт"

# Сканирование портов
"Просканируй открытые порты в сети 192.168.1.0/24"

# Перечисление поддоменов
"Перечисли все поддомены example.com"

# Определение отпечатков
"Определи технологический стек и WAF целевого сайта"

# JS-анализ
"Проанализируй JavaScript-файлы целевого сайта на предмет конфиденциальной информации"
```

#### Сканирование уязвимостей

```
# SQL-инъекция
"Проверь, есть ли SQL-инъекция на https://target.com/api?id=1"

# XSS-сканирование
"Просканируй целевые формы на XSS-уязвимости и сгенерируй PoC"

# Безопасность API
"Выполни полное тестирование безопасности JWT/CORS/GraphQL на целевом API"

# Поиск и эксплуатация CVE
"Найди CVE, связанные с Apache Log4j, и выполни PoC"
```

#### Операции Red Team

```
# Латеральное перемещение
"Выполни команду whoami на 192.168.1.100 через SMB"

# C2-коммуникация
"Запусти DNS-туннель к c2.example.com"

# Персистентность
"Установи персистентность через планировщик задач на Windows-цели"

# Атаки на AD
"Выполни атаку Kerberoasting на контроллер домена"
```

#### Автоматизированное тестирование на проникновение

```
# Полностью автоматизированный пентест
"Выполни полностью автоматизированный тест на проникновение на https://target.com с детальным отчётом"

# Интеллектуальная цепочка атак
"Проанализируй цель и сгенерируй оптимальную рекомендацию цепочки атак"

# Возобновление сессии
"Возобнови ранее прерванную сессию тестирования на проникновение"
```

### Python API

#### Базовое использование

```python
import asyncio
from core.recon import StandardReconEngine, ReconConfig
from core.detectors import DetectorFactory

async def main():
    # 1. Движок разведки
    config = ReconConfig(
        quick_mode=False,
        enable_js_analysis=True,
        max_threads=50
    )
    engine = StandardReconEngine("https://target.com", config)
    recon_result = await engine.run()
    print(f"Обнаружено {len(recon_result.open_ports)} открытых портов")

    # 2. Обнаружение уязвимостей
    detector = DetectorFactory.create_composite(['sqli', 'xss', 'ssrf'])
    vuln_results = await detector.async_detect(
        url="https://target.com/api",
        params={'id': '1'}
    )

    for vuln in vuln_results:
        print(f"Обнаружена уязвимость: {vuln.type} - {vuln.severity}")

asyncio.run(main())
```

#### MCTS планирование атак

```python
from core.mcts_planner import MCTSPlanner, AttackState

planner = MCTSPlanner(exploration_weight=1.414, max_depth=10)

state = AttackState(
    target="192.168.1.100",
    target_type="linux_server",
    open_ports={22: "ssh", 80: "http", 3306: "mysql"},
)

result = planner.plan(state, iterations=1000)

print(f"Рекомендуемая последовательность атаки:")
for action, visits, reward in result['recommended_actions']:
    print(f"  - {action.type.value}: {action.target_port} (уверенность: {reward:.2f})")
```

#### Граф знаний

```python
from core.knowledge import KnowledgeManager

km = KnowledgeManager()

# Построение знаний
target_id = km.store_target("192.168.1.100", "linux_server")
service_id = km.store_service(target_id, "nginx", 80)
vuln_id = km.store_vulnerability(service_id, "CVE-2021-44228", "critical")

# Запрос путей атаки
paths = km.get_attack_paths(target_id, vuln_id)
for path in paths:
    print(f"Длина пути: {path.length}, Вероятность успеха: {path.success_rate:.2%}")

# Поиск похожих целей
similar = km.find_similar_targets("192.168.1.100", top_k=5)
for match in similar:
    print(f"Похожая цель: {match.entity.properties['target']}, Оценка: {match.score:.2f}")
```

---

## Конфигурация

### Переменные окружения (.env)

```bash
# ========== Безопасность ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API-ключи ==========
OPENAI_API_KEY=ваш_ключ
ANTHROPIC_API_KEY=ваш_ключ
SHODAN_API_KEY=ваш_ключ
CENSYS_API_ID=ваш_id
CENSYS_API_SECRET=ваш_secret
NVD_API_KEY=ваш_ключ
GITHUB_TOKEN=ваш_токен

# ========== Прокси ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Глобальные настройки ==========
VERIFY_SSL=false
RATE_LIMIT_DELAY=0.3
MAX_THREADS=50
REQUEST_TIMEOUT=10

# ========== Логирование ==========
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
```

---

## Оптимизация производительности

### Конфигурация параллелизма

```yaml
# config/performance.yaml
concurrency:
  max_threads: 100
  max_async_tasks: 200
  connection_pool_size: 50

rate_limiting:
  requests_per_second: 50
  burst_size: 100

timeouts:
  connect: 5
  read: 30
  total: 120
```

### Оптимизация памяти

```python
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,
        batch_size=1000,
        memory_limit="2GB"
    )
)
```

---

## Устранение неполадок

| Проблема | Причина | Решение |
|----------|---------|---------|
| MCP-сервер не подключается | Ошибка пути или проблема окружения Python | Проверьте абсолютный путь, убедитесь в правильном интерпретаторе Python |
| Ошибки импорта | PYTHONPATH не установлен | Добавьте переменную окружения `PYTHONPATH` |
| Сбой внешнего инструмента | Инструмент не установлен или ошибка пути | Выполните `ext_tools_status` |
| Сбой синхронизации CVE | Сеть или ограничение API | Проверьте сеть, настройте NVD_API_KEY |
| Медленное сканирование | Низкая конфигурация параллелизма | Настройте `MAX_THREADS` и `RATE_LIMIT_DELAY` |
| Нехватка памяти | Крупномасштабное сканирование | Включите `streaming_mode`, установите `memory_limit` |

### Режим отладки

```bash
LOG_LEVEL=DEBUG python mcp_stdio_server.py
python -m py_compile mcp_stdio_server.py
pytest tests/test_mcp_security.py::TestInputValidator -v
```

---

## FAQ

<details>
<summary><b>В: Как использовать в оффлайн-среде?</b></summary>

1. Предварительно скачайте базу CVE: `python core/cve/update_manager.py sync --offline-export`
2. Используйте локальные файлы словарей
3. Отключите сетевые функции: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>В: Как добавить пользовательский детектор?</b></summary>

1. Создайте новый файл в `core/detectors/`
2. Наследуйте от класса `BaseDetector`
3. Реализуйте методы `detect()` и `async_detect()`
4. Зарегистрируйте MCP-инструмент в `handlers/detector_handlers.py`

</details>

<details>
<summary><b>В: Как работает MCTS-планировщик?</b></summary>

MCTS планирует пути атаки через четыре фазы:

1. **Выбор (Selection)**: Алгоритм UCB1 выбирает оптимальный путь от корня
2. **Расширение (Expansion)**: Расширение новых действий атаки в листовых узлах
3. **Симуляция (Simulation)**: Моделирование выполнения атаки и оценка вознаграждений
4. **Обратное распространение (Backpropagation)**: Распространение вознаграждений обратно для обновления узлов пути

Формула UCB1: `UCB1 = Q/N + c * sqrt(ln(N_parent) / N)`

Где `c = sqrt(2)` — вес исследования, балансирующий «известные хорошие пути» и «неисследованные пути».

</details>

<details>
<summary><b>В: Как граф знаний сокращает дублирование работы?</b></summary>

1. **Сходство целей**: Идентификация целей в одной подсети/домене, повторное использование информации об уязвимостях
2. **Вероятность успеха путей атаки**: Расчёт вероятности успеха на основе истории
3. **Ассоциация учётных данных**: Автоматическая привязка учётных данных к доступным целям
4. **Обучение на истории действий**: Запись вероятности успеха действий, оптимизация будущих решений

</details>

<details>
<summary><b>В: Как справиться с блокировкой WAF?</b></summary>

1. Используйте инструмент `smart_payload` для автоматического выбора payload с обходом WAF
2. Настройте пул прокси: `PROXY_POOL=true`
3. Включите мутацию трафика: `traffic_mutation=true`
4. Снизьте скорость сканирования: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>В: Какие форматы отчётов поддерживаются?</b></summary>

- JSON (машиночитаемый)
- HTML (визуализированный отчёт с графиками)
- Markdown (подходит для Git/Wiki)
- PDF (требуется установка `reportlab`)
- DOCX (требуется установка `python-docx`)

</details>

---

## Руководство по разработке

### Стандарты кода

```bash
# Форматирование кода
black core/ modules/ handlers/ utils/
isort core/ modules/ handlers/ utils/

# Статический анализ
pylint core/ modules/ handlers/ utils/
mypy core/ modules/ handlers/ utils/

# Запуск тестов
pytest tests/ -v --cov=core --cov-report=html
```

### Добавление новых MCP-инструментов

```python
# 1. Добавьте обработчик в handlers/
# handlers/my_handlers.py

from mcp import tool

@tool()
async def my_new_tool(target: str, option: str = "default") -> dict:
    """Описание инструмента

    Args:
        target: Адрес цели
        option: Опциональный параметр

    Returns:
        Словарь с результатом
    """
    return {"success": True, "data": ...}

# 2. Импортируйте в mcp_stdio_server.py
from handlers.my_handlers import my_new_tool
```

---

## История изменений

### v3.0.2 (В разработке) — Укрепление архитектуры

**Новые модули** (Реализовано, ожидает релиза)
- **MCP Security Middleware** — Валидация ввода, ограничение скорости, авторизация операций
- **DI-контейнер** — Управление жизненным циклом, обнаружение циклических зависимостей
- **MCTS планировщик атак** — Алгоритм UCB1, оптимизация путей атаки
- **Граф знаний** — Хранилище связей сущностей, BFS-поиск путей
- **Улучшение продвинутого верификатора** — Потокобезопасность OOB, SSTI payload

**Исправления безопасности**
- Устранены гонки TOCTOU (расширена область блокировки)
- Исправлена логика истечения авторизации по длительности
- Добавлено обнаружение SSRF (валидация приватных IP)
- Устранена утечка памяти Rate Limiter (max_keys eviction)
- Устранена DNS-инъекция (санитизация ID токена)
- Обновлено хэширование MD5 -> SHA256

**Улучшение тестирования**
- Добавлено 291 тестовых случаев (mcp_security: 62, container: 39, mcts: 57, verifier: 43, knowledge: 90)
- Покрытие тестов потокобезопасности
- Рабочие процессы интеграционного тестирования

### v3.0.1 (2026-01-30) — Укрепление качества

**Добавлено**
- Улучшение автоматической эксплуатации CVE (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- ИИ-генератор PoC (`core/cve/ai_poc_generator.py`)

**Исправлено**
- Синхронизация версий — унифицированы VERSION/pyproject.toml/исходный код
- Исправление ToolCounter — добавлены категории external_tools/lateral/persistence/ad
- Потокобезопасность — добавлен threading.Lock для управления состоянием beacon.py

**Улучшено**
- Укрепление CI/CD — ошибки lint теперь блокируют сборку
- Порог покрытия тестами повышен до 50%
- Ограничения зависимостей — добавлены верхние границы

### v3.0.0 (2026-01-18) — Расширение архитектуры

**Добавлено**
- Интеграция внешних инструментов — 8 MCP-команд внешних инструментов
- Оркестрация цепочки инструментов — YAML-управляемые комбинации инструментов
- Модуляризация обработчиков — 16 независимых модулей Handler

---

## Дорожная карта

### В работе

- [ ] Релиз v3.0.2 (MCP Security Middleware, MCTS-планировщик, граф знаний, DI-контейнер)
- [ ] Web UI интерфейс управления
- [ ] Распределённый кластер сканирования

### Запланировано

- [ ] Больше облачных платформ (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Интеграция плагина Burp Suite
- [ ] Тестирование безопасности мобильных приложений
- [ ] ИИ-автономный агент атак
- [ ] Neo4j-бэкенд графа знаний

### Завершено (v3.0.1)

- [x] Полный инструментарий Red Team
- [x] CVE-разведка и ИИ-генерация PoC
- [x] Модули API/Цепочки поставок/Облачной безопасности
- [x] Полностью автоматизированный фреймворк тестирования на проникновение
- [x] Интеграция внешних инструментов

---

## Руководство по внесению вклада

Мы приветствуем вклад любого рода!

### Быстрый старт

```bash
# 1. Fork и клонирование
git clone https://github.com/ВАШ_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. Создание ветки
git checkout -b feature/ваша-функция

# 3. Установка зависимостей для разработки
pip install -r requirements-dev.txt
pre-commit install

# 4. Разработка и тестирование
pytest tests/ -v

# 5. Отправка PR
git push origin feature/ваша-функция
```

### Соглашение о коммитах

Используйте формат [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` Новая функция
- `fix:` Исправление ошибки
- `docs:` Документация
- `refactor:` Рефакторинг
- `test:` Тестирование
- `chore:` Сборка/Инструменты
- `security:` Связано с безопасностью

Подробности см. в [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Политика безопасности

- **Ответственное раскрытие**: Сообщайте об уязвимостях безопасности на адрес [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Авторизованное использование**: Этот инструмент предназначен только для авторизованного тестирования безопасности и исследований
- **Соответствие законам**: Убедитесь в соблюдении местного законодательства перед использованием

Подробности см. в [SECURITY.md](SECURITY.md).

---

## Благодарности

### Основные зависимости

| Проект | Назначение | Лицензия |
|--------|------------|----------|
| [MCP Protocol](https://modelcontextprotocol.io/) | Стандарт протокола ИИ-инструментов | MIT |
| [aiohttp](https://github.com/aio-libs/aiohttp) | Асинхронный HTTP-клиент | Apache-2.0 |
| [pydantic](https://github.com/pydantic/pydantic) | Валидация данных | MIT |
| [pytest](https://github.com/pytest-dev/pytest) | Фреймворк тестирования | MIT |

### Источники вдохновения

| Проект | Вдохновение |
|--------|-------------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Дизайн движка сканирования уязвимостей |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | Подход к обнаружению SQL-инъекций |
| [Impacket](https://github.com/fortra/impacket) | Реализация сетевых протоколов |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Дизайн модулей постэксплуатации |

### Алгоритмы

| Алгоритм | Назначение | Ссылка |
|----------|------------|--------|
| UCB1 | Баланс исследования-эксплуатации в MCTS | Auer et al., 2002 |
| BFS | Поиск путей в графе знаний | - |
| Token Bucket | Ограничение скорости | - |
| Sliding Window | Ограничение скорости | - |

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Coff0xc/AutoRedTeam-Orchestrator&type=Date)](https://star-history.com/#Coff0xc/AutoRedTeam-Orchestrator&Date)

---

## Лицензия

Этот проект лицензирован под **лицензией MIT** — подробности см. в файле [LICENSE](LICENSE).

```
MIT License

Copyright (c) 2026 Coff0xc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Отказ от ответственности

> **ПРЕДУПРЕЖДЕНИЕ**: Этот инструмент предназначен исключительно для **авторизованного тестирования безопасности и исследований**.
>
> Перед использованием данного инструмента для тестирования любой системы убедитесь, что вы:
> - Получили **письменное разрешение** от владельца системы
> - Соблюдаете местные **законы и нормативные акты**
> - Придерживаетесь **профессиональных этических** стандартов
>
> Несанкционированное использование может нарушать закон. **Разработчики не несут ответственности за любое злоупотребление**.
>
> Данный инструмент содержит возможности атак Red Team (латеральное перемещение, C2-коммуникация, персистентность и т.д.), предназначенные исключительно для:
> - Авторизованного тестирования на проникновение
> - Исследований и обучения в области безопасности
> - CTF-соревнований
> - Валидации оборонительных возможностей
>
> **Запрещено использование в любых незаконных целях.**

---

<p align="center">
  <img src="https://img.shields.io/badge/Built%20with-Python%20%26%20%E2%9D%A4-blue?style=for-the-badge" alt="Built with Python">
</p>

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>

<p align="center">
  <sub>Если этот проект оказался вам полезен, пожалуйста, поставьте ему Star!</sub>
</p>
