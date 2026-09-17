# AutoRedTeam-Orchestrator

**Local-first, MCP-native рабочая среда автоматизации безопасности для авторизованного тестирования и анализа AI/MCP-поверхности атаки.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
![Status](https://img.shields.io/badge/status-Beta%20%2F%20Research%20Preview-yellow)

[中文](README.md) · [English](README_EN.md) · **Русский**

[Зрелость возможностей](docs/capability-maturity.md) · [Модель безопасности](docs/security-model.md) · [Аудиты безопасности](docs/security-audits/)

> **Beta / Research Preview** — приоритет отдаётся статическому анализу, dry-run и локальным стендам. Exploit, боковое перемещение, закрепление, C2, эксфильтрация и другие высокорисковые возможности являются ограниченными экспериментальными функциями; метаданные policy и sandbox не эквивалентны изоляции на уровне ОС или контейнера.

## Содержание

- [Обзор](#обзор)
- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Подключение MCP-сервера](#подключение-mcp-сервера)
- [Python SDK](#python-sdk)
- [Справочник CLI](#справочник-cli)
- [Конфигурация и авторизация](#конфигурация-и-авторизация)
- [Self-audit AI/MCP](#self-audit-aimcp)
- [Подход к проектированию](#подход-к-проектированию)
- [Безопасность и границы](#безопасность-и-границы)
- [Лицензия и отказ от ответственности](#лицензия-и-отказ-от-ответственности)

## Обзор

AutoRedTeam-Orchestrator предоставляет компонуемые возможности безопасности в едином репозитории, доступные через три точки входа: **MCP-сервер**, **Python SDK** и **Typer CLI**. Основное направление — **AI-ассистированная автоматизация безопасности**: AI-редакторы и агенты используют контролируемые возможности через MCP, а поверхность атаки самих AI/MCP-систем проходит статический аудит.

Подходит для авторизованных стендов, разработки автоматизации безопасности, анализа безопасности AI/MCP, CTF и обучения. Это **не** готовая корпоративная платформа, не автономный атакующий агент и не промышленный C2.

## Возможности

| Область | Статус | Границы |
|---|---|---|
| Разведка и обнаружение уязвимостей (JSON/SARIF) | Beta | Только авторизованные цели; публичного бенчмарка точности пока нет |
| Статический self-audit AI/MCP-поверхности | Preview | Только чтение AST → SARIF; охватывает FastMCP и low-level SDK |
| CVE-разведка и PoC | Preview | Синхронизация NVD, выполнение, совместимое с Nuclei |
| Отчёты (JSON/SARIF/HTML) | Beta | Экранирование HTML в процессе усиления |
| Оркестрация / эксплуатация / пост-эксплуатация / C2 / боковое перемещение / закрепление | Restricted Experimental | Только одноразовые изолированные стенды |

Полные определения см. в разделе [Зрелость возможностей](docs/capability-maturity.md).

## Быстрый старт

Установка одной командой (ставит команды `autort` и `autoredteam-mcp`):

```bash
pip install autoredteam-orchestrator                # PyPI
pipx install autoredteam-orchestrator               # изолированное окружение
uvx --from autoredteam-orchestrator autort --help    # запуск без установки
```

Не ждёте релиза в PyPI — установите напрямую из Git:

```bash
pip install "git+https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git"
uvx --from git+https://github.com/Coff0xc/AutoRedTeam-Orchestrator autort --help
```

Запуск из исходников (разработка):

```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator
pip install -r requirements.txt
python -m cli.main --help
```

Команды для начала — только чтение, без сети:

```bash
python -m cli.main ai-surface scan --path handlers --format sarif -o surface.sarif
python -m cli.main capabilities manifest --profile safe
```

## Подключение MCP-сервера

MCP-сервер предоставляет возможности безопасности в виде MCP-инструментов, чтобы AI-редактор или агент мог ими управлять. Он работает local-first: без облака, без телеметрии, только доверенный локальный stdio.

### Запуск сервера

Два равнозначных способа:

```bash
autoredteam-mcp --stdio                # установленная команда (из PyPI / Git)
python -m mcp_stdio_server --stdio     # запуск из исходников
```

Флаг `--stdio` выбирает транспорт stdio — именно его понимают MCP-клиенты (Claude Code, Cursor, Windsurf, Kiro и др.).

### Подключение к AI-редактору

Claude Code, Cursor и другие MCP-клиенты читают JSON-конфигурацию с ключом `mcpServers`. Минимальный `.mcp.json` для этого проекта:

```json
{
  "mcpServers": {
    "autoredteam": {
      "command": "autoredteam-mcp",
      "args": ["--stdio"],
      "env": {
        "AUTORT_CAPABILITY_PROFILE": "safe",
        "AUTOREDTEAM_AUTH_MODE": "strict",
        "AUTOREDTEAM_API_KEY": "replace-with-a-real-key"
      }
    }
  }
}
```

`AUTORT_CAPABILITY_PROFILE` выбирает, какие инструменты регистрируются (см. [Профили возможностей](#профили-возможностей)). Если опустить, используется fail-closed значение `safe` по умолчанию.

### Выбор профиля

Профиль определяется в таком порядке: явный аргумент → переменная окружения `AUTORT_CAPABILITY_PROFILE` → значение `safe` по умолчанию. Любой инструмент, чей `minimum_profile` выше выбранного профиля, **не регистрируется**, а любая неклассифицированная поверхность завершает регистрацию с ошибкой (`CapabilityManifestError`).

### Переменные окружения

| Переменная | Значения | По умолчанию | Смысл |
|---|---|---|---|
| `AUTORT_CAPABILITY_PROFILE` | `safe` \| `scan` \| `active-lab` \| `full` | `safe` | Уровень возможностей, регистрируемый как MCP-инструменты |
| `AUTOREDTEAM_AUTH_MODE` | `strict` \| `permissive` \| `disabled` | `strict` | Шлюз авторизации для защищённых инструментов |
| `AUTOREDTEAM_API_KEY` | произвольная строка | *(не задан)* | API-ключ, проверяемый в режиме `strict`; `MCP_API_KEY` — эквивалентный псевдоним |

## Python SDK

SDK — тонкая асинхронная обёртка над движками `core/`, импортируется из исходников:

```python
from autort import Scanner, Exploiter, AutoPentest, RedTeam, Reporter
from autort import __version__        # версия из единого источника, напр. "3.1.0"
```

Все вызовы асинхронны и возвращают `dict` (несколько методов сканирования — списки). Успех отмечается `"success": True`; ошибки несут реальную строку `"error"`, а не проглатываются.

### Scanner — разведка и обнаружение

```python
from autort import Scanner

scanner = Scanner("http://127.0.0.1:8000")

ports = await scanner.port_scan(ports="1-1000")          # или top=100
recon = await scanner.full_recon()                        # полная 10-этапная разведка
vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
nuclei = await scanner.nuclei_scan(tags=["cve"], severity=["high", "critical"])
```

Ключевые методы: `full_recon()`, `port_scan(ports="1-1000", top=None)`, `detect_vulns(categories=None, config=None)`, `fingerprint()`, `waf_detect()`, `subdomain_enum(domain=None)`, `passive_recon(domain=None)`, `nuclei_scan(tags=None, severity=None, template_dir=None, concurrency=10, limit=None)`.

### Exploiter — эксплуатация и CVE-разведка

```python
from autort import Exploiter

exploiter = Exploiter("http://127.0.0.1:8000")

cves = await exploiter.cve_search("Apache Log4j", severity="critical", has_poc=True)
```

`cve_search(keyword, severity=None, has_poc=None, limit=20)` — только разведка, работает в профиле `safe`. `cve_exploit(cve)`, `auto_exploit(top_n=5)` и `exploit(vuln, **kwargs)` требуют профиль `active-lab` (и выше), авторизованный одноразовый стенд, изолированный исполнитель и API-ключ.

### AutoPentest — однократная оркестрация

```python
from autort import AutoPentest

pentest = AutoPentest("http://127.0.0.1:8000", config={"timeout": 3600})
result = await pentest.run(phases=["recon", "vuln_scan"])   # без phases — полный цикл
```

`run(phases=None)` запускает конвейер `RECON → VULN_SCAN → POC_EXEC → EXPLOIT → PRIV_ESC → LATERAL → EXFIL → REPORT`. `resume(session_id)` продолжает прерванную сессию; `status(session_id)` читает живое состояние. Это возможность профиля `full`, работает только на изолированных авторизованных стендах.

### RedTeam — пост-эксплуатация (ограничено)

`RedTeam(config=None)` объединяет боковое перемещение, C2, закрепление, повышение привилегий и поиск учётных данных: `lateral_move(target, method="ssh", ...)`, `c2_start(host, port=443, protocol="https")`, `persist(target="", method="crontab", ...)`, `privesc(target, ...)`, `credential_find(...)`. Каждый метод возвращает `{"success": bool, ...}`. Это поверхности профиля `full`, требующие одобрения и изолированного исполнителя; здесь они приведены только как каталог, без примеров вызова.

### Reporter — отчётность

```python
from autort import Reporter

reporter = Reporter("session_id_here")
html_path = await reporter.generate(format="html")     # html | json | markdown | executive
findings = await reporter.export_findings(format="json")
```

## Справочник CLI

Typer CLI — основной вход для локального анализа, он же установленная команда `autort`; в исходниках — `python -m cli.main`.

### Команды верхнего уровня

| Команда | Назначение | Пример (только авторизованные цели) |
|---|---|---|
| `scan` | Сканирование портов / полная разведка | `autort scan http://127.0.0.1:8000 --full` |
| `detect` | Обнаружение уязвимостей | `autort detect http://127.0.0.1:8000 -c sqli,xss,ssrf --format sarif` |
| `exploit` | CVE / автоподбор эксплойта | `autort exploit http://127.0.0.1:8000 --cve CVE-2021-44228` |
| `cve-search` | CVE-разведка | `autort cve-search "Log4j" --severity critical --has-poc -n 20` |
| `pentest` | Однократная оркестрация | `autort pentest http://127.0.0.1:8000 --phases recon,vuln_scan` |
| `report` | Генерация отчёта | `autort report <session-id> -f html` |
| `nuclei` | Чисто-Python Nuclei-сканирование | `autort nuclei http://127.0.0.1:8000 -t cve,rce -s high,critical` |
| `tools` | Статус внешних инструментов | `autort tools` |
| `version` | Показать версию | `autort version` |

CI-флаги у `detect` (и у `ai-*`-сканеров): `--ci` выводит краткую сводку и возвращает ненулевой код выхода, когда находки достигают `--severity-threshold` (info/low/medium/high/critical).

### Группы подкоманд

| Группа | Команды | Назначение |
|---|---|---|
| `ai-redteam` | `run`, `catalog`, `convert`, `eval-run` | Декларативные AI red-team сценарии (dry-run по умолчанию) |
| `ai-surface` | `scan`, `scan-mcp-config`, `scan-skills` | Статическая инвентаризация AI/MCP-поверхности (только чтение) |
| `code-agent` | `expand` | Раскрытие call-chain контекста (без выполнения кода) |
| `runtime-api` | `serve` | Локальный runtime API только на чтение (`/api/runs`) |
| `sandbox` | `docker-smoke` | Локальная проверка Docker-песочницы |
| `capabilities` | `matrix`, `readiness`, `manifest`, `profiles` | Манифест возможностей и покрытие |
| `tools` | `lint` | Проверка контракта MCP-инструментов (статическая) |

Команды для начала — только чтение, без сети:

```bash
autort ai-surface scan --path handlers --format sarif -o surface.sarif
autort ai-surface scan-mcp-config --path .mcp.json
autort ai-surface scan-skills --path ./skills
autort capabilities profiles
autort capabilities manifest --profile safe
autort tools lint --path handlers
```

## Конфигурация и авторизация

### Профили возможностей

Профили — упорядоченные уровни доступа; каждый наследует предыдущий:

| Профиль | Включает | Рабочая граница |
|---|---|---|
| `safe` | Локальный анализ, dry-run, метаданные, контролируемое локальное состояние | Доверенный локальный процесс; без сетевого доступа к цели и выполнения команд хоста |
| `scan` | `safe` + авторизованная разведка и сканирование уязвимостей | Требуются явная область цели и внешний сетевой контроль |
| `active-lab` | `scan` + проверка эксплойтов и офенсивное планирование | Требуются одноразовый стенд, независимое одобрение, изолированный исполнитель |
| `full` | все поверхности, включая пост-эксплуатацию и ограниченные исследования | Только явный opt-in для изолированных, авторизованных, одноразовых сред |

Посмотреть актуальные определения:

```bash
autort capabilities profiles              # упорядоченные профили, наследование, число поверхностей
autort capabilities manifest -p scan      # полный манифест, отфильтрованный по профилю
```

### Режимы авторизации

Авторизация применяется к каждому инструменту через декораторы. Три режима, выбираемые `AUTOREDTEAM_AUTH_MODE`:

| Режим | Поведение |
|---|---|
| `strict` (по умолчанию) | Защищённые инструменты требуют действующий API-ключ (`AUTOREDTEAM_API_KEY` или `MCP_API_KEY`) |
| `permissive` | Пишет предупреждение, но разрешает доступ |
| `disabled` | Без проверки — действует только при `AUTOREDTEAM_ENV=test` или заданном `PYTEST_CURRENT_TEST` |

### Манифест возможностей

Манифест (`core/capability_manifest.py`) — машиночитаемый единый источник истины для каждой публичной MCP-поверхности. Каждая запись объявляет `kind`, `name`, `handler`, `category`, `minimum_profile`, `risk`, `maturity` и обязательные контроли — `auth_required`, `approval_required` и `executor` (`in-process` / `external-process` / `isolated-required`). Регистрация любой неклассифицированной поверхности завершается с ошибкой (fail-closed).

Поля `required_controls` — **декларативные**: они ограничивают только экспозицию MCP-схемы, а не принудительное исполнение. Они не заменяют аутентификацию, область цели, независимое одобрение или изолированный исполнитель.

## Self-audit AI/MCP

Выполните чисто статический аудит **вашего собственного репозитория**: инвентаризация поверхности атаки инструментов MCP-сервера и AI-агента, результаты передаются с точностью `file:line` в GitHub Code Scanning. Без цели, сети, секретов и авторизации.

Запуск как GitHub Action на каждом PR (полный пример в [`self-audit.example.yml`](.github/workflows/self-audit.example.yml)):

```yaml
- uses: Coff0xc/AutoRedTeam-Orchestrator@v3.1
  with:
    mode: self-audit
    path: '.'
    severity-threshold: high
```

Или локально:

```bash
python -m cli.main ai-surface scan --path . --format sarif        # поверхность инструментов MCP handler
python -m cli.main ai-surface scan-mcp-config --path .mcp.json    # опасные команды и секреты в открытом виде
python -m cli.main ai-surface scan-skills --path ./skills         # маркеры высокорисковых инструкций
```

Добавьте `--auth-mode lenient`, чтобы убрать специфичные для проекта находки авторизации при аудите внешних репозиториев.

## Подход к проектированию

- **Один набор движков, три точки входа.** Логика разведки, обнаружения, эксплуатации, оркестрации, CVE, AI red-team и AI-поверхности находится в `core/`; MCP-сервер, SDK (`autort/`) и CLI (`cli/main.py`) — тонкие адаптеры над одними и теми же движками. Возможность реализуется один раз, а не трижды.
- **Fail-closed MCP-экспозиция.** Каждая регистрируемая поверхность должна быть классифицирована в манифесте. Неклассифицированная или превышающая профиль поверхность не публикуется молча — регистрация завершается ошибкой. По умолчанию — самый узкий профиль (`safe`), а не самый широкий.
- **Декларативная экспозиция и принудительная авторизация — разные слои.** Профили фильтруют, *какие* инструменты существуют для клиента; авторизация решает, *может ли* защищённый инструмент выполниться. Они намеренно независимы, чтобы изменение профиля не могло случайно расширить круг тех, кто может действовать.
- **Local-first, dry-run по умолчанию.** Сервер работает только через stdio и доверяет локальному процессу. Высокорисковые возможности по умолчанию dry-run и выходят из него только в изолированном одноразовом стенде при явном opt-in.
- **Self-audit — первоклассная функция.** В том же репозитории есть сканер только на чтение для MCP handler, MCP-конфигураций клиентов и файлов skill/prompt, поэтому саму AI/MCP-поверхность можно проверить без цели и сети.

## Безопасность и границы

- Профили возможностей MCP (`safe`/`scan`/`active-lab`/`full`) фильтруют инструменты при регистрации, но не заменяют аутентификацию, область целей, независимое одобрение или изолированный исполнитель.
- Высокорисковые возможности по умолчанию работают в режиме dry-run и должны включаться только в одноразовых изолированных средах.
- Аутентификация подключается через отдельные декораторы инструментов и пока не является единой границей для всей зарегистрированной поверхности.

См. [Модель безопасности](docs/security-model.md) и [Зрелость возможностей](docs/capability-maturity.md).

## Лицензия и отказ от ответственности

Лицензия MIT — см. [`LICENSE`](LICENSE).

Только для явно авторизованного тестирования безопасности, внутренней проверки, обучения и локальных стендов. Пользователи обязаны соблюдать применимое законодательство и получить письменную авторизацию от владельца цели. Несанкционированное сканирование, эксплуатация, закрепление, эксфильтрация или обход средств защиты запрещены.
