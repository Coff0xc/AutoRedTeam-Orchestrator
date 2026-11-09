# AutoRedTeam-Orchestrator

**Локальный аудит поверхности атаки MCP/AI и контроль доказательств.** Профиль регистрации по умолчанию — `safe`: статический анализ, dry-run и локальные метаданные. Модули постэксплуатации, которые принадлежат только более широкому профилю, в этом профиле не импортируются.

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
- [Self-audit AI/MCP](#self-audit-aimcp)
- [Подключение MCP-сервера](#подключение-mcp-сервера)
- [Python SDK](#python-sdk)
- [Справочник CLI](#справочник-cli)
- [Конфигурация и авторизация](#конфигурация-и-авторизация)
- [Подход к проектированию](#подход-к-проектированию)
- [Безопасность и границы](#безопасность-и-границы)
- [Лицензия и отказ от ответственности](#лицензия-и-отказ-от-ответственности)

## Обзор

Продукт по умолчанию — локальный аудит поверхности атаки MCP/AI и контроль доказательств. Он доступен через **MCP-сервер**, **Python SDK** и **Typer CLI**. Модель принимает решения, процесс удерживает профиль, доказательства и запись аудита.

Код разведки, обнаружения и постэксплуатации остаётся в дереве исходников и регистрируется только при явном выборе `scan`, `active-lab` или `full`. Профиль `safe` не импортирует модули, которые существуют только для этих профилей. Публикуемый пакет не содержит эти экспериментальные движки. Описания, которые видит модель, содержат профиль, риск, эффекты и ограничения. Подходит для авторизованных стендов, анализа безопасности AI/MCP и обучения. Это не готовая корпоративная платформа, не автономный атакующий агент и не промышленный C2.

## Возможности

| Область | Статус | Границы |
|---|---|---|
| Статический self-audit AI/MCP-поверхности | Preview | Только чтение AST → SARIF; охватывает FastMCP и low-level SDK. Профиль по умолчанию — `safe` |
| CVE-разведка | Preview | Локальный поиск доступен в `safe`. Синхронизация и выполнение PoC требуют более широкий профиль |
| Отчёты (JSON/SARIF/HTML) | Beta | Экспорт findings доступен в `safe`. `generate_report` требует `scan` |
| Разведка и обнаружение уязвимостей (JSON/SARIF) | Beta | Минимальный профиль `scan`; только авторизованные цели; публичного бенчмарка точности пока нет |
| Оркестрация / эксплуатация / пост-эксплуатация / C2 / боковое перемещение / закрепление | Restricted Experimental | `active-lab` или `full`; только одноразовые изолированные стенды |

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

Старт по умолчанию — локальный аудит только на чтение и без сети. Эти команды не обращаются к цели и не импортируют экспериментальные движки. При запуске из исходников минимальная зависимость — `typer`:

```bash
pip install typer
python -m cli.main ai-surface scan --path handlers --format sarif -o surface.sarif
python -m cli.main ai-surface scan-mcp-config --path .mcp.json
python -m cli.main capabilities manifest --profile safe
```

`ai-surface scan` по умолчанию пропускает тестовые файлы. Сканирование корня репозитория или `handlers/` сверяется с capability manifest. Покрытие попадает в JSON `summary.static_coverage` и в SARIF `runs[].properties.static_coverage`.

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

SDK — тонкая асинхронная обёртка над движками `core/`, импортируется из исходников. В профиле по умолчанию начните с экспорта findings и поиска CVE:

```python
from autort import Exploiter, Reporter
from autort import __version__        # версия из единого источника, напр. "3.1.0"
```

Все вызовы асинхронны и возвращают `dict` (несколько методов сканирования — списки). Успех отмечается `"success": True`; ошибки несут реальную строку `"error"`, а не проглатываются. Если профиль слишком узкий, вызов отклоняется до импорта соответствующего движка.

### Доступно в профиле по умолчанию

```python
from autort import Exploiter, Reporter

exploiter = Exploiter("http://127.0.0.1:8000")
cves = await exploiter.cve_search("Apache Log4j", severity="critical", has_poc=True)

reporter = Reporter("session_id_here")
findings = await reporter.export_findings(format="json")
```

`cve_search(keyword, severity=None, has_poc=None, limit=20)` и `export_findings(format="json")` работают в `safe`. `AutoPentest.status(session_id)` читает локальную сессию, соответствует `session_status` и тоже доступен в `safe`.

### Явный профиль

Методы разведки и обнаружения у `Scanner` требуют минимум профиль `scan`. Профиль `safe` по умолчанию отклоняет их до импорта движка разведки или обнаружения.

```python
from autort import Scanner

scanner = Scanner("http://127.0.0.1:8000")

ports = await scanner.port_scan(ports="1-1000")          # или top=100
recon = await scanner.full_recon()                        # полная 10-этапная разведка
vulns = await scanner.detect_vulns(categories=["sqli", "xss", "ssrf"])
nuclei = await scanner.nuclei_scan(tags=["cve"], severity=["high", "critical"])
```

Ключевые методы: `full_recon()`, `port_scan(ports="1-1000", top=None)`, `detect_vulns(categories=None, config=None)`, `fingerprint()`, `waf_detect()`, `subdomain_enum(domain=None)`, `passive_recon(domain=None)`, `nuclei_scan(tags=None, severity=None, template_dir=None, concurrency=10, limit=None)`. Чтобы продолжить, задайте `AUTORT_CAPABILITY_PROFILE=scan` или выше.

`Exploiter.cve_exploit(cve)`, `auto_exploit(top_n=5)` и `exploit(vuln, **kwargs)` требуют профиль `active-lab` или выше, авторизованный одноразовый стенд, изолированный исполнитель и API-ключ. `Reporter.generate(format="html")` соответствует `generate_report` и требует `scan`.

`AutoPentest.run(phases=None)` и `resume(session_id)` соответствуют `auto_pentest` и `pentest_resume`. Оба требуют профиль `full` и работают только на изолированных авторизованных стендах. Без `phases` запускается полный цикл.

`RedTeam(config=None)` объединяет боковое перемещение, C2, закрепление, повышение привилегий и поиск учётных данных. Это поверхности профиля `full`, требующие одобрения и изолированного исполнителя; здесь они перечислены только как каталог, без примеров вызова.

## Справочник CLI

Typer CLI — вход для локального анализа, установленная команда `autort`; в исходниках — `python -m cli.main`. Сначала команды, которые работают в профиле `safe` по умолчанию, затем команды, которым нужен более широкий профиль.

### Путь по умолчанию (`safe`)

Эти команды не обращаются к цели. `cve-search` читает локальную CVE-разведку.

| Команда | Назначение | Пример |
|---|---|---|
| `ai-surface scan` | Статическая инвентаризация MCP handler | `autort ai-surface scan --path handlers --format sarif -o surface.sarif` |
| `ai-surface scan-mcp-config` | Проверка конфигурации MCP-клиента | `autort ai-surface scan-mcp-config --path .mcp.json` |
| `ai-surface scan-skills` | Маркеры высокорисковых инструкций в skill/prompt | `autort ai-surface scan-skills --path ./skills` |
| `capabilities profiles` | Наследование профилей и число поверхностей | `autort capabilities profiles` |
| `capabilities manifest` | Экспорт манифеста выбранного профиля | `autort capabilities manifest --profile safe` |
| `tools lint` | Статическая проверка контракта MCP-инструментов | `autort tools lint --path handlers` |
| `cve-search` | CVE-разведка | `autort cve-search "Log4j" --severity critical --has-poc -n 20` |
| `version` | Показать версию | `autort version` |

CI-флаги у `ai-surface`: `--ci` выводит краткую сводку и возвращает ненулевой код выхода, когда находки достигают `--severity-threshold` (info/low/medium/high/critical). `detect` не на этом пути: ему нужен профиль `scan`.

### Группы подкоманд

| Группа | Команды | Минимальный профиль | Назначение |
|---|---|---|---|
| `ai-surface` | `scan`, `scan-mcp-config`, `scan-skills` | `safe` | Статическая инвентаризация AI/MCP-поверхности (только чтение) |
| `capabilities` | `matrix`, `readiness`, `manifest`, `profiles` | `safe` | Манифест возможностей и покрытие |
| `tools` | `lint` | `safe` | Проверка контракта MCP-инструментов (статическая) |
| `code-agent` | `expand` | `safe` | Раскрытие call-chain контекста (без выполнения кода) |
| `runtime-api` | `serve` | `safe` | Локальный runtime API только на чтение (`/api/runs`) |
| `sandbox` | `docker-smoke` | `safe` | Локальная проверка Docker-песочницы |
| `ai-redteam` | `run`, `catalog`, `convert`, `eval-run` | `safe` | Декларативные AI red-team сценарии (dry-run по умолчанию) |

`autort tools` — это группа `lint` выше. Статус внешних инструментов — поверхность `ext_tools_status` с минимальным профилем `scan`. Отдельной достижимой CLI-команды у неё нет.

### Явный профиль

Профиль `safe` по умолчанию отклоняет эти команды. Профиль берётся из явного аргумента, затем из `AUTORT_CAPABILITY_PROFILE`, иначе остаётся `safe`.

| Команда | Минимальный профиль | Назначение | Пример (только авторизованные цели) |
|---|---|---|---|
| `scan` | `scan` | Сканирование портов / полная разведка | `autort scan http://127.0.0.1:8000 --full` |
| `detect` | `scan` | Обнаружение уязвимостей | `autort detect http://127.0.0.1:8000 -c sqli,xss,ssrf --format sarif` |
| `nuclei` | `scan` | Чисто-Python Nuclei-сканирование | `autort nuclei http://127.0.0.1:8000 -t cve,rce -s high,critical` |
| `report` | `scan` | Генерация отчёта | `autort report <session-id> -f html` |
| `exploit` | `active-lab` | CVE / автоподбор эксплойта | `autort exploit http://127.0.0.1:8000 --cve CVE-2021-44228` |
| `pentest` | `full` | Однократная оркестрация | `autort pentest http://127.0.0.1:8000 --phases recon,vuln_scan` |

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

## Подход к проектированию

- **Один набор движков, три точки входа.** Аудит AI-поверхности, CVE-разведка, разведка, обнаружение и экспериментальная оркестрация находятся в `core/`; MCP-сервер, SDK (`autort/`) и CLI (`cli/main.py`) — тонкие адаптеры над одними и теми же движками. Возможность реализуется один раз, а не трижды.
- **Fail-closed MCP-экспозиция.** Каждая регистрируемая поверхность должна быть классифицирована в манифесте. Неклассифицированная или превышающая профиль поверхность не публикуется молча — регистрация завершается ошибкой. По умолчанию — самый узкий профиль (`safe`), а не самый широкий.
- **Декларативная экспозиция и принудительная авторизация — разные слои.** Профили фильтруют, *какие* инструменты существуют для клиента; авторизация решает, *может ли* защищённый инструмент выполниться. Они намеренно независимы, чтобы изменение профиля не могло случайно расширить круг тех, кто может действовать.
- **Local-first, dry-run по умолчанию.** Сервер работает только через stdio и доверяет локальному процессу. Высокорисковые возможности по умолчанию dry-run и выходят из него только в изолированном одноразовом стенде при явном opt-in.
- **Self-audit — первоклассная функция.** В том же репозитории есть сканер только на чтение для MCP handler, MCP-конфигураций клиентов и файлов skill/prompt, поэтому саму AI/MCP-поверхность можно проверить без цели и сети.

## Безопасность и границы

- Одни и те же профили (`safe`/`scan`/`active-lab`/`full`) ограничивают регистрацию MCP и вызовы CLI и SDK, которые соответствуют поверхности манифеста. Они не заменяют аутентификацию, область целей, независимое одобрение или изолированный исполнитель. Прямые импорты `core` вне этих точек входа не проходят через эту проверку.
- Высокорисковые возможности по умолчанию работают в режиме dry-run и должны включаться только в одноразовых изолированных средах.
- Аутентификация подключается через отдельные декораторы инструментов и пока не является единой границей для всей зарегистрированной поверхности.

См. [Модель безопасности](docs/security-model.md) и [Зрелость возможностей](docs/capability-maturity.md).

## Лицензия и отказ от ответственности

Лицензия MIT — см. [`LICENSE`](LICENSE).

Только для явно авторизованного тестирования безопасности, внутренней проверки, обучения и локальных стендов. Пользователи обязаны соблюдать применимое законодательство и получить письменную авторизацию от владельца цели. Несанкционированное сканирование, эксплуатация, закрепление, эксфильтрация или обход средств защиты запрещены.
