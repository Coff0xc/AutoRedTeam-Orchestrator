# AutoRedTeam-Orchestrator

**Local-first, MCP-native рабочая среда автоматизации безопасности для авторизованного тестирования и анализа AI/MCP-поверхности атаки.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-3.1.0-orange)
![Status](https://img.shields.io/badge/status-Beta%20%2F%20Research%20Preview-yellow)

[中文](README.md) · [English](README_EN.md) · **Русский**

[Зрелость возможностей](docs/capability-maturity.md) · [Модель безопасности](docs/security-model.md) · [Аудиты безопасности](docs/security-audits/)

> **Beta / Research Preview** — приоритет отдаётся статическому анализу, dry-run и локальным стендам. Exploit, боковое перемещение, закрепление, C2, эксфильтрация и другие высокорисковые возможности являются ограниченными экспериментальными функциями; метаданные policy и sandbox не эквивалентны изоляции на уровне ОС или контейнера.

## Обзор

AutoRedTeam-Orchestrator предоставляет компонуемые возможности безопасности в едином репозитории, доступные через три точки входа: MCP-сервер, Python SDK и Typer CLI. Основное направление — **AI-ассистированная автоматизация безопасности**: AI-редакторы и агенты используют контролируемые возможности через MCP, а поверхность атаки самих AI/MCP-систем проходит статический аудит.

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

## Точки входа

| Точка входа | Путь | Позиционирование |
|---|---|---|
| MCP-сервер | `mcp_stdio_server.py` | По умолчанию fail-closed профиль `safe`; только доверенный локальный stdio |
| Python SDK | `autort/` | Из исходного checkout |
| Typer CLI | `cli/main.py` | Основная точка для локального анализа и разработки |

Авторизованные сканирования создают сетевой трафик — используйте их только против localhost, одноразового стенда или цели с письменной авторизацией:

```bash
python -m cli.main scan http://127.0.0.1:8000 --full
python -m cli.main detect http://127.0.0.1:8000 -c sqli,xss,ssrf
```

## Безопасность и границы

- Профили возможностей MCP (`safe`/`scan`/`active-lab`/`full`) фильтруют инструменты при регистрации, но не заменяют аутентификацию, область целей, независимое одобрение или изолированный исполнитель.
- Высокорисковые возможности по умолчанию работают в режиме dry-run и должны включаться только в одноразовых изолированных средах.
- Аутентификация подключается через отдельные декораторы инструментов и пока не является единой границей для всей зарегистрированной поверхности.

См. [Модель безопасности](docs/security-model.md) и [Зрелость возможностей](docs/capability-maturity.md).

## Лицензия и отказ от ответственности

Лицензия MIT — см. [`LICENSE`](LICENSE).

Только для явно авторизованного тестирования безопасности, внутренней проверки, обучения и локальных стендов. Пользователи обязаны соблюдать применимое законодательство и получить письменную авторизацию от владельца цели. Несанкционированное сканирование, эксплуатация, закрепление, эксфильтрация или обход средств защиты запрещены.
