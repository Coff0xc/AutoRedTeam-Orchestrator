<p align="center">
  <img src="https://raw.githubusercontent.com/Coff0xc/AutoRedTeam-Orchestrator/main/assets/banner.png" alt="AutoRedTeam-Orchestrator" width="800">
</p>

<h1 align="center">AutoRedTeam-Orchestrator</h1>

<p align="center">
  <b>Фреймворк автоматизированной оркестрации Red Team на основе ИИ</b><br>
  <sub>Кроссплатформенность | 100+ MCP инструментов | 2000+ Payload | Полное покрытие ATT&CK</sub>
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
  <img src="https://img.shields.io/badge/Инструменты-100+-FF6B6B?style=flat-square" alt="Инструменты">
  <img src="https://img.shields.io/badge/Лицензия-MIT-green?style=flat-square" alt="Лицензия">
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB"><img src="https://img.shields.io/badge/Discord-Сообщество-5865F2?style=flat-square&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/wiki"><img src="https://img.shields.io/badge/Wiki-Документация-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Wiki"></a>
</p>

---

## Содержание

- [Обзор проекта](#обзор-проекта)
- [Основные функции](#основные-функции)
- [Матрица покрытия ATT&CK](#матрица-покрытия-attck)
- [Быстрый старт](#быстрый-старт)
  - [Системные требования](#системные-требования)
  - [Способы установки](#способы-установки)
  - [Проверка установки](#проверка-установки)
- [Конфигурация MCP](#конфигурация-mcp)
- [Матрица инструментов](#матрица-инструментов-100-mcp-инструментов)
- [Интеграция внешних инструментов](#интеграция-внешних-инструментов)
- [Примеры использования](#примеры-использования)
  - [Использование командной строки](#использование-командной-строки)
  - [Вызовы Python API](#вызовы-python-api)
- [Архитектура](#архитектура)
- [Конфигурация](#конфигурация)
- [Оптимизация производительности](#оптимизация-производительности)
- [Устранение неполадок](#устранение-неполадок)
- [FAQ](#faq)
- [История изменений](#история-изменений)
- [Дорожная карта](#дорожная-карта)
- [Руководство по внесению вклада](#руководство-по-внесению-вклада)
- [Политика безопасности](#политика-безопасности)
- [Благодарности](#благодарности)
- [Лицензия](#лицензия)
- [Отказ от ответственности](#отказ-от-ответственности)

---

## Обзор проекта

**AutoRedTeam-Orchestrator** — это фреймворк автоматизированного тестирования на проникновение на основе ИИ, построенный на [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Он инкапсулирует 100+ инструментов безопасности как MCP-инструменты, обеспечивая бесшовную интеграцию с MCP-совместимыми ИИ-редакторами (Cursor, Windsurf, Kiro, Claude Desktop) для автоматизированного тестирования безопасности на естественном языке.

### Почему AutoRedTeam-Orchestrator?

| Характеристика | Традиционные инструменты | AutoRedTeam |
|----------------|-------------------------|-------------|
| **Взаимодействие** | Запоминание команд CLI | Диалог на естественном языке |
| **Кривая обучения** | Высокая (много параметров) | Низкая (ИИ выбирает инструменты) |
| **Интеграция инструментов** | Ручное переключение | 100+ инструментов объединено |
| **Планирование атак** | Ручное планирование | Рекомендации ИИ |
| **Создание отчетов** | Ручное написание | Профессиональные отчеты в один клик |
| **Управление сессиями** | Отсутствует | Поддержка контрольных точек/возобновления |

---

## Основные функции

<table>
<tr>
<td width="50%">

**ИИ-нативный дизайн**
- **Интеллектуальная идентификация** - Автоматическое определение технологического стека цели (CMS/фреймворки/WAF)
- **Планирование цепочки атак** - Рекомендации путей атаки на основе ИИ
- **Обучение на исторической обратной связи** - Непрерывная оптимизация стратегии на основе результатов
- **Автоматический выбор полезной нагрузки** - Интеллектуальная мутация с учетом WAF
- **Генерация PoC с помощью ИИ** - Автоматическая генерация кода эксплойта на основе описаний CVE

</td>
<td width="50%">

**Полная автоматизация процесса**
- **10-этапный конвейер разведки** - DNS/Порты/Отпечатки/WAF/Поддомены/Директории/JS-анализ
- **Обнаружение и верификация уязвимостей** - Автоматическое сканирование + OOB-верификация для снижения ложных срабатываний
- **Интеллектуальная оркестрация эксплойтов** - Движок обратной связи + автоматический повтор при ошибках
- **Профессиональные отчеты в один клик** - Многоформатный вывод JSON/HTML/Markdown
- **Контрольные точки/возобновление сессий** - Поддержка восстановления прерванных сканирований

</td>
</tr>
<tr>
<td width="50%">

**Инструментарий Red Team**
- **Латеральное перемещение** - SMB/SSH/WMI/WinRM/PSExec 5 протоколов
- **C2 коммуникация** - Beacon + DNS/HTTP/WebSocket/ICMP туннели
- **Обфускация/Уклонение** - XOR/AES/Base64/Пользовательские кодировщики
- **Персистентность** - Реестр Windows/Планировщик задач/WMI/Linux cron/Webshell
- **Доступ к учетным данным** - Извлечение из памяти/Поиск файлов/Распыление паролей
- **Атаки на AD** - Kerberoasting/AS-REP Roasting/SPN сканирование

</td>
<td width="50%">

**Расширение возможностей безопасности**
- **Безопасность API** - Тесты JWT/CORS/GraphQL/WebSocket/OAuth
- **Безопасность цепочки поставок** - Генерация SBOM/Аудит зависимостей/Сканирование CI-CD
- **Облачная безопасность** - K8s RBAC/Безопасность Pod/gRPC/Аудит конфигурации AWS
- **CVE разведка** - Многоисточниковая синхронизация NVD/Nuclei/ExploitDB
- **Обход WAF** - 2000+ полезных нагрузок + 30+ методов кодирования для интеллектуальной мутации

</td>
</tr>
</table>

---

## Матрица покрытия ATT&CK

| Тактическая фаза | Покрытие техник | Кол-во инструментов | Статус |
|------------------|-----------------|---------------------|--------|
| Разведка (Reconnaissance) | Активное сканирование, Пассивный сбор, OSINT, JS-анализ | 12+ | ✅ |
| Разработка ресурсов (Resource Development) | Генерация полезных нагрузок, Кодирование обфускации, Генерация PoC | 4+ | ✅ |
| Начальный доступ (Initial Access) | Эксплуатация Web-уязвимостей, Эксплуатация CVE, API-уязвимости | 19+ | ✅ |
| Выполнение (Execution) | Инъекция команд, Выполнение кода, Десериализация | 5+ | ✅ |
| Персистентность (Persistence) | Реестр, Планировщик задач, Webshell, WMI | 3+ | ✅ |
| Повышение привилегий (Privilege Escalation) | Обход UAC, Имперсонация токенов, Эксплойты ядра | 2+ | ⚠️ |
| Уклонение от защиты (Defense Evasion) | Обход AMSI, Обход ETW, Обфускация, Мутация трафика | 4+ | ✅ |
| Доступ к учетным данным (Credential Access) | Извлечение из памяти, Поиск файлов, Распыление паролей | 2+ | ✅ |
| Обнаружение (Discovery) | Сканирование сети, Перечисление служб, Перечисление AD | 8+ | ✅ |
| Латеральное перемещение (Lateral Movement) | SMB/SSH/WMI/WinRM/PSExec | 9+ | ✅ |
| Сбор (Collection) | Агрегация данных, Поиск конфиденциальных файлов | 2+ | ✅ |
| Командование и управление (C2) | HTTP/DNS/WebSocket/ICMP туннели | 4+ | ✅ |
| Эксфильтрация (Exfiltration) | DNS/HTTP/ICMP/SMB + AES шифрование | 4+ | ✅ |

---

## Быстрый старт

### Системные требования

| Компонент | Минимальные требования | Рекомендуемые |
|-----------|----------------------|---------------|
| ОС | Windows 10, Ubuntu 20.04, macOS 12 | Windows 11, Ubuntu 22.04, macOS 14 |
| Python | 3.10 | 3.11 или 3.12 |
| Память | 4GB | 8GB+ |
| Дисковое пространство | 500MB | 2GB+ (включая базу CVE) |
| Сеть | Доступ в интернет | Низкая задержка |

### Способы установки

#### Способ 1: Стандартная установка (рекомендуется)

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

# 4. Скопировать шаблон переменных окружения
cp .env.example .env
# Отредактировать .env и ввести API ключи

# 5. Запустить сервис
python mcp_stdio_server.py
```

#### Способ 2: Минимальная установка (только основные функции)

```bash
# Установить только основные зависимости (разведка + обнаружение уязвимостей)
pip install -r requirements-core.txt
```

#### Способ 3: Развертывание Docker

```bash
docker pull coff0xc/autoredteam:latest
docker run -it --rm \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  coff0xc/autoredteam
```

#### Способ 4: Среда разработки

```bash
# Установить зависимости для разработки (тесты, форматирование, линтинг)
pip install -r requirements-dev.txt

# Установить pre-commit хуки
pre-commit install
```

### Проверка установки

```bash
# Проверить версию
python mcp_stdio_server.py --version
# Вывод: AutoRedTeam-Orchestrator v3.0.1

# Запустить самопроверку
python -c "from core import __version__; print(f'Core version: {__version__}')"

# Запустить тесты (среда разработки)
pytest tests/ -v --tb=short
```

---

## Конфигурация MCP

Добавьте следующую конфигурацию в файл конфигурации MCP вашего ИИ-редактора:

### Пути к файлам конфигурации

| Редактор | Путь к файлу конфигурации |
|----------|--------------------------|
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

## Матрица инструментов (100+ MCP инструментов)

| Категория | Кол-во | Ключевые инструменты | Описание |
|-----------|--------|---------------------|----------|
| **Разведка** | 8 | `port_scan` `subdomain_enum` `fingerprint` `waf_detect` `js_analyze` `dir_scan` `dns_lookup` `tech_detect` | Сбор информации и обнаружение активов |
| **Обнаружение уязвимостей** | 11 | `sqli_scan` `xss_scan` `ssrf_scan` `rce_scan` `ssti_scan` `xxe_scan` `idor_scan` `path_traversal_scan` `cors_scan` `security_headers_scan` | OWASP Top 10 + логические уязвимости |
| **Безопасность API** | 7 | `jwt_scan` `graphql_scan` `websocket_scan` `oauth_scan` `cors_deep_scan` `security_headers_score` | Современное тестирование безопасности API |
| **Цепочка поставок** | 3 | `sbom_generate` `dependency_audit` `cicd_scan` | SBOM/Зависимости/CI-CD безопасность |
| **Облачные технологии** | 3 | `k8s_scan` `grpc_scan` `aws_scan` | K8s/gRPC/AWS аудит безопасности |
| **Ядро Red Team** | 14 | `lateral_smb` `c2_beacon_start` `credential_find` `privilege_escalate` `payload_obfuscate` | Пост-эксплуатация и внутренняя сеть |
| **Латеральное перемещение** | 9 | `lateral_ssh` `lateral_wmi` `lateral_winrm` `lateral_psexec` `lateral_ssh_tunnel` | 5 протоколов латерального перемещения |
| **Персистентность** | 3 | `persistence_windows` `persistence_linux` `persistence_webshell` | Windows/Linux/Web |
| **Атаки на AD** | 3 | `ad_enumerate` `ad_kerberos_attack` `ad_spn_scan` | Полный набор для проникновения в домен |
| **CVE** | 8 | `cve_search` `cve_sync` `cve_stats` `poc_execute` `poc_list` `cve_auto_exploit` `cve_exploit_with_desc` `cve_generate_poc` | CVE разведка + ИИ PoC |
| **Оркестрация** | 11 | `auto_pentest` `pentest_resume` `pentest_status` `pentest_phase` `smart_analyze` `attack_chain_plan` | Автоматизированное проникновение |
| **Внешние инструменты** | 8 | `ext_nmap_scan` `ext_nuclei_scan` `ext_sqlmap_scan` `ext_ffuf_fuzz` `ext_masscan_scan` `ext_tool_chain` `ext_tools_status` | Интеграция профессиональных инструментов |
| **ИИ-помощь** | 3 | `smart_payload` `ai_attack_chain` `smart_pentest` | Интеллектуальный анализ и принятие решений |
| **Сессия/Отчеты** | 9 | `session_create` `session_status` `session_list` `session_complete` `generate_report` `export_findings` | Управление сессиями + отчеты |

---

## Интеграция внешних инструментов

Поддержка интеграции локально установленных профессиональных инструментов безопасности для расширенных возможностей обнаружения:

| Инструмент | Назначение | MCP команда | Требования к установке |
|------------|------------|-------------|----------------------|
| **Nmap** | Сканирование портов + обнаружение служб + NSE скрипты | `ext_nmap_scan` | Системный PATH или настроенный путь |
| **Nuclei** | 7000+ шаблонов сканирования CVE/уязвимостей | `ext_nuclei_scan` | Go компиляция или бинарная загрузка |
| **SQLMap** | 6 техник SQL-инъекций + обход WAF | `ext_sqlmap_scan` | Python скрипт |
| **ffuf** | Высокоскоростной фаззинг директорий/параметров | `ext_ffuf_fuzz` | Go компиляция или бинарная загрузка |
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
    default_args:
      quick: ["-silent", "-severity", "critical,high"]
      cve: ["-silent", "-tags", "cve"]

  sqlmap:
    enabled: true
    path: "${base_path}/sqlmap/sqlmap.py"
    python_script: true
    default_args:
      detect: ["--batch", "--level=2", "--risk=1"]
      exploit: ["--batch", "--level=5", "--risk=3", "--dump"]

  ffuf:
    enabled: true
    path: "${base_path}/ffuf/ffuf"
    default_args:
      dir: ["-t", "50", "-fc", "404"]

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
# Полная цепочка разведки: masscan быстрое обнаружение → nmap детальная идентификация
ext_tool_chain target="192.168.1.0/24" chain_name="full_recon"

# Цепочка сканирования уязвимостей: nuclei + sqlmap комбинированное обнаружение
ext_tool_chain target="https://example.com" chain_name="vuln_scan"

# Проверить статус внешних инструментов
ext_tools_status
```

---

## Примеры использования

### Использование командной строки

Прямые разговорные вызовы в ИИ-редакторе:

#### Разведка и сбор информации

```
# Полная разведка
"Выполни полную разведку example.com и сгенерируй отчет"

# Сканирование портов
"Просканируй сегмент сети 192.168.1.0/24 на открытые порты"

# Перечисление поддоменов
"Перечисли все поддомены example.com"

# Идентификация отпечатков
"Определи технологический стек и WAF целевого сайта"

# JS-анализ
"Проанализируй JavaScript файлы целевого сайта на предмет конфиденциальной информации"
```

#### Сканирование уязвимостей

```
# SQL-инъекция
"Проверь есть ли SQL-инъекция на https://target.com/api?id=1"

# XSS сканирование
"Просканируй целевую форму на XSS уязвимости и сгенерируй PoC"

# Безопасность API
"Выполни полное тестирование безопасности JWT/CORS/GraphQL на целевом API"

# Поиск и эксплуатация CVE
"Найди CVE связанные с Apache Log4j и выполни PoC"
```

#### Операции Red Team

```
# Латеральное перемещение
"Выполни команду whoami на 192.168.1.100 через SMB"

# C2 коммуникация
"Запусти DNS туннель к c2.example.com"

# Персистентность
"Установи персистентность через планировщик задач на Windows цели"

# Атаки на AD
"Выполни атаку Kerberoasting на контроллер домена"
```

#### Автоматизированное проникновение

```
# Полностью автоматизированный тест на проникновение
"Выполни полностью автоматизированный тест на проникновение на https://target.com, сгенерируй детальный отчет"

# Интеллектуальная цепочка атак
"Проанализируй цель и сгенерируй оптимальную рекомендацию цепочки атак"

# Контрольная точка/Возобновление
"Возобнови ранее прерванную сессию теста на проникновение"
```

### Вызовы Python API

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

#### Латеральное перемещение

```python
from core.lateral import SMBLateralMove, SSHLateralMove

# SMB латеральное перемещение
smb = SMBLateralMove(
    target="192.168.1.100",
    credential={"username": "admin", "password_hash": "aad3b435..."}
)
result = await smb.execute_command("whoami")

# SSH туннель
ssh = SSHLateralMove(
    target="192.168.1.100",
    credential={"username": "root", "private_key_path": "/путь/к/ключу"}
)
await ssh.create_tunnel(local_port=8080, remote_port=80)
```

#### Автоматическая эксплуатация CVE

```python
from core.cve import CVEAutoExploit

exploit = CVEAutoExploit()

# Поиск и эксплуатация
results = await exploit.search_and_exploit(
    cve_id="CVE-2021-44228",
    target="https://target.com"
)

# Генерация PoC с помощью ИИ
poc_code = await exploit.generate_poc(
    cve_id="CVE-2024-12345",
    target_info={"os": "linux", "service": "nginx"}
)
```

#### Управление сессиями

```python
from core.session import SessionManager

manager = SessionManager()

# Создать сессию
session_id = await manager.create_session(
    target="https://target.com",
    scan_type="full_pentest"
)

# Возобновить сессию
await manager.resume_session(session_id)

# Экспортировать результаты
await manager.export_findings(session_id, format="html")
```

---

## Архитектура

```
AutoRedTeam-Orchestrator/
├── mcp_stdio_server.py       # Точка входа MCP сервера (100+ инструментов)
│
├── handlers/                 # Обработчики MCP инструментов (16 модулей)
│   ├── recon_handlers.py           # Инструменты разведки (8)
│   ├── detector_handlers.py        # Инструменты обнаружения уязвимостей (11)
│   ├── api_security_handlers.py    # Инструменты безопасности API (7)
│   ├── supply_chain_handlers.py    # Инструменты безопасности цепочки поставок (3)
│   ├── cloud_security_handlers.py  # Инструменты облачной безопасности (3)
│   ├── cve_handlers.py             # CVE инструменты (8)
│   ├── redteam_handlers.py         # Основные инструменты Red Team (14)
│   ├── lateral_handlers.py         # Инструменты латерального перемещения (9)
│   ├── persistence_handlers.py     # Инструменты персистентности (3)
│   ├── ad_handlers.py              # Инструменты атак на AD (3)
│   ├── orchestration_handlers.py   # Инструменты оркестрации (11)
│   ├── external_tools_handlers.py  # Внешние инструменты (8)
│   ├── ai_handlers.py              # Инструменты ИИ-помощи (3)
│   ├── session_handlers.py         # Инструменты сессий (4)
│   ├── report_handlers.py          # Инструменты отчетов (2)
│   └── misc_handlers.py            # Разные инструменты (3)
│
├── core/                     # Основные движки
│   ├── recon/               # Движок разведки (10-этапный конвейер)
│   ├── detectors/           # Детекторы уязвимостей
│   ├── cve/                 # CVE разведка
│   ├── c2/                  # C2 коммуникационный фреймворк
│   ├── lateral/             # Латеральное перемещение
│   ├── evasion/             # Уклонение и обфускация
│   ├── persistence/         # Персистентность
│   ├── credential/          # Доступ к учетным данным
│   ├── ad/                  # Атаки на AD
│   ├── session/             # Управление сессиями
│   ├── tools/               # Управление внешними инструментами
│   └── security/            # Компоненты безопасности
│
├── modules/                  # Функциональные модули
│   ├── api_security/        # Безопасность API
│   ├── supply_chain/        # Безопасность цепочки поставок
│   ├── cloud_security/      # Облачная безопасность
│   └── payload/             # Движок полезных нагрузок
│
├── utils/                    # Вспомогательные функции
├── wordlists/                # Встроенные словари
├── config/                   # Файлы конфигурации
└── tests/                    # Набор тестов (1075 тестовых случаев)
```

---

## Конфигурация

### Переменные окружения (.env)

```bash
# ========== Конфигурация безопасности ==========
REDTEAM_MASTER_KEY=
AUTOREDTEAM_API_KEY=
AUTOREDTEAM_AUTH_MODE=permissive

# ========== API ключи ==========
OPENAI_API_KEY=ваш_ключ
ANTHROPIC_API_KEY=ваш_ключ
SHODAN_API_KEY=ваш_ключ
CENSYS_API_ID=ваш_id
CENSYS_API_SECRET=ваш_secret
NVD_API_KEY=ваш_ключ
GITHUB_TOKEN=ваш_токен

# ========== Настройки прокси ==========
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# ========== Глобальная конфигурация ==========
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
  max_threads: 100          # Максимальное количество потоков
  max_async_tasks: 200      # Максимум асинхронных задач
  connection_pool_size: 50  # Размер пула соединений

rate_limiting:
  requests_per_second: 50   # Запросов в секунду
  burst_size: 100           # Burst запросы

timeouts:
  connect: 5                # Таймаут соединения (секунды)
  read: 30                  # Таймаут чтения
  total: 120                # Общий таймаут
```

### Оптимизация памяти

```python
# Использовать потоковую обработку для крупных сканирований
engine = StandardReconEngine(
    target="192.168.0.0/16",
    config=ReconConfig(
        streaming_mode=True,    # Включить потоковую обработку
        batch_size=1000,        # Размер пакета
        memory_limit="2GB"      # Лимит памяти
    )
)
```

---

## Устранение неполадок

### Распространенные проблемы

| Проблема | Причина | Решение |
|----------|--------|---------|
| MCP сервер не подключается | Ошибка пути или проблема окружения Python | Проверить абсолютный путь в конфигурации, убедиться в правильном интерпретаторе Python |
| Ошибка импорта | PYTHONPATH не установлен | Добавить переменную окружения `PYTHONPATH` в конфигурацию |
| Сбой вызова внешнего инструмента | Инструмент не установлен или ошибка пути | Выполнить `ext_tools_status` для проверки статуса инструмента |
| Сбой синхронизации базы CVE | Проблема сети или ограничение API | Проверить сеть, настроить NVD_API_KEY для повышения лимитов |
| Медленная скорость сканирования | Низкая конфигурация параллелизма | Настроить `MAX_THREADS` и `RATE_LIMIT_DELAY` |
| Переполнение памяти | Крупное сканирование | Включить `streaming_mode`, установить `memory_limit` |

### Режим отладки

```bash
# Включить детальное логирование
LOG_LEVEL=DEBUG python mcp_stdio_server.py

# Проверить синтаксические ошибки
python -m py_compile mcp_stdio_server.py

# Запустить один тест
pytest tests/test_recon.py::test_port_scan -v
```

---

## FAQ

<details>
<summary><b>В: Как использовать в оффлайн среде?</b></summary>

О:
1. Предварительно скачать базу CVE: `python core/cve/update_manager.py sync --offline-export`
2. Использовать локальные файлы словарей
3. Отключить функции, требующие сети: `OFFLINE_MODE=true`

</details>

<details>
<summary><b>В: Как добавить пользовательский детектор?</b></summary>

О:
1. Создать новый файл в `core/detectors/`
2. Наследовать от класса `BaseDetector`
3. Реализовать методы `detect()` и `async_detect()`
4. Зарегистрировать MCP инструмент в `handlers/detector_handlers.py`

</details>

<details>
<summary><b>В: Как интегрировать другие внешние инструменты?</b></summary>

О:
1. Добавить конфигурацию инструмента в `config/external_tools.yaml`
2. Добавить функцию MCP инструмента в `handlers/external_tools_handlers.py`
3. Использовать метод `execute_tool()` из `core/tools/tool_manager.py`

</details>

<details>
<summary><b>В: Как справиться с блокировкой WAF?</b></summary>

О:
1. Использовать инструмент `smart_payload` для автоматического выбора payload с обходом WAF
2. Настроить пул прокси: `PROXY_POOL=true`
3. Включить мутацию трафика: `traffic_mutation=true`
4. Снизить скорость сканирования: `RATE_LIMIT_DELAY=1.0`

</details>

<details>
<summary><b>В: Какие форматы отчетов поддерживаются?</b></summary>

О:
- JSON (машиночитаемый)
- HTML (визуализированный отчет с графиками)
- Markdown (подходит для Git/Wiki)
- PDF (требуется установка `reportlab`)
- DOCX (требуется установка `python-docx`)

</details>

---

## История изменений

### v3.0.1 (2026-01-30) - Укрепление качества

**Новое**
- Улучшение автоматической эксплуатации CVE (`cve_auto_exploit`, `cve_exploit_with_desc`, `cve_generate_poc`)
- Генератор PoC с ИИ (`core/cve/ai_poc_generator.py`)

**Исправлено**
- Унификация номера версии - Полная синхронизация VERSION/pyproject.toml/исходного кода
- Исправление ToolCounter - Добавлены новые категории external_tools/lateral/persistence/ad
- Исправления тестов - Обновлены устаревшие ссылки на тесты
- Потокобезопасность - Добавлен threading.Lock для управления состоянием beacon.py

**Улучшено**
- Укрепление CI/CD - Ошибки проверки lint теперь блокируют сборку
- Порог покрытия тестами повышен до 50%
- Ограничения версий зависимостей - Добавлены верхние границы для предотвращения проблем совместимости

### v3.0.0 (2026-01-18) - Расширение архитектуры

**Новое**
- Интеграция внешних инструментов - 8 MCP команд внешних инструментов
- Оркестрация цепочки инструментов - YAML-управляемая комбинация инструментов
- Модуляризация обработчиков - 16 независимых модулей обработчиков

**Улучшено**
- Количество MCP инструментов достигло 100+
- Движок обратной связи - Интеллектуальный оркестратор эксплуатации
- Обход WAF - Улучшенный движок мутации payload

---

## Дорожная карта

### В работе
- [ ] Web UI интерфейс управления
- [ ] Распределенный кластер сканирования

### Запланировано
- [ ] Больше облачных платформ (GCP/Alibaba Cloud/Tencent Cloud)
- [ ] Интеграция плагина Burp Suite
- [ ] Тестирование безопасности мобильных приложений
- [ ] ИИ-автономный агент атак

### Завершено
- [x] Полный инструментарий Red Team
- [x] CVE разведка и генерация PoC с ИИ
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

# 2. Создать ветку
git checkout -b feature/ваша-функция

# 3. Установить зависимости для разработки
pip install -r requirements-dev.txt
pre-commit install

# 4. Разработка и тестирование
pytest tests/ -v

# 5. Отправить PR
git push origin feature/ваша-функция
```

### Соглашение о коммитах

Используйте формат [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` Новая функция
- `fix:` Исправление ошибки
- `docs:` Обновление документации
- `refactor:` Рефакторинг
- `test:` Связано с тестами
- `chore:` Сборка/Инструменты

См. [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Политика безопасности

- **Ответственное раскрытие**: При обнаружении уязвимостей безопасности свяжитесь с нами по адресу [Coff0xc@protonmail.com](mailto:Coff0xc@protonmail.com)
- **Авторизованное использование**: Этот инструмент предназначен только для авторизованного тестирования безопасности и исследований
- **Заявление о соответствии**: Убедитесь, что вы соблюдаете местные законы и правила

См. [SECURITY.md](SECURITY.md)

---

## Благодарности

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Дизайн движка сканирования уязвимостей
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Подход к обнаружению SQL-инъекций
- [Impacket](https://github.com/fortra/impacket) - Реализация сетевых протоколов
- [MCP Protocol](https://modelcontextprotocol.io/) - Стандарт протокола ИИ-инструментов

---

## Лицензия

Этот проект лицензирован под **лицензией MIT** - см. файл [LICENSE](LICENSE)

---

## Отказ от ответственности

> **Предупреждение**: Этот инструмент предназначен только для **авторизованного тестирования безопасности и исследований**.
>
> Перед использованием этого инструмента для тестирования любой системы убедитесь, что:
> - Вы получили **письменное разрешение** от владельца системы
> - Вы соблюдаете местные **законы и правила**
> - Вы соответствуете **профессиональным этическим** стандартам
>
> Несанкционированное использование этого инструмента может нарушать закон. **Разработчики не несут ответственности за злоупотребления**.

---

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Coff0xc">Coff0xc</a></b>
</p>

<p align="center">
  <a href="https://discord.gg/PtVyrMvB">Discord</a> ·
  <a href="mailto:Coff0xc@protonmail.com">Email</a> ·
  <a href="https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues">Issues</a>
</p>
