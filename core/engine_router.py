"""
引擎路由器 — 统一接口，自动选择最强可用后端

逻辑:
    外部工具可用 → 优先用外部工具 (性能最强)
    外部工具不可用 → 自动退回纯 Python 引擎 (零依赖兜底)

用户不需要关心底层用的什么，调用接口完全一致。

使用:
    from core.engine_router import get_scanner, get_sqli_engine, get_dir_scanner
    scanner = get_scanner()       # 自动选 nmap 或纯 Python
    sqli = get_sqli_engine()      # 自动选 sqlmap 或纯 Python
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 内置工具目录
_TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"


def _find_tool(name: str) -> Optional[Path]:
    """查找工具: 内置 bin → 系统 PATH → None"""
    # 1. tools/bin/
    bin_dir = _TOOLS_DIR / "bin"
    for ext in ("", ".exe"):
        p = bin_dir / f"{name}{ext}"
        if p.exists():
            return p
    # 2. 系统 PATH
    system = shutil.which(name)
    if system:
        return Path(system)
    return None


class EngineRouter:
    """引擎路由器 — 每个能力域一个方法，返回最强可用后端"""

    # ── 端口扫描 ──

    @staticmethod
    def get_port_scanner(**kwargs):
        """获取端口扫描器

        优先: nmap → 纯 Python PortScanner
        """
        nmap_path = _find_tool("nmap")
        if nmap_path:
            logger.info("端口扫描: 使用 nmap (%s)", nmap_path)
            from core.recon.port_scanner import PortScanner

            scanner = PortScanner(**kwargs)
            scanner._nmap_path = str(nmap_path)  # 标记有 nmap
            return scanner
        else:
            logger.info("端口扫描: 使用纯 Python 引擎 (并发 500)")
            from core.recon.port_scanner import PortScanner

            return PortScanner(**kwargs)

    # ── SQLi 利用 ──

    @staticmethod
    def get_sqli_engine(**kwargs):
        """获取 SQL 注入引擎

        优先: 内置 sqlmap (submodule) → 纯 Python PureSQLi
        """
        sqlmap_path = _TOOLS_DIR / "sqlmap" / "sqlmap.py"
        if sqlmap_path.exists():
            logger.info("SQLi 引擎: 使用内置 sqlmap (%s)", sqlmap_path)
            return _SqlmapWrapper(sqlmap_path, **kwargs)
        else:
            logger.info("SQLi 引擎: 使用纯 Python 引擎")
            from core.exploit.pure_sqli import SQLInjector

            return SQLInjector(**kwargs)

    # ── 漏洞扫描 (Nuclei) ──

    @staticmethod
    def get_nuclei_engine(**kwargs):
        """获取 Nuclei 引擎

        优先: nuclei 二进制 + 内置模板 → 纯 Python Nuclei 引擎 + 内置模板
        """
        nuclei_path = _find_tool("nuclei")
        templates_dir = _TOOLS_DIR / "nuclei-templates"
        if not templates_dir.exists():
            templates_dir = None

        if nuclei_path:
            logger.info("Nuclei: 使用原生二进制 (%s), 模板: %s", nuclei_path, templates_dir)
            return _NucleiWrapper(nuclei_path, templates_dir, **kwargs)
        else:
            logger.info("Nuclei: 使用纯 Python 引擎, 模板: %s", templates_dir)
            from core.detectors.nuclei_engine import NucleiEngine

            td = str(templates_dir) if templates_dir else None
            return NucleiEngine(template_dir=td, **kwargs)

    # ── 目录扫描 ──

    @staticmethod
    def get_dir_scanner(**kwargs):
        """获取目录扫描器

        优先: ffuf → 纯 Python DirectoryScanner
        """
        ffuf_path = _find_tool("ffuf")
        if ffuf_path:
            logger.info("目录扫描: 使用 ffuf (%s)", ffuf_path)
            return _FfufWrapper(ffuf_path, **kwargs)
        else:
            logger.info("目录扫描: 使用纯 Python 引擎")
            from core.recon.directory import DirectoryScanner

            return DirectoryScanner(**kwargs)

    # ── 子域名枚举 ──

    @staticmethod
    def get_subdomain_enumerator(**kwargs):
        """获取子域名枚举器

        始终使用内置引擎 (被动侦察 6 源 + DNS 暴破)
        """
        from core.recon.subdomain import SubdomainEnumerator

        return SubdomainEnumerator(passive=True, **kwargs)

    # ── 服务指纹 ──

    @staticmethod
    def get_service_prober(**kwargs):
        """获取服务探针

        始终使用内置引擎 (15+ 协议签名)
        """
        from core.recon.service_probe import ServiceProber

        return ServiceProber(**kwargs)

    # ── 状态总览 ──

    @staticmethod
    def status() -> dict:
        """返回所有引擎的可用状态"""
        from tools.downloader import get_all_tool_status

        tool_status = get_all_tool_status()

        return {
            "port_scanner": "nmap" if _find_tool("nmap") else "python",
            "sqli_engine": "sqlmap" if (_TOOLS_DIR / "sqlmap" / "sqlmap.py").exists() else "python",
            "nuclei": "native" if _find_tool("nuclei") else "python",
            "dir_scanner": "ffuf" if _find_tool("ffuf") else "python",
            "subdomain": "python+passive(6 sources)",
            "service_probe": "python(15+ protocols)",
            "tools": tool_status,
        }


# ── 外部工具 Wrapper ──


class _SqlmapWrapper:
    """sqlmap 封装 — 通过 subprocess 调用内置 sqlmap"""

    def __init__(self, sqlmap_path: Path, **kwargs):
        self.sqlmap_path = sqlmap_path
        self.kwargs = kwargs

    async def scan(self, target: str, **kwargs) -> dict:
        import asyncio
        import subprocess
        import sys

        args = [
            sys.executable,
            str(self.sqlmap_path),
            "-u",
            target,
            "--batch",
            "--output-dir=/tmp/sqlmap-out",
            "--forms",
            "--level=3",
            "--risk=2",
        ]
        # 额外参数
        if kwargs.get("tamper"):
            args.extend(["--tamper", kwargs["tamper"]])
        if kwargs.get("threads"):
            args.extend(["--threads", str(kwargs["threads"])])

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                args,
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 300),
            )
            return {
                "success": proc.returncode == 0,
                "tool": "sqlmap",
                "stdout": proc.stdout[-5000:] if proc.stdout else "",
                "stderr": proc.stderr[-2000:] if proc.stderr else "",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "sqlmap 执行超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class _NucleiWrapper:
    """nuclei 二进制封装"""

    def __init__(self, nuclei_path: Path, templates_dir: Optional[Path] = None, **kwargs):
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir

    async def scan(self, target: str, **kwargs) -> dict:
        import asyncio
        import subprocess

        args = [str(self.nuclei_path), "-u", target, "-jsonl", "-silent"]
        if self.templates_dir:
            args.extend(["-t", str(self.templates_dir)])
        if kwargs.get("tags"):
            args.extend(["-tags", ",".join(kwargs["tags"])])
        if kwargs.get("severity"):
            args.extend(["-severity", ",".join(kwargs["severity"])])

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                args,
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 600),
            )
            import json

            findings = []
            for line in (proc.stdout or "").strip().split("\n"):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return {"success": True, "tool": "nuclei-native", "findings": findings}
        except Exception as e:
            return {"success": False, "error": str(e)}


class _FfufWrapper:
    """ffuf 封装"""

    def __init__(self, ffuf_path: Path, **kwargs):
        self.ffuf_path = ffuf_path

    async def scan(self, target: str, wordlist: str = None, **kwargs) -> dict:
        import asyncio
        import subprocess

        if not wordlist:
            # 使用内置小字典
            wordlist = str(Path(__file__).parent / "data" / "wordlists" / "common.txt")
            if not Path(wordlist).exists():
                wordlist = "/usr/share/wordlists/dirb/common.txt"

        url = target.rstrip("/") + "/FUZZ"
        args = [
            str(self.ffuf_path),
            "-u",
            url,
            "-w",
            wordlist,
            "-o",
            "/tmp/ffuf-out.json",
            "-of",
            "json",
            "-mc",
            "200,301,302,403",
            "-t",
            str(kwargs.get("threads", 50)),
        ]

        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                args,
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 300),
            )
            import json

            try:
                with open("/tmp/ffuf-out.json") as f:
                    data = json.load(f)
                return {"success": True, "tool": "ffuf", "results": data.get("results", [])}
            except Exception:
                return {"success": True, "tool": "ffuf", "stdout": proc.stdout[-5000:]}
        except Exception as e:
            return {"success": False, "error": str(e)}


# ── 便捷函数 ──

_router = EngineRouter()

get_port_scanner = _router.get_port_scanner
get_sqli_engine = _router.get_sqli_engine
get_nuclei_engine = _router.get_nuclei_engine
get_dir_scanner = _router.get_dir_scanner
get_subdomain_enumerator = _router.get_subdomain_enumerator
get_service_prober = _router.get_service_prober
engine_status = _router.status
