"""
工具自动下载器 — 首次调用时自动获取二进制工具

支持的工具:
- nmap: 端口扫描 (从 GitHub releases 下载)
- nuclei: 漏洞扫描 (从 projectdiscovery releases 下载)
- ffuf: 目录/模糊测试 (从 GitHub releases 下载)
- masscan: 快速端口扫描 (从 GitHub releases 下载)

使用:
    from tools.downloader import ensure_tool, ensure_all_tools
    nmap_path = await ensure_tool("nmap")  # 自动下载并返回路径
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# 工具存放目录
TOOLS_BIN_DIR = Path(__file__).resolve().parent / "bin"
TOOLS_BIN_DIR.mkdir(parents=True, exist_ok=True)

# 当前平台
_SYSTEM = platform.system().lower()  # linux, windows, darwin
_ARCH = platform.machine().lower()  # x86_64, amd64, arm64, aarch64
_IS_WINDOWS = _SYSTEM == "windows"

# 标准化架构名
if _ARCH in ("x86_64", "amd64", "x64"):
    _ARCH_NORM = "amd64"
elif _ARCH in ("aarch64", "arm64"):
    _ARCH_NORM = "arm64"
else:
    _ARCH_NORM = _ARCH


def _ext() -> str:
    return ".exe" if _IS_WINDOWS else ""


# ── 工具下载配置 ──

TOOL_CONFIGS: Dict[str, Dict] = {
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        "asset_pattern": f"nuclei_*_{_SYSTEM}_{_ARCH_NORM}.zip",
        "binary_name": f"nuclei{_ext()}",
        "version": "latest",
    },
    "ffuf": {
        "repo": "ffuf/ffuf",
        "asset_pattern": f"ffuf_*_{_SYSTEM}_{_ARCH_NORM}.{'zip' if _IS_WINDOWS else 'tar.gz'}",
        "binary_name": f"ffuf{_ext()}",
        "version": "latest",
    },
    "masscan": {
        "repo": "robertdavidgraham/masscan",
        "binary_name": f"masscan{_ext()}",
        "version": "latest",
        # masscan 没有标准 release，仅 Linux 可编译; Windows 需手动
        "manual_note": "masscan 需要手动安装: https://github.com/robertdavidgraham/masscan",
    },
    "nmap": {
        # nmap 没有 GitHub release 二进制，需要系统安装
        "binary_name": f"nmap{_ext()}",
        "system_install": True,
        "install_hints": {
            "linux": "sudo apt install nmap  # 或 yum install nmap",
            "darwin": "brew install nmap",
            "windows": "从 https://nmap.org/download.html 下载安装",
        },
    },
}


def get_tool_path(tool_name: str) -> Optional[Path]:
    """获取工具路径 (已安装/已下载 → 路径, 否则 None)"""
    config = TOOL_CONFIGS.get(tool_name)
    if not config:
        return None

    binary = config["binary_name"]

    # 1. 检查内置 bin 目录
    local_path = TOOLS_BIN_DIR / binary
    if local_path.exists():
        return local_path

    # 2. 检查系统 PATH
    system_path = shutil.which(binary.replace(_ext(), "") if _IS_WINDOWS else binary)
    if system_path:
        return Path(system_path)

    # 3. 检查 sqlmap (特殊: 纯 Python, 在 tools/sqlmap/)
    if tool_name == "sqlmap":
        sqlmap_py = Path(__file__).resolve().parent / "sqlmap" / "sqlmap.py"
        if sqlmap_py.exists():
            return sqlmap_py

    return None


def is_tool_available(tool_name: str) -> bool:
    """检查工具是否可用"""
    return get_tool_path(tool_name) is not None


async def ensure_tool(tool_name: str) -> Optional[Path]:
    """确保工具可用 — 不可用时自动下载

    Returns:
        工具路径, 或 None (无法获取)
    """
    # 已有则直接返回
    path = get_tool_path(tool_name)
    if path:
        return path

    config = TOOL_CONFIGS.get(tool_name)
    if not config:
        logger.warning("未知工具: %s", tool_name)
        return None

    # 需要系统安装的工具 (如 nmap)
    if config.get("system_install"):
        hint = config.get("install_hints", {}).get(_SYSTEM, "请手动安装")
        logger.warning("工具 %s 未安装。安装方法: %s", tool_name, hint)
        return None

    # 有手动说明的工具 (如 masscan)
    if config.get("manual_note"):
        logger.warning("%s: %s", tool_name, config["manual_note"])
        return None

    # 从 GitHub releases 下载
    return await _download_from_github(tool_name, config)


async def _download_from_github(tool_name: str, config: dict) -> Optional[Path]:
    """从 GitHub releases 下载工具"""
    repo = config["repo"]
    binary = config["binary_name"]
    target_path = TOOLS_BIN_DIR / binary

    logger.info("正在下载 %s...", tool_name)

    try:
        from core.http.client import get_client

        client = get_client()

        # 获取最新 release
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        resp = await asyncio.to_thread(client.get, api_url)
        if not resp or resp.status_code != 200:
            logger.error("获取 %s release 信息失败", tool_name)
            return None

        import json

        release = json.loads(resp.text)
        assets = release.get("assets", [])

        # 查找匹配的 asset
        asset_pattern = config.get("asset_pattern", "")
        download_url = None
        for asset in assets:
            name = asset.get("name", "").lower()
            # 简单模式匹配
            pattern_parts = asset_pattern.lower().replace("*", "").split("_")
            if all(part in name for part in pattern_parts if part):
                download_url = asset.get("browser_download_url")
                break

        if not download_url:
            logger.error("未找到 %s 的 %s/%s 版本", tool_name, _SYSTEM, _ARCH_NORM)
            return None

        # 下载
        logger.info("下载: %s", download_url)
        dl_resp = await asyncio.to_thread(client.get, download_url)
        if not dl_resp or dl_resp.status_code != 200:
            logger.error("下载 %s 失败", tool_name)
            return None

        # 保存并解压
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(download_url).suffix) as tmp:
            tmp.write(dl_resp.content if hasattr(dl_resp, "content") else dl_resp.text.encode())
            tmp_path = Path(tmp.name)

        try:
            _extract_binary(tmp_path, target_path, binary)
        finally:
            tmp_path.unlink(missing_ok=True)

        if target_path.exists():
            # 设置可执行权限
            if not _IS_WINDOWS:
                target_path.chmod(target_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            logger.info("工具 %s 已下载到 %s", tool_name, target_path)
            return target_path

    except Exception as e:
        logger.error("下载 %s 失败: %s", tool_name, e)

    return None


def _extract_binary(archive_path: Path, target_path: Path, binary_name: str) -> None:
    """从压缩包中提取二进制文件"""
    suffix = archive_path.suffix.lower()

    if suffix == ".zip":
        with zipfile.ZipFile(str(archive_path)) as zf:
            for name in zf.namelist():
                if name.endswith(binary_name) or Path(name).name == binary_name:
                    with zf.open(name) as src, open(str(target_path), "wb") as dst:
                        dst.write(src.read())
                    return

    elif suffix == ".gz" and str(archive_path).endswith(".tar.gz"):
        with tarfile.open(str(archive_path), "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith(binary_name) or Path(member.name).name == binary_name:
                    f = tf.extractfile(member)
                    if f:
                        with open(str(target_path), "wb") as dst:
                            dst.write(f.read())
                    return


async def ensure_all_tools() -> Dict[str, Optional[Path]]:
    """确保所有工具可用"""
    results = {}
    for name in TOOL_CONFIGS:
        results[name] = await ensure_tool(name)
    # sqlmap: 纯 Python，直接克隆
    results["sqlmap"] = await ensure_sqlmap()
    # nuclei-templates: YAML 数据
    results["nuclei-templates"] = await ensure_nuclei_templates()
    return results


async def ensure_sqlmap() -> Optional[Path]:
    """确保 sqlmap 可用 — 不存在则自动克隆"""
    sqlmap_dir = Path(__file__).resolve().parent / "sqlmap"
    sqlmap_py = sqlmap_dir / "sqlmap.py"
    if sqlmap_py.exists():
        return sqlmap_py

    logger.info("正在克隆 sqlmap (首次使用，仅此一次)...")
    try:
        import subprocess

        result = await asyncio.to_thread(
            subprocess.run,
            ["git", "clone", "--depth", "1", "https://github.com/sqlmapproject/sqlmap.git", str(sqlmap_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if sqlmap_py.exists():
            logger.info("sqlmap 已就绪: %s", sqlmap_py)
            return sqlmap_py
        else:
            logger.error("sqlmap 克隆失败: %s", result.stderr[:500])
    except Exception as e:
        logger.error("sqlmap 克隆失败: %s", e)
    return None


async def ensure_nuclei_templates() -> Optional[Path]:
    """确保 nuclei-templates 可用 — 不存在则自动克隆"""
    templates_dir = Path(__file__).resolve().parent / "nuclei-templates"
    if templates_dir.exists() and any(templates_dir.glob("**/http/**/*.yaml")):
        return templates_dir

    logger.info("正在克隆 nuclei-templates (首次使用，仅此一次，约 100MB)...")
    try:
        import subprocess

        result = await asyncio.to_thread(
            subprocess.run,
            ["git", "clone", "--depth", "1", "https://github.com/projectdiscovery/nuclei-templates.git", str(templates_dir)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if templates_dir.exists():
            logger.info("nuclei-templates 已就绪: %s", templates_dir)
            return templates_dir
        else:
            logger.error("nuclei-templates 克隆失败: %s", result.stderr[:500])
    except Exception as e:
        logger.error("nuclei-templates 克隆失败: %s", e)
    return None


def get_all_tool_status() -> Dict[str, Dict]:
    """获取所有工具状态"""
    status = {}
    for name, config in TOOL_CONFIGS.items():
        path = get_tool_path(name)
        status[name] = {
            "available": path is not None,
            "path": str(path) if path else None,
            "source": "builtin" if path and str(TOOLS_BIN_DIR) in str(path) else "system" if path else "missing",
        }
    # sqlmap
    sqlmap_path = Path(__file__).resolve().parent / "sqlmap" / "sqlmap.py"
    status["sqlmap"] = {
        "available": sqlmap_path.exists(),
        "path": str(sqlmap_path) if sqlmap_path.exists() else None,
        "source": "submodule" if sqlmap_path.exists() else "missing",
    }
    # nuclei-templates
    templates_dir = Path(__file__).resolve().parent / "nuclei-templates"
    status["nuclei-templates"] = {
        "available": templates_dir.exists() and any(templates_dir.glob("**/*.yaml")),
        "path": str(templates_dir) if templates_dir.exists() else None,
        "source": "submodule",
    }
    return status
