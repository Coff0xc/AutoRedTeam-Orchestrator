#!/usr/bin/env python3
"""
离线密码哈希破解工具集 - John the Ripper / Hashcat 集成
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.registry import BaseTool, ToolCategory, ToolParameter
from shared.subprocess_runner import get_subprocess_runner

logger = logging.getLogger(__name__)

# Hash 格式映射
JOHN_FORMATS = {
    "md5": "raw-md5",
    "sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "sha512": "raw-sha512",
    "ntlm": "nt",
    "lm": "lm",
    "krb5tgs": "krb5tgs",
    "krb5asrep": "krb5asrep",
    "bcrypt": "bcrypt",
    "descrypt": "descrypt",
    "mysql": "mysql-sha1",
    "mssql": "mssql",
}

HASHCAT_MODES = {
    "md5": "0",
    "sha1": "100",
    "sha256": "1400",
    "sha512": "1700",
    "ntlm": "1000",
    "lm": "3000",
    "krb5tgs": "13100",
    "krb5asrep": "18200",
    "bcrypt": "3200",
    "mysql": "300",
    "mssql": "1731",
    "wpa": "22000",
}


@dataclass
class JohnTool(BaseTool):
    """John the Ripper 哈希破解"""

    name: str = "john"
    description: str = "John the Ripper - 离线密码哈希破解工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("hash_file", "string", "哈希文件路径", required=True),
            ToolParameter(
                "format",
                "string",
                "哈希格式",
                required=False,
                default="",
                choices=list(JOHN_FORMATS.keys()),
            ),
            ToolParameter("wordlist", "string", "字典文件路径", required=False, default=""),
            ToolParameter(
                "rules", "string", "规则名称(如single/wordlist/jumbo)", required=False, default=""
            ),
            ToolParameter("incremental", "boolean", "增量模式", required=False, default=False),
            ToolParameter("show", "boolean", "显示已破解结果", required=False, default=False),
        ]
    )
    timeout: int = 7200

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        hash_file = params["hash_file"]
        fmt = params.get("format", "")
        wordlist = params.get("wordlist", "")
        rules = params.get("rules", "")
        incremental = params.get("incremental", False)
        show = params.get("show", False)

        runner = get_subprocess_runner(self.timeout)

        # 显示已破解结果
        if show:
            cmd = ["john", "--show", hash_file]
            if fmt:
                cmd.extend(["--format", JOHN_FORMATS.get(fmt, fmt)])
            result = runner.run(cmd, tool_name="john", install_cmd="apt install john")
            if not result.success:
                return result.to_dict()
            return {
                "success": True,
                "cracked": self._parse_show_output(result.data.get("output", "")),
                "raw_output": result.data.get("output", ""),
            }

        # 构建破解命令
        cmd = ["john"]
        if fmt:
            cmd.extend(["--format", JOHN_FORMATS.get(fmt, fmt)])
        if wordlist:
            cmd.extend(["--wordlist", wordlist])
        if rules:
            cmd.extend(["--rules", rules])
        if incremental:
            cmd.append("--incremental")
        cmd.append(hash_file)

        logger.info("执行John: %s", " ".join(cmd))
        result = runner.run(cmd, tool_name="john", install_cmd="apt install john")

        if not result.success:
            return result.to_dict()

        # 获取破解结果
        show_cmd = ["john", "--show", hash_file]
        if fmt:
            show_cmd.extend(["--format", JOHN_FORMATS.get(fmt, fmt)])
        show_result = runner.run(show_cmd, tool_name="john")

        cracked = []
        if show_result.success:
            cracked = self._parse_show_output(show_result.data.get("output", ""))

        return {
            "success": True,
            "cracked": cracked,
            "cracked_count": len(cracked),
            "raw_output": result.data.get("output", ""),
        }

    def _parse_show_output(self, output: str) -> List[Dict[str, str]]:
        """解析 john --show 输出"""
        cracked = []
        for line in output.splitlines():
            if (
                ":" in line
                and not line.startswith("0 password")
                and "password hash" not in line.lower()
            ):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    cracked.append({"user": parts[0], "password": parts[1].split(":")[0]})
        return cracked


@dataclass
class HashcatTool(BaseTool):
    """Hashcat GPU 哈希破解"""

    name: str = "hashcat"
    description: str = "Hashcat - GPU加速密码哈希破解工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("hash_file", "string", "哈希文件路径", required=True),
            ToolParameter(
                "hash_type",
                "string",
                "哈希类型",
                required=True,
                choices=list(HASHCAT_MODES.keys()),
            ),
            ToolParameter(
                "attack_mode",
                "string",
                "攻击模式",
                required=False,
                default="dictionary",
                choices=[
                    "dictionary",
                    "combinator",
                    "bruteforce",
                    "mask",
                    "hybrid_wl_mask",
                    "hybrid_mask_wl",
                ],
            ),
            ToolParameter("wordlist", "string", "字典文件路径", required=False, default=""),
            ToolParameter("mask", "string", "掩码(如?a?a?a?a?a?a)", required=False, default=""),
            ToolParameter("rules", "string", "规则文件路径", required=False, default=""),
            ToolParameter("outfile", "string", "输出文件路径", required=False, default=""),
            ToolParameter("status", "boolean", "启用状态输出", required=False, default=True),
            ToolParameter("force", "boolean", "强制运行(忽略警告)", required=False, default=False),
        ]
    )
    timeout: int = 7200

    # 攻击模式映射
    ATTACK_MODES = {
        "dictionary": "0",
        "combinator": "1",
        "bruteforce": "3",
        "mask": "3",
        "hybrid_wl_mask": "6",
        "hybrid_mask_wl": "7",
    }

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        hash_file = params["hash_file"]
        hash_type = params["hash_type"]
        attack_mode = params.get("attack_mode", "dictionary")
        wordlist = params.get("wordlist", "")
        mask = params.get("mask", "")
        rules = params.get("rules", "")
        outfile = params.get("outfile", "")
        status = params.get("status", True)
        force = params.get("force", False)

        mode_num = HASHCAT_MODES.get(hash_type, hash_type)
        attack_num = self.ATTACK_MODES.get(attack_mode, "0")

        cmd = ["hashcat", "-m", mode_num, "-a", attack_num]

        if status:
            cmd.append("--status")
        if force:
            cmd.append("--force")
        if outfile:
            cmd.extend(["-o", outfile])
        if rules:
            cmd.extend(["-r", rules])

        cmd.append(hash_file)

        # 根据攻击模式添加参数
        if attack_mode in ("dictionary", "combinator", "hybrid_wl_mask"):
            if wordlist:
                cmd.append(wordlist)
        if attack_mode in ("mask", "bruteforce", "hybrid_wl_mask", "hybrid_mask_wl"):
            if mask:
                cmd.append(mask)

        runner = get_subprocess_runner(self.timeout)
        logger.info("执行Hashcat: %s", " ".join(cmd))
        result = runner.run(cmd, tool_name="hashcat", install_cmd="apt install hashcat")

        if not result.success:
            return result.to_dict()

        output = result.data.get("output", "")
        cracked = self._parse_output(output)

        return {
            "success": True,
            "cracked": cracked,
            "cracked_count": len(cracked),
            "raw_output": output,
        }

    def _parse_output(self, output: str) -> List[Dict[str, str]]:
        """解析 hashcat 输出"""
        cracked = []
        # 匹配格式: hash:password
        for line in output.splitlines():
            if ":" in line and not line.startswith("[") and not line.startswith("Session"):
                match = re.match(r"^([^:]+):(.+)$", line.strip())
                if match:
                    cracked.append({"hash": match.group(1), "password": match.group(2)})
        return cracked
