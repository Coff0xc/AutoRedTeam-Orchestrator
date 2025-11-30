#!/usr/bin/env python3
"""
工具依赖检查器 - 检查系统中安装的安全工具
"""

import subprocess
import shutil
from typing import Dict, List, Tuple

class ToolChecker:
    """工具检查器"""
    
    # 必需工具列表
    REQUIRED_TOOLS = {
        "nmap": {"package": "nmap", "description": "端口扫描"},
        "whois": {"package": "whois", "description": "域名查询"},
        "dig": {"package": "dnsutils", "description": "DNS查询"},
        "curl": {"package": "curl", "description": "HTTP请求"},
    }
    
    # 推荐工具列表
    RECOMMENDED_TOOLS = {
        "subfinder": {"package": "subfinder", "description": "子域名枚举", "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        "httpx": {"package": "httpx", "description": "HTTP探测", "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
        "nuclei": {"package": "nuclei", "description": "漏洞扫描", "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
        "whatweb": {"package": "whatweb", "description": "技术栈识别", "install": "apt install whatweb"},
        "wafw00f": {"package": "wafw00f", "description": "WAF检测", "install": "pip3 install wafw00f"},
        "gobuster": {"package": "gobuster", "description": "目录扫描", "install": "apt install gobuster"},
        "nikto": {"package": "nikto", "description": "Web漏洞扫描", "install": "apt install nikto"},
        "sslscan": {"package": "sslscan", "description": "SSL扫描", "install": "apt install sslscan"},
        "sqlmap": {"package": "sqlmap", "description": "SQL注入", "install": "apt install sqlmap"},
        "hydra": {"package": "hydra", "description": "密码爆破", "install": "apt install hydra"},
    }
    
    @classmethod
    def check_tool(cls, tool_name: str) -> bool:
        """检查单个工具是否可用"""
        return shutil.which(tool_name) is not None
    
    @classmethod
    def check_all(cls) -> Tuple[Dict[str, bool], Dict[str, bool]]:
        """检查所有工具"""
        required = {tool: cls.check_tool(tool) for tool in cls.REQUIRED_TOOLS}
        recommended = {tool: cls.check_tool(tool) for tool in cls.RECOMMENDED_TOOLS}
        return required, recommended
    
    @classmethod
    def get_missing_tools(cls) -> Tuple[List[str], List[str]]:
        """获取缺失的工具列表"""
        required, recommended = cls.check_all()
        missing_required = [t for t, v in required.items() if not v]
        missing_recommended = [t for t, v in recommended.items() if not v]
        return missing_required, missing_recommended
    
    @classmethod
    def print_status(cls):
        """打印工具状态"""
        required, recommended = cls.check_all()
        
        print("\n" + "="*60)
        print("  🔧 工具依赖检查")
        print("="*60)
        
        print("\n📌 必需工具:")
        for tool, available in required.items():
            info = cls.REQUIRED_TOOLS[tool]
            status = "✓" if available else "✗"
            color = "\033[92m" if available else "\033[91m"
            print(f"  {color}{status}\033[0m {tool} - {info['description']}")
        
        print("\n📌 推荐工具:")
        for tool, available in recommended.items():
            info = cls.RECOMMENDED_TOOLS[tool]
            status = "✓" if available else "✗"
            color = "\033[92m" if available else "\033[93m"
            print(f"  {color}{status}\033[0m {tool} - {info['description']}")
            if not available:
                print(f"      安装: {info.get('install', 'N/A')}")
        
        # 统计
        req_ok = sum(1 for v in required.values() if v)
        rec_ok = sum(1 for v in recommended.values() if v)
        print(f"\n📊 统计: 必需 {req_ok}/{len(required)}, 推荐 {rec_ok}/{len(recommended)}")
        print("="*60 + "\n")
    
    @classmethod
    def get_install_commands(cls) -> List[str]:
        """获取安装命令"""
        _, recommended = cls.check_all()
        commands = []
        for tool, available in recommended.items():
            if not available:
                info = cls.RECOMMENDED_TOOLS[tool]
                if "install" in info:
                    commands.append(f"# {tool}: {info['install']}")
        return commands


if __name__ == "__main__":
    ToolChecker.print_status()
