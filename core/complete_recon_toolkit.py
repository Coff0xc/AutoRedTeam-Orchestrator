#!/usr/bin/env python3
"""
完整侦察工具包 - 整合全网侦察工具和Nuclei模板
基于红队实战流程设计
"""

from typing import Dict, List
import subprocess
import json


class CompleteReconToolkit:
    """完整侦察工具包"""
    
    # ==================== Nuclei模板统计 ====================
    NUCLEI_STATS = {
        "total_templates": 11997,  # 总模板数
        "directories": 873,
        "kev_templates": 1496,  # 已知被利用漏洞
        "cve_templates": 3000,  # CVE模板数
        "categories": {
            "cves": "CVE漏洞模板",
            "exposures": "信息泄露",
            "misconfiguration": "错误配置",
            "takeovers": "子域名接管",
            "vulnerabilities": "通用漏洞",
            "technologies": "技术栈检测",
            "default-logins": "默认登录",
            "file": "敏感文件",
            "dns": "DNS相关",
            "network": "网络服务"
        },
        "severity": {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
            "info": "信息"
        }
    }
    
    # ==================== 侦察工具链 (完整版) ====================
    RECON_TOOLS = {
        # 子域名枚举 (10+工具)
        "subdomain_enum": {
            "subfinder": {
                "description": "快速子域名发现",
                "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "usage": "subfinder -d domain.com -silent"
            },
            "amass": {
                "description": "OWASP深度子域名枚举",
                "install": "apt install amass",
                "usage": "amass enum -d domain.com"
            },
            "OneForAll": {
                "description": "全面子域名收集",
                "github": "https://github.com/shmilylty/OneForAll",
                "usage": "python3 oneforall.py --target domain.com run"
            },
            "ksubdomain": {
                "description": "无状态子域名爆破",
                "github": "https://github.com/knownsec/ksubdomain",
                "usage": "ksubdomain -d domain.com"
            },
            "sublist3r": {
                "description": "子域名枚举工具",
                "install": "pip install sublist3r",
                "usage": "sublist3r -d domain.com"
            }
        },
        
        # 端口扫描 (8+工具)
        "port_scan": {
            "nmap": {
                "description": "网络扫描之王",
                "install": "apt install nmap",
                "usage": "nmap -sS -sV -T4 target"
            },
            "masscan": {
                "description": "超快速端口扫描",
                "install": "apt install masscan",
                "usage": "masscan -p1-65535 target --rate=10000"
            },
            "naabu": {
                "description": "快速端口扫描器",
                "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                "usage": "naabu -host target -top-ports 1000"
            },
            "rustscan": {
                "description": "Rust编写的快速扫描器",
                "github": "https://github.com/RustScan/RustScan",
                "usage": "rustscan -a target"
            }
        },
        
        # Web指纹识别 (10+工具)
        "fingerprint": {
            "whatweb": {
                "description": "Web指纹识别(1800+插件)",
                "install": "apt install whatweb",
                "usage": "whatweb -a 3 target"
            },
            "wappalyzer": {
                "description": "技术栈识别",
                "type": "浏览器插件",
                "url": "https://www.wappalyzer.com/"
            },
            "httpx": {
                "description": "HTTP探测工具",
                "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                "usage": "httpx -l urls.txt -title -status-code"
            },
            "EHole": {
                "description": "红队重点系统指纹探测",
                "github": "https://github.com/EdgeSecurityTeam/EHole",
                "usage": "ehole finger -l urls.txt"
            },
            "TideFinger": {
                "description": "指纹识别工具(20000+指纹)",
                "github": "https://github.com/TideSec/TideFinger",
                "usage": "python3 TideFinger.py -u target"
            },
            "kscan": {
                "description": "全方位扫描器(20000+指纹)",
                "github": "https://github.com/lcvvvv/kscan",
                "usage": "kscan -t target"
            }
        },
        
        # 目录扫描 (6+工具)
        "directory_scan": {
            "gobuster": {
                "description": "目录/DNS暴力扫描",
                "install": "apt install gobuster",
                "usage": "gobuster dir -u target -w wordlist"
            },
            "dirsearch": {
                "description": "Web路径扫描",
                "github": "https://github.com/maurosoria/dirsearch",
                "usage": "python3 dirsearch.py -u target"
            },
            "ffuf": {
                "description": "快速Web Fuzzer",
                "install": "go install github.com/ffuf/ffuf@latest",
                "usage": "ffuf -u target/FUZZ -w wordlist"
            },
            "feroxbuster": {
                "description": "Rust编写的目录扫描",
                "github": "https://github.com/epi052/feroxbuster",
                "usage": "feroxbuster -u target"
            }
        },
        
        # 漏洞扫描 (5+工具)
        "vuln_scan": {
            "nuclei": {
                "description": "基于模板的漏洞扫描器",
                "templates": 11997,
                "kev": 1496,
                "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "usage": "nuclei -u target -t nuclei-templates/",
                "presets": {
                    "quick": "nuclei -u target -tags cve,exposure",
                    "full": "nuclei -u target -t nuclei-templates/",
                    "kev": "nuclei -u target -tags kev,vkev",
                    "critical": "nuclei -u target -severity critical,high"
                }
            },
            "xray": {
                "description": "被动扫描器",
                "github": "https://github.com/chaitin/xray",
                "usage": "xray webscan --url target"
            },
            "afrog": {
                "description": "漏洞扫描工具",
                "github": "https://github.com/zan8in/afrog",
                "usage": "afrog -t target"
            }
        },
        
        # 信息收集综合工具
        "comprehensive": {
            "reconftw": {
                "description": "自动化侦察框架",
                "github": "https://github.com/six2dez/reconftw",
                "features": "子域名+端口+目录+漏洞全流程"
            },
            "AlliN": {
                "description": "链式资产发现",
                "github": "https://github.com/P1-Team/AlliN",
                "features": "企业信息+域名+子域名+端口"
            }
        }
    }
    
    # ==================== Nuclei模板分类 ====================
    NUCLEI_TEMPLATES = {
        "cves": {
            "count": 3000,
            "description": "CVE漏洞模板",
            "examples": [
                "CVE-2021-44228 - Log4j RCE",
                "CVE-2022-22965 - Spring4Shell",
                "CVE-2023-22515 - Confluence RCE",
                "CVE-2024-21887 - Ivanti RCE"
            ]
        },
        "exposures": {
            "count": 500,
            "description": "信息泄露检测",
            "examples": [
                "git配置泄露",
                "环境变量泄露",
                "备份文件泄露",
                "源码泄露"
            ]
        },
        "technologies": {
            "count": 800,
            "description": "技术栈检测",
            "examples": [
                "Apache检测",
                "Nginx检测",
                "PHP版本检测",
                "WordPress检测"
            ]
        },
        "misconfiguration": {
            "count": 600,
            "description": "错误配置检测",
            "examples": [
                "目录列表",
                "默认页面",
                "调试模式",
                "CORS配置错误"
            ]
        },
        "default-logins": {
            "count": 200,
            "description": "默认登录凭证",
            "examples": [
                "Tomcat默认口令",
                "Jenkins默认口令",
                "phpMyAdmin默认口令"
            ]
        },
        "takeovers": {
            "count": 100,
            "description": "子域名接管",
            "examples": [
                "GitHub Pages",
                "AWS S3",
                "Azure",
                "Heroku"
            ]
        }
    }
    
    # ==================== 侦察流程 ====================
    RECON_WORKFLOW = {
        "phase1_asset_discovery": {
            "name": "资产发现",
            "tools": ["天眼查", "爱企查", "cSubsidiary", "ENScan"],
            "output": "企业信息、子公司、域名、APP、公众号"
        },
        "phase2_subdomain_enum": {
            "name": "子域名枚举",
            "tools": ["subfinder", "amass", "OneForAll", "ksubdomain"],
            "output": "子域名列表"
        },
        "phase3_alive_detection": {
            "name": "存活检测",
            "tools": ["httpx", "WebAliveScan"],
            "output": "存活域名列表"
        },
        "phase4_port_scan": {
            "name": "端口扫描",
            "tools": ["nmap", "masscan", "naabu"],
            "output": "开放端口列表"
        },
        "phase5_fingerprint": {
            "name": "指纹识别",
            "tools": ["whatweb", "EHole", "TideFinger", "kscan"],
            "output": "CMS、框架、中间件信息"
        },
        "phase6_directory_scan": {
            "name": "目录扫描",
            "tools": ["gobuster", "dirsearch", "ffuf"],
            "output": "敏感目录、文件"
        },
        "phase7_vuln_scan": {
            "name": "漏洞扫描",
            "tools": ["nuclei", "xray", "afrog"],
            "output": "漏洞列表"
        },
        "phase8_exploit": {
            "name": "漏洞利用",
            "tools": ["POC bomber", "自定义脚本"],
            "output": "权限获取"
        }
    }
    
    @classmethod
    def get_nuclei_command(cls, target: str, preset: str = "quick") -> str:
        """获取Nuclei扫描命令"""
        presets = {
            "quick": f"nuclei -u {target} -tags cve,exposure -severity critical,high",
            "full": f"nuclei -u {target} -t ~/nuclei-templates/",
            "kev": f"nuclei -u {target} -tags kev,vkev",
            "critical": f"nuclei -u {target} -severity critical",
            "web": f"nuclei -u {target} -tags xss,sqli,rce,lfi",
            "exposure": f"nuclei -u {target} -tags exposure,config",
            "cve_2024": f"nuclei -u {target} -tags cve2024"
        }
        return presets.get(preset, presets["quick"])
    
    @classmethod
    def get_recon_workflow(cls) -> str:
        """获取完整侦察流程"""
        workflow = """
完整红队侦察流程:

阶段1: 资产发现
  └─ 企业信息收集 (天眼查、爱企查)
  └─ 子公司发现 (cSubsidiary)
  └─ APP/公众号收集 (ENScan)

阶段2: 域名收集
  └─ Whois查询
  └─ 备案反查
  └─ 子域名枚举 (subfinder, amass, OneForAll)
  └─ 证书透明度查询

阶段3: 存活检测
  └─ HTTP探测 (httpx)
  └─ 状态码检测
  └─ 标题获取

阶段4: 端口扫描
  └─ 快速扫描 (masscan, naabu)
  └─ 详细扫描 (nmap -sV -sC)
  └─ 服务识别

阶段5: 指纹识别
  └─ CMS识别 (whatweb, EHole, TideFinger)
  └─ 框架识别 (20000+指纹库)
  └─ 中间件识别
  └─ WAF检测

阶段6: 目录扫描
  └─ 敏感目录 (gobuster, dirsearch)
  └─ 备份文件
  └─ 配置文件

阶段7: 漏洞扫描
  └─ Nuclei (11997个模板)
  └─ Xray被动扫描
  └─ 自定义POC

阶段8: 深度分析
  └─ JS文件分析
  └─ API端点提取
  └─ 参数Fuzz
  └─ 默认口令测试

阶段9: 漏洞验证
  └─ POC验证
  └─ 手动复现
  └─ 漏洞确认

阶段10: 漏洞利用
  └─ Exploit执行
  └─ 权限获取
  └─ 内网渗透
"""
        return workflow
    
    @classmethod
    def get_tool_stats(cls) -> Dict:
        """获取工具统计"""
        return {
            "subdomain_tools": len(cls.RECON_TOOLS["subdomain_enum"]),
            "port_scan_tools": len(cls.RECON_TOOLS["port_scan"]),
            "fingerprint_tools": len(cls.RECON_TOOLS["fingerprint"]),
            "directory_tools": len(cls.RECON_TOOLS["directory_scan"]),
            "vuln_scan_tools": len(cls.RECON_TOOLS["vuln_scan"]),
            "nuclei_templates": cls.NUCLEI_STATS["total_templates"],
            "nuclei_kev": cls.NUCLEI_STATS["kev_templates"]
        }


if __name__ == "__main__":
    print("完整侦察工具包统计:")
    print(json.dumps(CompleteReconToolkit.get_tool_stats(), indent=2, ensure_ascii=False))
    print("\n" + CompleteReconToolkit.get_recon_workflow())
