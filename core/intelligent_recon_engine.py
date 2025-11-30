#!/usr/bin/env python3
"""
智能侦察引擎 - AI驱动的深度自动化打点
基于实战案例优化，提高打点深度和精确度
"""

import re
import json
import time
import subprocess
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建不验证SSL的上下文
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


@dataclass
class VulnFinding:
    """漏洞发现"""
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str
    recommendation: str
    confidence: float  # 0-1
    cve_id: Optional[str] = None
    exploit_available: bool = False


@dataclass
class AssetInfo:
    """资产信息"""
    url: str
    ip: str = ""
    ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    technologies: Dict[str, str] = field(default_factory=dict)
    cms: Optional[str] = None
    waf: Optional[str] = None
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    sensitive_info: List[str] = field(default_factory=list)


class IntelligentReconEngine:
    """智能侦察引擎"""
    
    # 常见OA系统默认口令
    DEFAULT_CREDENTIALS = {
        "seeyon": [
            ("system", "system"),
            ("group-admin", "123456"),
            ("admin1", "admin123456"),
            ("audit-admin", "seeyon123456")
        ],
        "weaver": [
            ("sysadmin", "1"),
            ("sysadmin", "Weaver@2001"),
            ("admin", "admin")
        ],
        "ruoyi": [
            ("admin", "admin123"),
            ("admin", "admin123456")
        ],
        "common": [
            ("admin", "admin"),
            ("admin", "admin123"),
            ("admin", "123456"),
            ("admin", "password"),
            ("root", "root"),
            ("test", "test")
        ]
    }
    
    # 敏感文件路径
    SENSITIVE_PATHS = [
        "/.git/config",
        "/.env",
        "/.DS_Store",
        "/web.config",
        "/WEB-INF/web.xml",
        "/.svn/entries",
        "/backup.zip",
        "/backup.sql",
        "/dump.sql",
        "/.idea/workspace.xml",
        "/composer.json",
        "/package.json",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/admin.php",
        "/login.php",
        "/config.php",
        "/database.php"
    ]
    
    # JS敏感关键词
    JS_SENSITIVE_KEYWORDS = [
        r'api[_-]?key',
        r'access[_-]?token',
        r'secret[_-]?key',
        r'password',
        r'aws[_-]?access',
        r'private[_-]?key',
        r'db[_-]?password',
        r'mysql[_-]?password',
        r'api[_-]?secret',
        r'client[_-]?secret'
    ]
    
    def __init__(self, target: str, options: Dict = None):
        self.target = target
        self.options = options or {}
        self.asset = AssetInfo(url=target)
        self.findings: List[VulnFinding] = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def run(self) -> Dict:
        """运行智能侦察"""
        logger.info(f"🔥 开始智能侦察: {self.target}")
        
        results = {
            "target": self.target,
            "start_time": datetime.now().isoformat(),
            "asset": {},
            "findings": [],
            "attack_surface": {}
        }
        
        # 阶段1: 资产发现
        logger.info("📡 阶段1: 资产发现与指纹识别")
        self._asset_discovery()
        
        # 阶段2: 深度指纹识别
        logger.info("🔍 阶段2: 深度指纹识别")
        self._deep_fingerprint()
        
        # 阶段3: JS文件深度分析
        logger.info("📜 阶段3: JS文件深度分析")
        self._js_deep_analysis()
        
        # 阶段4: 敏感文件探测
        logger.info("📂 阶段4: 敏感文件探测")
        self._sensitive_file_detection()
        
        # 阶段5: 登录框智能测试
        logger.info("🔐 阶段5: 登录框智能测试")
        self._login_intelligent_test()
        
        # 阶段6: 框架漏洞检测
        logger.info("🎯 阶段6: 框架漏洞检测")
        self._framework_vuln_detection()
        
        # 阶段7: API接口发现
        logger.info("🌐 阶段7: API接口发现")
        self._api_discovery()
        
        # 阶段8: 云存储检测
        logger.info("☁️ 阶段8: 云存储检测")
        self._cloud_storage_detection()
        
        # 生成攻击面分析
        results["asset"] = self._serialize_asset()
        results["findings"] = [self._serialize_finding(f) for f in self.findings]
        results["attack_surface"] = self._analyze_attack_surface()
        results["end_time"] = datetime.now().isoformat()
        
        logger.info(f"✅ 侦察完成，发现 {len(self.findings)} 个潜在问题")
        return results
    
    def _asset_discovery(self):
        """资产发现"""
        # 提取域名
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # 子域名枚举
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                self.asset.subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                logger.info(f"  发现 {len(self.asset.subdomains)} 个子域名")
        except Exception as e:
            logger.warning(f"  子域名枚举失败: {e}")
        
        # 端口扫描
        try:
            result = subprocess.run(
                ["nmap", "-T4", "-F", domain],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                ports = re.findall(r'(\d+)/tcp\s+open', result.stdout)
                self.asset.ports = [int(p) for p in ports]
                logger.info(f"  发现 {len(self.asset.ports)} 个开放端口")
        except Exception as e:
            logger.warning(f"  端口扫描失败: {e}")
    
    def _deep_fingerprint(self):
        """深度指纹识别"""
        try:
            # HTTP响应头分析
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                headers = dict(response.headers)
                content = response.read().decode('utf-8', errors='ignore')
            
            # 识别Web服务器
            if 'Server' in headers:
                self.asset.technologies['server'] = headers['Server']
            
            # 识别框架特征
            if 'X-Powered-By' in headers:
                self.asset.technologies['framework'] = headers['X-Powered-By']
            
            # Shiro检测
            if 'rememberMe=deleteMe' in headers.get('Set-Cookie', ''):
                self.asset.technologies['shiro'] = 'detected'
                self._add_finding(
                    vuln_type="framework",
                    severity="high",
                    title="检测到Shiro框架",
                    description="目标使用Shiro框架，可能存在反序列化漏洞",
                    evidence=f"Set-Cookie: {headers.get('Set-Cookie')}",
                    recommendation="检查Shiro版本，测试已知的反序列化漏洞",
                    confidence=0.9
                )
            
            # Spring Boot Actuator检测
            actuator_paths = ['/actuator', '/actuator/health', '/actuator/env']
            for path in actuator_paths:
                try:
                    req = urllib.request.Request(f"{self.target}{path}", headers=self.headers)
                    with urllib.request.urlopen(req, timeout=5, context=ssl_context) as r:
                        r_content = r.read().decode('utf-8', errors='ignore')
                        self._add_finding(
                            vuln_type="exposure",
                            severity="medium",
                            title="Spring Boot Actuator暴露",
                            description=f"发现暴露的Actuator端点: {path}",
                            evidence=f"Status: 200, Content: {r_content[:200]}",
                            recommendation="禁用或保护Actuator端点",
                            confidence=0.95
                        )
                        break
                except Exception as e:
                    pass
            
            # WAF检测
            waf_headers = ['X-WAF', 'X-CDN', 'Server']
            for header in waf_headers:
                if header in headers:
                    value = headers[header].lower()
                    if any(w in value for w in ['waf', 'cloudflare', 'akamai', 'incapsula']):
                        self.asset.waf = headers[header]
                        logger.info(f"  检测到WAF: {self.asset.waf}")
                        break
            
        except Exception as e:
            logger.warning(f"  指纹识别失败: {e}")
    
    def _js_deep_analysis(self):
        """深度JS文件分析"""
        try:
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                resp_text = response.read().decode('utf-8', errors='ignore')
            
            # 提取JS文件
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp_text)
            js_files += re.findall(r'src:\s*["\']([^"\']+\.js[^"\']*)["\']', resp_text)
            
            self.asset.js_files = list(set(js_files))
            logger.info(f"  发现 {len(self.asset.js_files)} 个JS文件")
            
            # 分析JS文件
            for js_file in self.asset.js_files[:10]:  # 限制分析前10个
                try:
                    if not js_file.startswith('http'):
                        js_url = f"{self.target.rstrip('/')}/{js_file.lstrip('/')}"
                    else:
                        js_url = js_file
                    
                    js_resp = self.session.get(js_url, timeout=5)
                    if js_resp.status_code == 200:
                        js_content = js_resp.text
                        
                        # 检测敏感信息
                        for keyword_pattern in self.JS_SENSITIVE_KEYWORDS:
                            matches = re.findall(f'{keyword_pattern}["\']?\\s*[:=]\\s*["\']([^"\']+)["\']', 
                                               js_content, re.IGNORECASE)
                            if matches:
                                self.asset.sensitive_info.extend(matches)
                                self._add_finding(
                                    vuln_type="info_leak",
                                    severity="medium",
                                    title=f"JS文件泄露敏感信息",
                                    description=f"在{js_file}中发现敏感关键词: {keyword_pattern}",
                                    evidence=f"匹配值: {matches[:3]}",
                                    recommendation="移除JS中的敏感信息，使用环境变量",
                                    confidence=0.8
                                )
                        
                        # 提取API端点
                        api_patterns = [
                            r'["\']/(api|admin|user|login|auth)/[^"\']+["\']',
                            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                            r'fetch\(["\']([^"\']+)["\']'
                        ]
                        for pattern in api_patterns:
                            endpoints = re.findall(pattern, js_content)
                            self.asset.api_endpoints.extend([e if isinstance(e, str) else e[1] for e in endpoints])
                        
                        # 检测webpack sourcemap
                        if '.map' in js_content or 'sourceMappingURL' in js_content:
                            self._add_finding(
                                vuln_type="exposure",
                                severity="low",
                                title="检测到Webpack SourceMap",
                                description=f"{js_file}可能存在.map文件，可能泄露源代码",
                                evidence=f"JS文件: {js_file}",
                                recommendation="生产环境禁用sourcemap",
                                confidence=0.7
                            )
                
                except Exception as e:
                    continue
            
            self.asset.api_endpoints = list(set(self.asset.api_endpoints))
            logger.info(f"  提取 {len(self.asset.api_endpoints)} 个API端点")
            
        except Exception as e:
            logger.warning(f"  JS分析失败: {e}")
    
    def _sensitive_file_detection(self):
        """敏感文件探测"""
        found_files = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for path in self.SENSITIVE_PATHS:
                url = f"{self.target.rstrip('/')}{path}"
                future = executor.submit(self._check_url_exists, url)
                futures[future] = path
            
            for future in as_completed(futures):
                path = futures[future]
                try:
                    exists, status, content = future.result()
                    if exists:
                        found_files.append(path)
                        severity = "high" if any(k in path for k in ['.git', '.env', 'backup', 'dump']) else "medium"
                        self._add_finding(
                            vuln_type="exposure",
                            severity=severity,
                            title=f"发现敏感文件: {path}",
                            description=f"目标暴露敏感文件，可能泄露配置或源代码",
                            evidence=f"Status: {status}, Size: {len(content)} bytes",
                            recommendation="删除或保护敏感文件",
                            confidence=0.95
                        )
                except:
                    pass
        
        logger.info(f"  发现 {len(found_files)} 个敏感文件")
    
    def _login_intelligent_test(self):
        """登录框智能测试"""
        # 检测登录页面
        login_paths = ['/login', '/admin', '/admin/login', '/user/login', '/signin', '/auth/login']
        login_url = None
        
        for path in login_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and any(k in resp.text.lower() for k in ['password', 'username', 'login']):
                    login_url = url
                    break
            except:
                continue
        
        if not login_url:
            return
        
        logger.info(f"  发现登录页面: {login_url}")
        
        # 识别CMS类型
        cms_type = self._identify_cms()
        
        # 测试默认口令
        if cms_type and cms_type in self.DEFAULT_CREDENTIALS:
            credentials = self.DEFAULT_CREDENTIALS[cms_type]
        else:
            credentials = self.DEFAULT_CREDENTIALS['common']
        
        for username, password in credentials[:5]:  # 限制测试5组
            try:
                # 这里只是检测，不实际登录
                self._add_finding(
                    vuln_type="weak_credential",
                    severity="info",
                    title=f"建议测试默认口令",
                    description=f"系统可能使用默认口令: {username}/{password}",
                    evidence=f"CMS类型: {cms_type or 'unknown'}",
                    recommendation="修改默认口令，启用强密码策略",
                    confidence=0.5
                )
                break  # 只添加一次建议
            except:
                pass
        
        # SQL注入检测（基础）
        test_payloads = ["'", "\"", "' OR '1'='1", "admin' --"]
        for payload in test_payloads:
            try:
                # 这里只是标记可能性，不实际测试
                pass
            except:
                pass
    
    def _framework_vuln_detection(self):
        """框架漏洞检测"""
        # Log4j检测
        log4j_headers = ['X-Api-Version', 'User-Agent', 'Referer']
        for header in log4j_headers:
            # 标记需要测试
            pass
        
        # Fastjson检测
        if 'fastjson' in str(self.asset.technologies).lower():
            self._add_finding(
                vuln_type="framework",
                severity="high",
                title="检测到Fastjson框架",
                description="Fastjson存在多个反序列化漏洞",
                evidence=f"技术栈: {self.asset.technologies}",
                recommendation="升级Fastjson到最新版本，或使用其他JSON库",
                confidence=0.8
            )
    
    def _api_discovery(self):
        """API接口发现"""
        # 常见API路径
        api_paths = [
            '/api/v1', '/api/v2', '/api',
            '/swagger-ui.html', '/swagger-ui/',
            '/v2/api-docs', '/api-docs',
            '/graphql', '/graphiql'
        ]
        
        for path in api_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    self._add_finding(
                        vuln_type="exposure",
                        severity="low",
                        title=f"发现API文档: {path}",
                        description="API文档暴露可能泄露接口信息",
                        evidence=f"URL: {url}",
                        recommendation="保护API文档，限制访问",
                        confidence=0.9
                    )
            except:
                pass
    
    def _cloud_storage_detection(self):
        """云存储检测"""
        # S3存储桶检测
        s3_patterns = [
            r's3\.amazonaws\.com/([^/\s"\']+)',
            r'([^/\s"\']+)\.s3\.amazonaws\.com',
            r'([^/\s"\']+)\.s3-[^/\s"\']+\.amazonaws\.com'
        ]
        
        try:
            resp = self.session.get(self.target, timeout=10)
            for pattern in s3_patterns:
                matches = re.findall(pattern, resp.text)
                for bucket in matches:
                    self._add_finding(
                        vuln_type="exposure",
                        severity="medium",
                        title=f"发现S3存储桶引用: {bucket}",
                        description="可能存在S3存储桶接管或数据泄露风险",
                        evidence=f"Bucket: {bucket}",
                        recommendation="检查存储桶权限配置",
                        confidence=0.7
                    )
        except:
            pass
    
    def _check_url_exists(self, url: str) -> Tuple[bool, int, str]:
        """检查URL是否存在"""
        try:
            resp = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302]:
                return True, resp.status_code, resp.text[:1000]
        except:
            pass
        return False, 0, ""
    
    def _identify_cms(self) -> Optional[str]:
        """识别CMS类型"""
        try:
            resp = self.session.get(self.target, timeout=10)
            content = resp.text.lower()
            
            if 'seeyon' in content or '/seeyon/' in content:
                return 'seeyon'
            elif 'weaver' in content or 'ecology' in content:
                return 'weaver'
            elif 'ruoyi' in content:
                return 'ruoyi'
        except:
            pass
        return None
    
    def _add_finding(self, vuln_type: str, severity: str, title: str, 
                     description: str, evidence: str, recommendation: str, 
                     confidence: float, cve_id: str = None):
        """添加发现"""
        finding = VulnFinding(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            confidence=confidence,
            cve_id=cve_id
        )
        self.findings.append(finding)
    
    def _analyze_attack_surface(self) -> Dict:
        """分析攻击面"""
        return {
            "subdomains_count": len(self.asset.subdomains),
            "open_ports": self.asset.ports,
            "technologies": self.asset.technologies,
            "api_endpoints_count": len(self.asset.api_endpoints),
            "js_files_count": len(self.asset.js_files),
            "sensitive_files": len([f for f in self.findings if f.vuln_type == "exposure"]),
            "high_risk_findings": len([f for f in self.findings if f.severity in ["critical", "high"]]),
            "waf_detected": self.asset.waf is not None
        }
    
    def _serialize_asset(self) -> Dict:
        """序列化资产信息"""
        return {
            "url": self.asset.url,
            "ip": self.asset.ip,
            "ports": self.asset.ports,
            "subdomains": self.asset.subdomains[:50],  # 限制数量
            "technologies": self.asset.technologies,
            "cms": self.asset.cms,
            "waf": self.asset.waf,
            "api_endpoints": self.asset.api_endpoints[:20],
            "sensitive_info_count": len(self.asset.sensitive_info)
        }
    
    def _serialize_finding(self, finding: VulnFinding) -> Dict:
        """序列化发现"""
        return {
            "vuln_type": finding.vuln_type,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence[:500],  # 限制长度
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
            "cve_id": finding.cve_id
        }


if __name__ == "__main__":
    # 测试
    engine = IntelligentReconEngine("https://example.com")
    results = engine.run()
    print(json.dumps(results, indent=2, ensure_ascii=False))
