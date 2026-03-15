#!/usr/bin/env python3
"""
CDN识别与真实IP发现工具集

功能:
- CDN识别 (Cloudflare/Akamai/Fastly/CloudFront/阿里云CDN)
- 真实IP发现: 历史DNS、SSL证书反查、邮件头分析、子域名IP收集、favicon hash搜索
"""

import logging
from typing import Any, Dict, List, Optional, Set

import httpx

try:
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.registry import BaseTool, ToolCategory, ToolMetadata, ToolParameter, ParamType
from core.result import ToolResult
from shared.validators import validate_domain as _validate_domain

logger = logging.getLogger(__name__)

# CDN特征库
CDN_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cnames": ["cloudflare.com", "cloudflare.net", "cloudflare-dns.com"],
        "ip_ranges": [
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "108.162.192.0/18",
            "131.0.72.0/22",
            "141.101.64.0/18",
            "162.158.0.0/15",
            "172.64.0.0/13",
            "173.245.48.0/20",
            "188.114.96.0/20",
            "190.93.240.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
        ],
        "nameservers": ["cloudflare.com"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "cnames": [
            "akamai.net",
            "akamaiedge.net",
            "akamaihd.net",
            "akamaitechnologies.com",
            "edgesuite.net",
            "edgekey.net",
        ],
        "nameservers": ["akam.net"],
    },
    "fastly": {
        "headers": ["x-served-by", "x-cache", "x-cache-hits", "x-fastly-request-id"],
        "cnames": ["fastly.net", "fastlylb.net", "fastly.com"],
    },
    "cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "cnames": ["cloudfront.net", "amazonaws.com"],
    },
    "aliyun": {
        "headers": [
            "eagleid",
            "x-swift-savetime",
            "x-swift-cachetime",
            "ali-swift-global-savetime",
        ],
        "cnames": ["kunlun.com", "alikunlun.com", "cdngslb.com", "tbcache.com", "aliyuncs.com"],
    },
    "tencent": {
        "headers": ["x-nws-log-uuid", "x-cache-lookup"],
        "cnames": ["cdn.dnsv1.com", "tdnsv5.com", "qcloud.com"],
    },
    "huawei": {
        "cnames": ["huaweicloud.com", "cdnhwc1.com", "cdnhwc2.com"],
    },
}


def validate_domain(domain: str) -> bool:
    """验证域名格式（委托给shared.validators，适配布尔返回值）"""
    valid, _ = _validate_domain(domain)
    return valid


class CDNDetectTool(BaseTool):
    """CDN识别工具"""

    metadata = ToolMetadata(
        name="cdn_detect",
        description="识别目标是否使用CDN及CDN类型",
        category=ToolCategory.RECON,
        parameters=[
            ToolParameter(
                name="domain", type=ParamType.DOMAIN, description="目标域名", required=True
            ),
            ToolParameter(
                name="timeout",
                type=ParamType.INTEGER,
                description="超时秒数",
                required=False,
                default=10,
            ),
        ],
        timeout=30.0,
    )

    def execute(self, **kwargs) -> ToolResult:
        domain = kwargs["domain"]
        timeout = kwargs.get("timeout", 10)

        if not validate_domain(domain):
            return ToolResult.fail(error=f"无效域名: {domain}")

        result = {
            "domain": domain,
            "is_cdn": False,
            "cdn_provider": None,
            "evidence": [],
            "ip_addresses": [],
            "cnames": [],
        }

        # 1. DNS解析获取CNAME和IP
        if DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = timeout
                resolver.lifetime = timeout

                # 获取CNAME
                try:
                    cname_answers = resolver.resolve(domain, "CNAME")
                    result["cnames"] = [str(r.target).rstrip(".") for r in cname_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass

                # 获取A记录
                try:
                    a_answers = resolver.resolve(domain, "A")
                    result["ip_addresses"] = [str(r) for r in a_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
            except Exception as e:
                logger.warning("DNS解析失败: %s", e)

        # 2. 检测CNAME特征
        for cname in result["cnames"]:
            cname_lower = cname.lower()
            for cdn_name, sigs in CDN_SIGNATURES.items():
                for pattern in sigs.get("cnames", []):
                    if pattern in cname_lower:
                        result["is_cdn"] = True
                        result["cdn_provider"] = cdn_name
                        result["evidence"].append(f"CNAME匹配: {cname} -> {cdn_name}")
                        break

        # 3. HTTP头检测
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                for scheme in ["https", "http"]:
                    try:
                        resp = client.get(
                            f"{scheme}://{domain}/", headers={"User-Agent": "Mozilla/5.0"}
                        )
                        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                        for cdn_name, sigs in CDN_SIGNATURES.items():
                            for header in sigs.get("headers", []):
                                if header.lower() in headers_lower:
                                    result["is_cdn"] = True
                                    result["cdn_provider"] = result["cdn_provider"] or cdn_name
                                    result["evidence"].append(f"HTTP头: {header}")
                        break
                    except httpx.RequestError:
                        continue
        except Exception as e:
            logger.warning("HTTP检测失败: %s", e)

        # 4. 多IP检测 (CDN通常返回多个IP)
        if len(result["ip_addresses"]) > 2:
            result["evidence"].append(f"多IP响应: {len(result['ip_addresses'])}个")
            if not result["is_cdn"]:
                result["is_cdn"] = True
                result["cdn_provider"] = "unknown"

        return ToolResult.ok(data=result)


class RealIPFinderTool(BaseTool):
    """真实IP发现工具"""

    metadata = ToolMetadata(
        name="real_ip_finder",
        description="通过多种方法发现CDN后的真实IP",
        category=ToolCategory.RECON,
        parameters=[
            ToolParameter(
                name="domain", type=ParamType.DOMAIN, description="目标域名", required=True
            ),
            ToolParameter(
                name="securitytrails_key",
                type=ParamType.STRING,
                description="SecurityTrails API Key",
                required=False,
                sensitive=True,
            ),
            ToolParameter(
                name="timeout",
                type=ParamType.INTEGER,
                description="超时秒数",
                required=False,
                default=15,
            ),
        ],
        timeout=120.0,
    )

    def execute(self, **kwargs) -> ToolResult:
        domain = kwargs["domain"]
        api_key = kwargs.get("securitytrails_key")
        timeout = kwargs.get("timeout", 15)

        if not validate_domain(domain):
            return ToolResult.fail(error=f"无效域名: {domain}")

        result = {
            "domain": domain,
            "potential_ips": [],
            "methods": {},
        }

        # 1. 历史DNS记录 (SecurityTrails)
        if api_key:
            hist_ips = self._query_securitytrails(domain, api_key, timeout)
            if hist_ips:
                result["methods"]["historical_dns"] = hist_ips
                result["potential_ips"].extend(hist_ips)

        # 2. 子域名IP收集
        subdomain_ips = self._collect_subdomain_ips(domain, timeout)
        if subdomain_ips:
            result["methods"]["subdomain_ips"] = list(subdomain_ips)
            result["potential_ips"].extend(subdomain_ips)

        # 3. MX记录分析
        mx_ips = self._analyze_mx_records(domain, timeout)
        if mx_ips:
            result["methods"]["mx_records"] = mx_ips
            result["potential_ips"].extend(mx_ips)

        # 4. SSL证书反查 (crt.sh)
        cert_ips = self._search_ssl_certs(domain, timeout)
        if cert_ips:
            result["methods"]["ssl_certs"] = cert_ips
            result["potential_ips"].extend(cert_ips)

        # 5. Favicon hash搜索
        favicon_hash = self._get_favicon_hash(domain, timeout)
        if favicon_hash:
            result["methods"]["favicon_hash"] = favicon_hash

        # 去重
        result["potential_ips"] = list(set(result["potential_ips"]))

        return ToolResult.ok(data=result)

    def _query_securitytrails(self, domain: str, api_key: str, timeout: int) -> List[str]:
        """查询SecurityTrails历史DNS"""
        ips = []
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                    headers={"APIKEY": api_key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("records", []):
                        for val in record.get("values", []):
                            if ip := val.get("ip"):
                                ips.append(ip)
        except Exception as e:
            logger.warning("SecurityTrails查询失败: %s", e)
        return list(set(ips))

    def _collect_subdomain_ips(self, domain: str, timeout: int) -> Set[str]:
        """收集子域名IP"""
        ips: Set[str] = set()
        if not DNS_AVAILABLE:
            return ips

        common_subdomains = [
            "mail",
            "ftp",
            "direct",
            "origin",
            "www",
            "api",
            "dev",
            "test",
            "staging",
            "admin",
            "cpanel",
            "webmail",
            "mx",
            "smtp",
            "pop",
            "imap",
        ]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        for sub in common_subdomains:
            try:
                answers = resolver.resolve(f"{sub}.{domain}", "A")
                for r in answers:
                    ips.add(str(r))
            except Exception:
                continue
        return ips

    def _analyze_mx_records(self, domain: str, timeout: int) -> List[str]:
        """分析MX记录获取邮件服务器IP"""
        ips = []
        if not DNS_AVAILABLE:
            return ips

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            mx_answers = resolver.resolve(domain, "MX")

            for mx in mx_answers:
                mx_host = str(mx.exchange).rstrip(".")
                # 检查MX是否属于同一域名
                if domain in mx_host:
                    try:
                        a_answers = resolver.resolve(mx_host, "A")
                        ips.extend(str(r) for r in a_answers)
                    except Exception:
                        continue
        except Exception as e:
            logger.warning("MX记录分析失败: %s", e)
        return list(set(ips))

    def _search_ssl_certs(self, domain: str, timeout: int) -> List[str]:
        """通过crt.sh搜索SSL证书关联的IP"""
        ips = []
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code == 200:
                    certs = resp.json()
                    # 提取证书中的域名，尝试解析
                    seen_names: Set[str] = set()
                    for cert in certs[:20]:  # 限制数量
                        name = cert.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lstrip("*.")
                            if n and validate_domain(n) and n not in seen_names:
                                seen_names.add(n)

                    if DNS_AVAILABLE:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        for name in list(seen_names)[:10]:
                            try:
                                answers = resolver.resolve(name, "A")
                                ips.extend(str(r) for r in answers)
                            except Exception:
                                continue
        except Exception as e:
            logger.warning("SSL证书搜索失败: %s", e)
        return list(set(ips))

    def _get_favicon_hash(self, domain: str, timeout: int) -> Optional[str]:
        """获取favicon的MMH3 hash (用于Shodan搜索)"""
        try:
            import mmh3
            import base64

            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                for path in ["/favicon.ico", "/assets/favicon.ico", "/static/favicon.ico"]:
                    try:
                        resp = client.get(f"https://{domain}{path}")
                        if resp.status_code == 200 and len(resp.content) > 0:
                            favicon_b64 = base64.encodebytes(resp.content).decode()
                            return str(mmh3.hash(favicon_b64))
                    except Exception:
                        continue
        except ImportError:
            logger.debug("mmh3未安装，跳过favicon hash")
        except Exception as e:
            logger.warning("Favicon获取失败: %s", e)
        return None


class HistoricalDNSTool(BaseTool):
    """历史DNS记录查询工具"""

    metadata = ToolMetadata(
        name="historical_dns",
        description="查询域名的历史DNS记录",
        category=ToolCategory.RECON,
        parameters=[
            ToolParameter(
                name="domain", type=ParamType.DOMAIN, description="目标域名", required=True
            ),
            ToolParameter(
                name="securitytrails_key",
                type=ParamType.STRING,
                description="SecurityTrails API Key",
                required=True,
                sensitive=True,
            ),
            ToolParameter(
                name="record_type",
                type=ParamType.STRING,
                description="记录类型",
                required=False,
                default="a",
                choices=["a", "aaaa", "mx", "ns", "txt"],
            ),
        ],
        timeout=30.0,
    )

    def execute(self, **kwargs) -> ToolResult:
        domain = kwargs["domain"]
        api_key = kwargs["securitytrails_key"]
        record_type = kwargs.get("record_type", "a")

        if not validate_domain(domain):
            return ToolResult.fail(error=f"无效域名: {domain}")

        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}",
                    headers={"APIKEY": api_key, "Accept": "application/json"},
                )

                if resp.status_code == 401:
                    return ToolResult.fail(error="API Key无效")
                if resp.status_code == 429:
                    return ToolResult.fail(error="API请求限制")
                if resp.status_code != 200:
                    return ToolResult.fail(error=f"API错误: {resp.status_code}")

                data = resp.json()
                records = []
                for record in data.get("records", []):
                    records.append(
                        {
                            "first_seen": record.get("first_seen"),
                            "last_seen": record.get("last_seen"),
                            "values": record.get("values", []),
                        }
                    )

                return ToolResult.ok(
                    data={
                        "domain": domain,
                        "record_type": record_type,
                        "records": records,
                        "total": len(records),
                    }
                )

        except httpx.TimeoutException:
            return ToolResult.fail(error="请求超时")
        except Exception as e:
            return ToolResult.fail(error=str(e))


# 导出
__all__ = [
    "CDNDetectTool",
    "RealIPFinderTool",
    "HistoricalDNSTool",
]
