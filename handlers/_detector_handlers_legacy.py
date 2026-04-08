"""
漏洞检测工具处理器
包含: vuln_scan, sqli_scan, xss_scan, ssrf_scan, rce_scan, path_traversal_scan,
      ssti_scan, xxe_scan, idor_scan, cors_scan, security_headers_scan

重构说明 (2026-01):
    使用 handle_errors 装饰器替代手动 try-except，实现:
    - 异常自动分类和日志记录
    - 标准化错误响应格式
    - 减少代码重复
"""

from typing import Any, Dict, List, Optional

from .error_handling import (
    ErrorCategory,
    extract_url,
    handle_errors,
    validate_inputs,
)
from .tooling import tool


def register_detector_tools(mcp, counter, logger):
    """注册漏洞检测工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def vuln_scan(
        url: str, params: Optional[Dict[str, str]] = None, detectors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """综合漏洞扫描 - 检测多种Web漏洞

        支持: SQL注入、XSS、命令注入、SSRF、路径遍历、XXE等

        Args:
            url: 目标URL
            params: 请求参数 (例: {"id": "1", "name": "test"})
            detectors: 要使用的检测器 (默认: sqli, xss, rce, ssrf, path_traversal)

        Returns:
            发现的漏洞列表
        """
        from core.detectors import DetectorFactory, DetectorPresets

        if detectors:
            composite = DetectorFactory.create_composite(detectors)
        else:
            composite = DetectorPresets.owasp_top10()

        results = await composite.async_detect(url, params=params or {})

        vulnerabilities = [
            {
                "type": r.vuln_type,
                "severity": r.severity.value,
                "param": r.param,
                "payload": r.payload,
                "evidence": r.evidence[:200] if r.evidence else None,
                "remediation": r.remediation,
            }
            for r in results
            if r.vulnerable
        ]

        return {
            "success": True,
            "url": url,
            "vulnerabilities": vulnerabilities,
            "total_vulns": len(vulnerabilities),
            "detectors_used": detectors or ["owasp_top10"],
        }

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def sqli_scan(
        url: str, params: Optional[Dict[str, str]] = None, method: str = "GET"
    ) -> Dict[str, Any]:
        """SQL注入检测 - 检测SQL注入漏洞

        支持: 基于错误、布尔盲注、时间盲注、联合注入

        Args:
            url: 目标URL
            params: 请求参数
            method: HTTP方法 (GET/POST)

        Returns:
            SQL注入检测结果
        """
        from core.detectors import SQLiDetector

        detector = SQLiDetector()
        results = await detector.async_detect(url, params=params or {}, method=method)

        findings = [
            {
                "param": r.param,
                "payload": r.payload,
                "type": r.injection_type if hasattr(r, "injection_type") else "unknown",
                "evidence": r.evidence[:200] if r.evidence else None,
            }
            for r in results
            if r.vulnerable
        ]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def xss_scan(url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """XSS漏洞检测 - 检测跨站脚本攻击漏洞

        支持: 反射型XSS、存储型XSS、DOM型XSS

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            XSS检测结果
        """
        from core.detectors import XSSDetector

        detector = XSSDetector()
        results = await detector.async_detect(url, params=params or {})

        findings = [
            {
                "param": r.param,
                "payload": r.payload,
                "context": r.context if hasattr(r, "context") else None,
                "evidence": r.evidence[:200] if r.evidence else None,
            }
            for r in results
            if r.vulnerable
        ]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def ssrf_scan(url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """SSRF漏洞检测 - 检测服务端请求伪造漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            SSRF检测结果
        """
        from core.detectors import SSRFDetector

        detector = SSRFDetector()
        results = await detector.async_detect(url, params=params or {})

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def rce_scan(url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """命令注入检测 - 检测远程命令执行漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            RCE检测结果
        """
        from core.detectors import RCEDetector

        detector = RCEDetector()
        results = await detector.async_detect(url, params=params or {})

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def path_traversal_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """路径遍历检测 - 检测目录遍历/LFI漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            路径遍历检测结果
        """
        from core.detectors import PathTraversalDetector

        detector = PathTraversalDetector()
        results = await detector.async_detect(url, params=params or {})

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def ssti_scan(url: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """模板注入检测 - 检测服务端模板注入漏洞

        支持: Jinja2, Twig, Freemarker, Velocity等模板引擎

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            SSTI检测结果
        """
        from core.detectors import SSTIDetector

        detector = SSTIDetector()
        results = await detector.async_detect(url, params=params or {})

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def xxe_scan(url: str, content_type: str = "application/xml") -> Dict[str, Any]:
        """XXE漏洞检测 - 检测XML外部实体注入漏洞

        Args:
            url: 目标URL (接受XML输入的端点)
            content_type: Content-Type头

        Returns:
            XXE检测结果
        """
        from core.detectors import XXEDetector

        detector = XXEDetector()
        results = await detector.async_detect(url, content_type=content_type)

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def idor_scan(
        url: str, id_param: str = "id", test_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """IDOR漏洞检测 - 检测不安全的直接对象引用

        Args:
            url: 目标URL
            id_param: ID参数名
            test_ids: 要测试的ID列表

        Returns:
            IDOR检测结果
        """
        from core.detectors import IDORDetector

        detector = IDORDetector()
        results = await detector.async_detect(url, id_param=id_param, test_ids=test_ids)

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def cors_scan(url: str) -> Dict[str, Any]:
        """CORS配置检测 - 检测跨域资源共享配置问题

        检测: 通配符源、凭据泄露、Origin反射等

        Args:
            url: 目标URL

        Returns:
            CORS检测结果
        """
        from core.detectors import CORSDetector

        detector = CORSDetector()
        results = await detector.async_detect(url)

        findings = [r.to_dict() for r in results if r.vulnerable]

        return {"success": True, "vulnerable": len(findings) > 0, "url": url, "findings": findings}

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def security_headers_scan(url: str) -> Dict[str, Any]:
        """安全头检测 - 检测HTTP安全响应头配置

        检测: CSP, X-Frame-Options, X-XSS-Protection, HSTS等

        Args:
            url: 目标URL

        Returns:
            安全头检测结果
        """
        from core.detectors import SecurityHeadersDetector

        detector = SecurityHeadersDetector()
        results = await detector.async_detect(url)

        return {"success": True, "url": url, "findings": [r.to_dict() for r in results]}

    # ── 以下为新增的 10 个休眠检测器 ──

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def ldap_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """LDAP注入检测 - 检测LDAP注入漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            LDAP注入检测结果
        """
        from core.detectors.injection.ldap import LDAPiDetector

        detector = LDAPiDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def open_redirect_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """开放重定向检测 - 检测URL重定向漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            开放重定向检测结果
        """
        from core.detectors.access.open_redirect import OpenRedirectDetector

        detector = OpenRedirectDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def info_disclosure_scan(url: str) -> Dict[str, Any]:
        """信息泄露检测 - 检测敏感信息泄露

        检测: 错误信息泄露、目录列表、敏感文件暴露等

        Args:
            url: 目标URL

        Returns:
            信息泄露检测结果
        """
        from core.detectors.misc.info_disclosure import InfoDisclosureDetector

        detector = InfoDisclosureDetector()
        results = await detector.async_detect(url)
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def csrf_scan(
        url: str, data: Optional[Dict[str, str]] = None, method: str = "POST"
    ) -> Dict[str, Any]:
        """CSRF跨站请求伪造检测 - 检测CSRF防护缺失或配置问题

        Args:
            url: 目标URL
            data: POST数据
            method: HTTP方法 (POST/PUT/DELETE/PATCH)

        Returns:
            CSRF检测结果
        """
        from core.detectors.misc.csrf import CSRFDetector

        detector = CSRFDetector()
        results = await detector.async_detect(url, data=data or {}, method=method)
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def auth_bypass_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """认证绕过检测 - 检测身份认证绕过漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            认证绕过检测结果
        """
        from core.detectors.auth.auth_bypass import AuthBypassDetector

        detector = AuthBypassDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def weak_password_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """弱密码检测 - 检测弱密码和默认凭据

        Args:
            url: 目标URL
            params: 请求参数 (例: {"username_field": "user", "password_field": "pass"})

        Returns:
            弱密码检测结果
        """
        from core.detectors.auth.weak_password import WeakPasswordDetector

        detector = WeakPasswordDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def session_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """会话安全检测 - 检测会话管理漏洞

        检测: 会话固定、会话劫持、Cookie安全属性缺失等

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            会话安全检测结果
        """
        from core.detectors.auth.session import SessionDetector

        detector = SessionDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def upload_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """文件上传漏洞检测 - 检测文件上传安全问题

        检测: 文件类型绕过、路径穿越、恶意文件上传等

        Args:
            url: 目标URL (文件上传端点)
            params: 请求参数

        Returns:
            文件上传漏洞检测结果
        """
        from core.detectors.file.upload import FileUploadDetector

        detector = FileUploadDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def lfi_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """本地文件包含检测 - 检测LFI漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            LFI检测结果
        """
        from core.detectors.file.lfi import LFIDetector

        detector = LFIDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def deserialize_scan(
        url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """反序列化漏洞检测 - 检测不安全的反序列化

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            反序列化漏洞检测结果
        """
        from core.detectors.injection.deserialize import DeserializeDetector

        detector = DeserializeDetector()
        results = await detector.async_detect(url, params=params or {})
        findings = [r.to_dict() for r in results if r.vulnerable]
        return {
            "success": True,
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_checks": len(results),
        }

    counter.add("detector", 1)

    counter.add("detector", 11)
    logger.info("[Detector] 已注册 21 个漏洞检测工具")
