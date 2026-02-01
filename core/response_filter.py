#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
响应过滤器 - SPA检测、内容去重、基线对比
解决 sensitive_scan / auth_bypass_detect 的误报问题
"""

import hashlib
import re
import uuid
from typing import Dict, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None


class ResponseFilter:
    """智能响应过滤器 - 增强版"""

    # SPA 框架特征标记 - 扩展版
    SPA_MARKERS = [
        # React
        '<div id="root">',
        "data-reactroot",
        "__REACT_DEVTOOLS",
        "react-dom",
        "_reactRootContainer",
        "data-reactid",
        # Vue
        '<div id="app">',
        "data-v-",
        "__VUE__",
        "vue-router",
        "vuex",
        "v-cloak",
        "v-if",
        "v-for",
        # Next.js
        "__NEXT_DATA__",
        "_next/static",
        "next-head",
        "__N_SSP",
        "__N_SSG",
        "next-route-loader",
        # Nuxt.js
        "window.__NUXT__",
        "__nuxt",
        "_nuxt/",
        "nuxt-link",
        # Angular
        "ng-version",
        "<app-root>",
        "ng-app",
        "ng-controller",
        "angular.min.js",
        "ng-model",
        "ng-click",
        # Svelte
        "__svelte",
        "svelte-",
        "svelte-kit",
        # Remix
        "__remixContext",
        "__remixManifest",
        # SolidJS
        "solid-js",
        "_$owner",
        # 通用 SPA 特征
        "window.__INITIAL_STATE__",
        "window.__PRELOADED_STATE__",
        "window.__APP_STATE__",
        "hydrate",
        "window.__DATA__",
        'application/json" id="__',
        "__APOLLO_STATE__",
        "window.__REDUX_STATE__",
        "window.__STORE__",
    ]

    # 登录页特征 - 扩展版
    LOGIN_MARKERS = [
        'type="password"',
        'name="password"',
        "login",
        "signin",
        "sign in",
        "登录",
        "登陆",
        "登入",
        "username",
        "email",
        "forgot password",
        "忘记密码",
        "remember me",
        "记住我",
        "create account",
        "注册",
        "oauth",
        "sso",
        "single sign-on",
        "统一登录",
        "two-factor",
        "双因素",
        "mfa",
        "authenticator",
        "captcha",
        "验证码",
        "verification code",
    ]

    # 错误页特征 - 扩展版
    ERROR_MARKERS = [
        "404",
        "not found",
        "page not found",
        "file not found",
        "403",
        "forbidden",
        "access denied",
        "unauthorized",
        "500",
        "internal server error",
        "server error",
        "502",
        "bad gateway",
        "503",
        "service unavailable",
        "页面不存在",
        "访问被拒绝",
        "服务器错误",
        "无权限",
        "error occurred",
        "something went wrong",
        "出错了",
        "page does not exist",
        "页面未找到",
        "资源不存在",
    ]

    # 通用页面特征 - 用于检测误报
    GENERIC_PAGE_MARKERS = [
        "under construction",
        "建设中",
        "coming soon",
        "即将上线",
        "maintenance",
        "维护中",
        "temporarily unavailable",
        "please wait",
        "请稍候",
        "loading...",
        "加载中",
    ]

    def __init__(self, verify_ssl: bool = False, timeout: int = 5):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.baseline_cache: Dict[str, dict] = {}  # host -> baseline info
        self.response_hashes: Dict[str, set] = {}  # host -> seen hashes

    def calibrate(self, base_url: str) -> dict:
        """
        校准基线 - 获取目标的标准404响应和首页响应

        Args:
            base_url: 目标基础URL

        Returns:
            基线信息字典
        """
        if not requests:
            return {"error": "requests not installed"}

        base_url = base_url.rstrip("/")
        host = self._extract_host(base_url)

        baseline = {
            "host": host,
            "404_hash": None,
            "404_length": 0,
            "home_hash": None,
            "home_length": 0,
            "is_spa": False,
            "spa_markers_found": [],
        }

        try:
            # 1. 获取随机路径响应 (模拟404)
            random_path = f"/rand_{uuid.uuid4().hex[:12]}_notexist"
            resp_404 = requests.get(
                base_url + random_path,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            baseline["404_hash"] = self._compute_hash(resp_404.text)
            baseline["404_length"] = len(resp_404.text)
            baseline["404_status"] = resp_404.status_code

            # 2. 获取首页响应
            resp_home = requests.get(
                base_url + "/", timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True
            )
            baseline["home_hash"] = self._compute_hash(resp_home.text)
            baseline["home_length"] = len(resp_home.text)

            # 3. 检测是否为SPA
            spa_check = self.detect_spa(resp_home.text)
            baseline["is_spa"] = spa_check["is_spa"]
            baseline["spa_markers_found"] = spa_check["markers_found"]

            # 4. 如果404返回200且内容与首页相似，确认为SPA fallback
            if resp_404.status_code == 200:
                similarity = self._compute_similarity(resp_404.text, resp_home.text)
                if similarity > 0.8:
                    baseline["is_spa"] = True
                    baseline["spa_fallback_confirmed"] = True

        except Exception as e:
            baseline["error"] = str(e)

        self.baseline_cache[host] = baseline
        return baseline

    def detect_spa(self, html: str) -> dict:
        """
        检测HTML是否为SPA应用

        Args:
            html: HTML内容

        Returns:
            {"is_spa": bool, "markers_found": list}
        """
        html_lower = html.lower()
        markers_found = []

        for marker in self.SPA_MARKERS:
            if marker.lower() in html_lower:
                markers_found.append(marker)

        return {
            "is_spa": len(markers_found) >= 1,
            "markers_found": markers_found,
            "confidence": min(len(markers_found) / 3, 1.0),
        }

    def is_login_page(self, html: str) -> bool:
        """检测是否为登录页"""
        html_lower = html.lower()
        matches = sum(1 for m in self.LOGIN_MARKERS if m.lower() in html_lower)
        return matches >= 2

    def is_error_page(self, html: str) -> bool:
        """检测是否为错误页"""
        html_lower = html.lower()
        return any(m.lower() in html_lower for m in self.ERROR_MARKERS)

    def is_spa_fallback(self, url: str, html: str, status_code: int = 200) -> Tuple[bool, str]:
        """
        判断响应是否为SPA fallback

        Args:
            url: 请求URL
            html: 响应HTML
            status_code: HTTP状态码

        Returns:
            (is_fallback, reason)
        """
        host = self._extract_host(url)
        baseline = self.baseline_cache.get(host)

        # 1. 检查SPA标记
        spa_check = self.detect_spa(html)
        if spa_check["is_spa"] and spa_check["confidence"] > 0.5:
            return True, f"SPA markers found: {spa_check['markers_found']}"

        # 2. 与基线对比
        if baseline:
            current_hash = self._compute_hash(html)

            # 与404基线对比
            if baseline.get("404_hash") == current_hash:
                return True, "Content matches 404 baseline"

            # 与首页对比
            if baseline.get("home_hash") == current_hash:
                return True, "Content matches home page"

            # 长度相似度对比
            if baseline.get("404_length"):
                length_ratio = len(html) / baseline["404_length"]
                if 0.9 < length_ratio < 1.1:
                    # 与404基线内容比较（需要缓存404响应内容）
                    return True, "Content length similar to 404 baseline"

        # 3. 检查是否为空壳页面 (只有框架没有内容)
        if self._is_empty_shell(html):
            return True, "Empty shell page detected"

        return False, ""

    def is_duplicate(self, url: str, html: str) -> bool:
        """
        检查响应是否重复

        Args:
            url: 请求URL
            html: 响应HTML

        Returns:
            是否为重复响应
        """
        host = self._extract_host(url)
        content_hash = self._compute_hash(html)

        if host not in self.response_hashes:
            self.response_hashes[host] = set()

        if content_hash in self.response_hashes[host]:
            return True

        self.response_hashes[host].add(content_hash)
        return False

    def validate_sensitive_file(
        self, url: str, html: str, path: str, status_code: int, content_type: str = ""
    ) -> dict:
        """
        验证敏感文件是否为真实发现 - 增强版

        Args:
            url: 完整URL
            html: 响应内容
            path: 请求路径
            status_code: HTTP状态码
            content_type: Content-Type头

        Returns:
            {"valid": bool, "reason": str, "confidence": float}
        """
        result = {"valid": False, "reason": "", "confidence": 0.0}

        # 1. 状态码检查
        if status_code != 200:
            result["reason"] = f"Non-200 status: {status_code}"
            return result

        # 2. 内容长度检查 - 过短可能是空页面
        if len(html) < 50:
            result["reason"] = "Response too short, likely empty"
            return result

        # 3. 检查是否为通用页面（维护页、建设中等）
        html_lower = html.lower()
        generic_matches = sum(1 for m in self.GENERIC_PAGE_MARKERS if m.lower() in html_lower)
        if generic_matches >= 1:
            result["reason"] = f"Generic page detected: {generic_matches} markers found"
            return result

        # 4. SPA fallback 检查
        is_fallback, fallback_reason = self.is_spa_fallback(url, html, status_code)
        if is_fallback:
            result["reason"] = f"SPA fallback: {fallback_reason}"
            return result

        # 3. 重复检查
        if self.is_duplicate(url, html):
            result["reason"] = "Duplicate response"
            return result

        # 4. Content-Type 验证
        expected_types = self._get_expected_content_type(path)
        if content_type and expected_types:
            if not any(et in content_type.lower() for et in expected_types):
                result["reason"] = f"Content-Type mismatch: {content_type}"
                result["confidence"] = 0.3
                result["valid"] = True  # 降低置信度但仍报告
                return result

        # 5. 内容特征验证
        if self._validate_content_signature(html, path):
            result["valid"] = True
            result["confidence"] = 0.9
            result["reason"] = "Content signature matched"
        else:
            result["valid"] = True
            result["confidence"] = 0.5
            result["reason"] = "Basic validation passed"

        return result

    def validate_auth_bypass(
        self, url: str, html: str, baseline_html: str, status_code: int
    ) -> dict:
        """
        验证认证绕过是否为真实漏洞

        Args:
            url: 请求URL
            html: 绕过尝试的响应
            baseline_html: 基线响应 (正常访问admin的响应)
            status_code: HTTP状态码

        Returns:
            {"valid": bool, "reason": str, "confidence": float}
        """
        result = {"valid": False, "reason": "", "confidence": 0.0}

        # 1. 状态码检查
        if status_code != 200:
            result["reason"] = f"Non-200 status: {status_code}"
            return result

        # 2. SPA fallback 检查
        is_fallback, fallback_reason = self.is_spa_fallback(url, html, status_code)
        if is_fallback:
            result["reason"] = f"SPA fallback: {fallback_reason}"
            return result

        # 3. 登录页检查
        if self.is_login_page(html):
            result["reason"] = "Response is login page"
            return result

        # 4. 与基线对比
        if baseline_html:
            similarity = self._compute_similarity(html, baseline_html)
            if similarity > 0.9:
                result["reason"] = "Response same as baseline (no bypass)"
                return result

        # 5. 检查是否包含管理员特征
        admin_markers = ["dashboard", "admin", "panel", "manage", "管理", "控制台"]
        html_lower = html.lower()
        admin_found = sum(1 for m in admin_markers if m in html_lower)

        if admin_found >= 2:
            result["valid"] = True
            result["confidence"] = 0.8
            result["reason"] = "Admin content detected"
        elif admin_found == 1:
            result["valid"] = True
            result["confidence"] = 0.5
            result["reason"] = "Possible admin content"
        else:
            result["reason"] = "No admin content found"

        return result

    def _compute_hash(self, content: str) -> str:
        """计算内容哈希 (规范化后)"""
        # 移除空白字符和动态内容
        normalized = re.sub(r"\s+", "", content)
        normalized = re.sub(
            r'csrf[_-]?token["\']?\s*[:=]\s*["\'][^"\']+["\']', "", normalized, flags=re.I
        )
        normalized = re.sub(r'nonce["\']?\s*[:=]\s*["\'][^"\']+["\']', "", normalized, flags=re.I)
        return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _compute_similarity(self, text1: str, text2: str) -> float:
        """计算两个文本的相似度 (简化版Jaccard)"""
        if not text1 or not text2:
            return 0.0
        words1 = set(re.findall(r"\w+", text1.lower()))
        words2 = set(re.findall(r"\w+", text2.lower()))
        if not words1 or not words2:
            return 0.0
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return intersection / union if union > 0 else 0.0

    def _extract_host(self, url: str) -> str:
        """提取URL的host部分"""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _is_empty_shell(self, html: str) -> bool:
        """检测是否为空壳页面"""
        # 移除脚本和样式
        clean = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.I)
        clean = re.sub(r"<style[^>]*>.*?</style>", "", clean, flags=re.DOTALL | re.I)
        clean = re.sub(r"<[^>]+>", "", clean)
        clean = re.sub(r"\s+", "", clean)
        # 如果去除标签后内容很少，认为是空壳
        return len(clean) < 100

    def _get_expected_content_type(self, path: str) -> list:
        """根据路径获取期望的Content-Type"""
        ext_map = {
            ".json": ["application/json"],
            ".xml": ["application/xml", "text/xml"],
            ".txt": ["text/plain"],
            ".log": ["text/plain"],
            ".sql": ["text/plain", "application/sql"],
            ".env": ["text/plain"],
            ".yml": ["text/yaml", "application/yaml"],
            ".yaml": ["text/yaml", "application/yaml"],
            ".conf": ["text/plain"],
            ".config": ["text/plain", "application/xml"],
            ".bak": ["application/octet-stream"],
            ".zip": ["application/zip"],
            ".gz": ["application/gzip"],
        }
        for ext, types in ext_map.items():
            if path.lower().endswith(ext):
                return types
        return []

    def _validate_content_signature(self, content: str, path: str) -> bool:
        """验证内容签名是否匹配文件类型"""
        path_lower = path.lower()
        content_start = content[:500].strip()

        # JSON 文件
        if path_lower.endswith(".json"):
            return content_start.startswith(("{", "["))

        # XML 文件
        if path_lower.endswith(".xml"):
            return content_start.startswith("<?xml") or content_start.startswith("<")

        # SQL 文件
        if path_lower.endswith(".sql"):
            sql_keywords = ["select", "insert", "create", "drop", "alter", "--"]
            return any(kw in content_start.lower() for kw in sql_keywords)

        # 环境变量文件
        if ".env" in path_lower:
            return "=" in content_start and not content_start.startswith("<")

        # 配置文件
        if any(ext in path_lower for ext in [".conf", ".config", ".yml", ".yaml"]):
            return not content_start.startswith("<!DOCTYPE") and not content_start.startswith(
                "<html"
            )

        return True


# 全局单例
_filter_instance: Optional[ResponseFilter] = None


def get_response_filter() -> ResponseFilter:
    """获取全局响应过滤器实例"""
    global _filter_instance
    if _filter_instance is None:
        _filter_instance = ResponseFilter()
    return _filter_instance


def reset_response_filter():
    """重置全局响应过滤器"""
    global _filter_instance
    _filter_instance = None
