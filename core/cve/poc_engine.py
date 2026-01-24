#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC 执行引擎
兼容 Nuclei YAML 格式，支持漏洞验证

作者: AutoRedTeam-Orchestrator
"""

import re
import random
import string
import logging
import time
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .models import PoCTemplate, PoCMatcher, PoCExtractor, Severity

logger = logging.getLogger(__name__)

# YAML 支持
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("yaml 库未安装，无法加载 YAML 格式的 PoC 模板")

# HTTP 客户端
try:
    from core.http import get_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class PoCResult:
    """PoC 执行结果"""
    success: bool                              # 执行是否成功
    vulnerable: bool                           # 是否存在漏洞
    template_id: str                           # 模板 ID
    template_name: str = ''                    # 模板名称
    target: str = ''                           # 目标地址
    matched: bool = False                      # 是否匹配成功
    matcher_name: str = ''                     # 匹配的 Matcher 名称
    extracted: Dict[str, Any] = field(default_factory=dict)  # 提取的数据
    evidence: str = ''                         # 证据
    request: Optional[Dict[str, Any]] = None   # 请求详情
    response: Optional[Dict[str, Any]] = None  # 响应详情
    error: Optional[str] = None                # 错误信息
    execution_time_ms: float = 0               # 执行时间 (毫秒)
    timestamp: str = ''                        # 时间戳

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'success': self.success,
            'vulnerable': self.vulnerable,
            'template_id': self.template_id,
            'template_name': self.template_name,
            'target': self.target,
            'matched': self.matched,
            'matcher_name': self.matcher_name,
            'extracted': self.extracted,
            'evidence': self.evidence,
            'request': self.request,
            'response': self.response,
            'error': self.error,
            'execution_time_ms': self.execution_time_ms,
            'timestamp': self.timestamp,
        }


class VariableReplacer:
    """变量替换器"""

    # 内置变量模式
    VARIABLE_PATTERN = re.compile(r'\{\{([^}]+)\}\}')

    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    @staticmethod
    def generate_random_int(min_val: int = 1, max_val: int = 999999) -> int:
        """生成随机整数"""
        return random.randint(min_val, max_val)

    @staticmethod
    def generate_interactsh_url() -> str:
        """生成 Interactsh URL (模拟)"""
        random_id = VariableReplacer.generate_random_string(20)
        return f"{random_id}.oast.fun"

    @classmethod
    def replace(
        cls,
        text: str,
        base_url: str,
        custom_vars: Optional[Dict[str, str]] = None
    ) -> str:
        """
        替换文本中的变量

        支持的变量:
        - {{BaseURL}}: 完整的基础 URL
        - {{RootURL}}: 根 URL (不含路径)
        - {{Hostname}}: 主机名
        - {{Host}}: 主机 (可能含端口)
        - {{Port}}: 端口
        - {{Path}}: 路径
        - {{Scheme}}: 协议 (http/https)
        - {{randstr}}: 随机字符串
        - {{rand_int(min, max)}}: 随机整数
        - {{interactsh-url}}: Interactsh URL

        Args:
            text: 原始文本
            base_url: 基础 URL
            custom_vars: 自定义变量

        Returns:
            替换后的文本
        """
        if not text:
            return text

        custom_vars = custom_vars or {}

        # 解析 URL
        parsed = urlparse(base_url)
        hostname = parsed.hostname or ''
        host = parsed.netloc or ''
        port = str(parsed.port) if parsed.port else ('443' if parsed.scheme == 'https' else '80')
        path = parsed.path or '/'
        scheme = parsed.scheme or 'http'
        root_url = f"{scheme}://{host}"

        # 内置变量映射
        builtin_vars = {
            'BaseURL': base_url.rstrip('/'),
            'RootURL': root_url,
            'Hostname': hostname,
            'Host': host,
            'Port': port,
            'Path': path,
            'Scheme': scheme,
            'randstr': cls.generate_random_string(),
            'interactsh-url': cls.generate_interactsh_url(),
        }

        # 合并自定义变量 (优先级更高)
        variables = {**builtin_vars, **custom_vars}

        result = text

        # 替换所有变量
        def replacer(match):
            var_name = match.group(1).strip()

            # 处理 rand_int 函数
            rand_int_match = re.match(r'rand_int\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', var_name)
            if rand_int_match:
                min_val = int(rand_int_match.group(1))
                max_val = int(rand_int_match.group(2))
                return str(cls.generate_random_int(min_val, max_val))

            # 普通变量替换
            return variables.get(var_name, match.group(0))

        result = cls.VARIABLE_PATTERN.sub(replacer, result)

        return result


class PoCEngine:
    """
    PoC 执行引擎 - 兼容 Nuclei 格式

    特性:
    - 支持 YAML 格式的 PoC 模板
    - 变量替换
    - 多种 Matcher 类型 (word, regex, status, size)
    - Extractor 支持
    - 并发执行
    """

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
        max_redirects: int = 10
    ):
        """
        初始化 PoC 引擎

        Args:
            timeout: 请求超时时间 (秒)
            verify_ssl: 是否验证 SSL 证书
            proxy: 代理地址
            max_redirects: 最大重定向次数
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.max_redirects = max_redirects

        # 模板缓存
        self._templates: Dict[str, PoCTemplate] = {}
        self._templates_lock = threading.Lock()

        # HTTP 会话
        self._session = None

        logger.info("[PoCEngine] 初始化完成")

    def _get_session(self):
        """获取 HTTP 会话"""
        if self._session is None:
            if HAS_HTTP_FACTORY:
                self._session = get_client()
            elif HAS_REQUESTS:
                import requests
                self._session = requests.Session()
                self._session.verify = self.verify_ssl
                if self.proxy:
                    self._session.proxies = {
                        'http': self.proxy,
                        'https': self.proxy
                    }

        return self._session

    def load_template(self, path: str) -> Optional[PoCTemplate]:
        """
        从文件加载 PoC 模板

        Args:
            path: 模板文件路径

        Returns:
            PoC 模板或 None
        """
        if not HAS_YAML:
            logger.error("[PoCEngine] 需要安装 pyyaml 库")
            return None

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            template = PoCTemplate.from_dict(data)

            # 缓存模板
            with self._templates_lock:
                self._templates[template.id] = template

            logger.debug(f"[PoCEngine] 加载模板: {template.id}")
            return template

        except Exception as e:
            logger.error(f"[PoCEngine] 加载模板失败 {path}: {e}")
            return None

    def load_template_from_dict(self, data: Dict[str, Any]) -> Optional[PoCTemplate]:
        """
        从字典加载 PoC 模板

        Args:
            data: 模板数据

        Returns:
            PoC 模板或 None
        """
        try:
            template = PoCTemplate.from_dict(data)

            with self._templates_lock:
                self._templates[template.id] = template

            return template

        except Exception as e:
            logger.error(f"[PoCEngine] 解析模板失败: {e}")
            return None

    def load_template_from_yaml(self, yaml_str: str) -> Optional[PoCTemplate]:
        """
        从 YAML 字符串加载模板

        Args:
            yaml_str: YAML 字符串

        Returns:
            PoC 模板或 None
        """
        if not HAS_YAML:
            logger.error("[PoCEngine] 需要安装 pyyaml 库")
            return None

        try:
            data = yaml.safe_load(yaml_str)
            return self.load_template_from_dict(data)

        except Exception as e:
            logger.error(f"[PoCEngine] 解析 YAML 失败: {e}")
            return None

    def get_template(self, template_id: str) -> Optional[PoCTemplate]:
        """获取缓存的模板"""
        with self._templates_lock:
            return self._templates.get(template_id)

    def list_templates(self) -> List[str]:
        """列出所有已加载的模板"""
        with self._templates_lock:
            return list(self._templates.keys())

    def execute(
        self,
        target: str,
        template: PoCTemplate,
        variables: Optional[Dict[str, str]] = None
    ) -> PoCResult:
        """
        执行 PoC

        Args:
            target: 目标 URL
            template: PoC 模板
            variables: 自定义变量

        Returns:
            执行结果
        """
        start_time = time.time()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        try:
            # 获取要测试的路径
            paths = template.paths if template.paths else [template.path]

            for path in paths:
                # 变量替换
                replaced_path = VariableReplacer.replace(path, target, variables)

                # 构建完整 URL
                if replaced_path.startswith('http'):
                    url = replaced_path
                else:
                    url = urljoin(target.rstrip('/') + '/', replaced_path.lstrip('/'))

                # 替换请求头中的变量
                headers = {}
                for key, value in template.headers.items():
                    headers[key] = VariableReplacer.replace(value, target, variables)

                # 替换请求体中的变量
                body = None
                if template.body:
                    body = VariableReplacer.replace(template.body, target, variables)

                # 发送请求
                response = self._send_request(
                    method=template.method,
                    url=url,
                    headers=headers,
                    body=body,
                    redirect=template.redirect
                )

                if response is None:
                    continue

                status_code, resp_body, resp_headers = response

                # 检查 Matchers
                matched, matcher_name, evidence = self._check_matchers(
                    template.matchers,
                    template.matchers_condition,
                    status_code,
                    resp_body,
                    resp_headers
                )

                if matched:
                    # 运行 Extractors
                    extracted = self._run_extractors(
                        template.extractors,
                        resp_body,
                        resp_headers
                    )

                    execution_time = (time.time() - start_time) * 1000

                    return PoCResult(
                        success=True,
                        vulnerable=True,
                        template_id=template.id,
                        template_name=template.name,
                        target=target,
                        matched=True,
                        matcher_name=matcher_name,
                        extracted=extracted,
                        evidence=evidence[:500],  # 限制长度
                        request={
                            'method': template.method,
                            'url': url,
                            'headers': headers,
                            'body': body
                        },
                        response={
                            'status_code': status_code,
                            'headers': dict(resp_headers),
                            'body_length': len(resp_body)
                        },
                        execution_time_ms=execution_time,
                        timestamp=timestamp
                    )

                # 如果设置了 stop_at_first_match，继续检查其他路径
                if not template.stop_at_first_match:
                    continue

            # 所有路径都未匹配
            execution_time = (time.time() - start_time) * 1000

            return PoCResult(
                success=True,
                vulnerable=False,
                template_id=template.id,
                template_name=template.name,
                target=target,
                matched=False,
                execution_time_ms=execution_time,
                timestamp=timestamp
            )

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(f"[PoCEngine] 执行失败: {e}")

            return PoCResult(
                success=False,
                vulnerable=False,
                template_id=template.id,
                template_name=template.name,
                target=target,
                error=str(e),
                execution_time_ms=execution_time,
                timestamp=timestamp
            )

    def execute_batch(
        self,
        targets: List[str],
        template: PoCTemplate,
        variables: Optional[Dict[str, str]] = None,
        concurrency: int = 10
    ) -> List[PoCResult]:
        """
        批量执行 PoC

        Args:
            targets: 目标 URL 列表
            template: PoC 模板
            variables: 自定义变量
            concurrency: 并发数

        Returns:
            执行结果列表
        """
        import concurrent.futures

        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {
                executor.submit(self.execute, target, template, variables): target
                for target in targets
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    target = futures[future]
                    results.append(PoCResult(
                        success=False,
                        vulnerable=False,
                        template_id=template.id,
                        template_name=template.name,
                        target=target,
                        error=str(e),
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                    ))

        return results

    def _send_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        redirect: bool = True
    ) -> Optional[Tuple[int, str, Dict[str, str]]]:
        """
        发送 HTTP 请求

        Args:
            method: HTTP 方法
            url: URL
            headers: 请求头
            body: 请求体
            redirect: 是否跟随重定向

        Returns:
            (状态码, 响应体, 响应头) 或 None
        """
        session = self._get_session()
        if not session:
            logger.error("[PoCEngine] 无可用的 HTTP 客户端")
            return None

        try:
            method = method.upper()

            if HAS_HTTP_FACTORY:
                # 使用统一 HTTP 客户端
                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    allow_redirects=redirect
                )
                return (
                    response.status_code,
                    response.text,
                    dict(response.headers)
                )

            elif HAS_REQUESTS:
                # 使用 requests
                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    allow_redirects=redirect
                )
                return (
                    response.status_code,
                    response.text,
                    dict(response.headers)
                )

        except Exception as e:
            logger.debug(f"[PoCEngine] 请求失败 {url}: {e}")
            return None

    def _check_matchers(
        self,
        matchers: List[PoCMatcher],
        condition: str,
        status_code: int,
        body: str,
        headers: Dict[str, str]
    ) -> Tuple[bool, str, str]:
        """
        检查 Matchers

        Args:
            matchers: Matcher 列表
            condition: 条件 (and/or)
            status_code: 状态码
            body: 响应体
            headers: 响应头

        Returns:
            (是否匹配, Matcher 名称, 证据)
        """
        if not matchers:
            return (False, '', '')

        results = []
        matched_name = ''
        evidence = ''

        for matcher in matchers:
            matched, ev = self._check_single_matcher(
                matcher, status_code, body, headers
            )

            if matcher.negative:
                matched = not matched

            results.append(matched)

            if matched:
                matched_name = matcher.type
                evidence = ev

        # 条件判断
        if condition.lower() == 'and':
            final_matched = all(results) if results else False
        else:  # or
            final_matched = any(results) if results else False

        return (final_matched, matched_name, evidence)

    def _check_single_matcher(
        self,
        matcher: PoCMatcher,
        status_code: int,
        body: str,
        headers: Dict[str, str]
    ) -> Tuple[bool, str]:
        """
        检查单个 Matcher

        Args:
            matcher: Matcher
            status_code: 状态码
            body: 响应体
            headers: 响应头

        Returns:
            (是否匹配, 证据)
        """
        # 确定检查的内容
        if matcher.part == 'header':
            content = '\n'.join(f'{k}: {v}' for k, v in headers.items())
        elif matcher.part == 'status':
            content = str(status_code)
        elif matcher.part == 'all':
            header_str = '\n'.join(f'{k}: {v}' for k, v in headers.items())
            content = f"Status: {status_code}\n{header_str}\n\n{body}"
        else:  # body
            content = body

        # 是否忽略大小写
        if matcher.case_insensitive:
            content = content.lower()

        matcher_type = matcher.type.lower() if isinstance(matcher.type, str) else matcher.type

        # Word 匹配
        if matcher_type == 'word':
            words = matcher.words
            if matcher.case_insensitive:
                words = [w.lower() for w in words]

            if matcher.condition.lower() == 'and':
                matched = all(w in content for w in words)
            else:
                matched = any(w in content for w in words)

            if matched:
                matched_words = [w for w in words if w in content]
                return (True, f"Matched words: {', '.join(matched_words[:3])}")

        # Regex 匹配
        elif matcher_type == 'regex':
            for pattern in matcher.regex:
                flags = re.IGNORECASE if matcher.case_insensitive else 0
                match = re.search(pattern, content, flags)
                if match:
                    return (True, f"Regex matched: {match.group(0)[:100]}")

        # Status 匹配
        elif matcher_type == 'status':
            if status_code in matcher.status:
                return (True, f"Status code: {status_code}")

        return (False, '')

    def _run_extractors(
        self,
        extractors: List[PoCExtractor],
        body: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        运行 Extractors

        Args:
            extractors: Extractor 列表
            body: 响应体
            headers: 响应头

        Returns:
            提取的数据
        """
        extracted = {}

        for extractor in extractors:
            if extractor.internal:
                continue

            name = extractor.name or f"extractor_{len(extracted)}"

            # 确定内容
            if extractor.part == 'header':
                content = '\n'.join(f'{k}: {v}' for k, v in headers.items())
            else:
                content = body

            extractor_type = extractor.type.lower() if isinstance(extractor.type, str) else extractor.type

            # Regex 提取
            if extractor_type == 'regex':
                for pattern in extractor.regex:
                    match = re.search(pattern, content)
                    if match:
                        if match.groups():
                            extracted[name] = match.group(extractor.group) if len(match.groups()) >= extractor.group else match.group(0)
                        else:
                            extracted[name] = match.group(0)
                        break

            # JSON 提取
            elif extractor_type == 'json':
                try:
                    import json
                    data = json.loads(body)
                    for json_path in extractor.json_path:
                        value = self._extract_json_path(data, json_path)
                        if value is not None:
                            extracted[name] = value
                            break
                except (ValueError, TypeError):
                    pass

        return extracted

    def _extract_json_path(self, data: Any, path: str) -> Any:
        """
        简单的 JSON 路径提取

        Args:
            data: JSON 数据
            path: 路径 (如 .data.user.name)

        Returns:
            提取的值或 None
        """
        if not path or not data:
            return None

        parts = path.lstrip('.').split('.')
        current = data

        for part in parts:
            if not part:
                continue

            # 数组索引
            array_match = re.match(r'(\w+)\[(\d+)\]', part)
            if array_match:
                key = array_match.group(1)
                index = int(array_match.group(2))
                if isinstance(current, dict) and key in current:
                    current = current[key]
                    if isinstance(current, list) and len(current) > index:
                        current = current[index]
                    else:
                        return None
                else:
                    return None
            else:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None

        return current

    def close(self):
        """关闭引擎"""
        if self._session and HAS_REQUESTS and hasattr(self._session, 'close'):
            self._session.close()
            self._session = None

        logger.debug("[PoCEngine] 已关闭")


# 全局引擎实例
_engine: Optional[PoCEngine] = None
_engine_lock = threading.Lock()


def get_poc_engine(
    timeout: int = 10,
    verify_ssl: bool = False,
    proxy: Optional[str] = None
) -> PoCEngine:
    """
    获取全局 PoC 引擎

    Args:
        timeout: 超时时间
        verify_ssl: 是否验证 SSL
        proxy: 代理地址

    Returns:
        PoC 引擎实例
    """
    global _engine

    with _engine_lock:
        if _engine is None:
            _engine = PoCEngine(
                timeout=timeout,
                verify_ssl=verify_ssl,
                proxy=proxy
            )

    return _engine


def reset_poc_engine():
    """重置全局 PoC 引擎"""
    global _engine

    with _engine_lock:
        if _engine:
            _engine.close()
            _engine = None


# 便捷函数
def load_poc(path: str) -> Optional[PoCTemplate]:
    """加载 PoC 模板"""
    engine = get_poc_engine()
    return engine.load_template(path)


def execute_poc(
    target: str,
    template: PoCTemplate,
    variables: Optional[Dict[str, str]] = None
) -> PoCResult:
    """执行 PoC"""
    engine = get_poc_engine()
    return engine.execute(target, template, variables)


def execute_poc_batch(
    targets: List[str],
    template: PoCTemplate,
    variables: Optional[Dict[str, str]] = None,
    concurrency: int = 10
) -> List[PoCResult]:
    """批量执行 PoC"""
    engine = get_poc_engine()
    return engine.execute_batch(targets, template, variables, concurrency)


# CLI 入口
if __name__ == '__main__':
    import sys

    print("PoC Engine Test")
    print("=" * 50)

    # 示例模板
    sample_template_data = {
        'id': 'test-poc',
        'info': {
            'name': 'Test PoC Template',
            'author': 'test',
            'severity': 'medium',
            'description': 'A test PoC template',
        },
        'method': 'GET',
        'path': '/',
        'matchers': [
            {
                'type': 'status',
                'status': [200, 301, 302]
            }
        ]
    }

    engine = PoCEngine()
    template = engine.load_template_from_dict(sample_template_data)

    if template:
        print(f"[+] 加载模板: {template.id}")
        print(f"    名称: {template.name}")
        print(f"    严重性: {template.severity.value}")

    # 变量替换测试
    print("\n[+] 变量替换测试:")
    test_url = "https://example.com:8443/api/v1"
    test_text = "URL: {{BaseURL}}, Host: {{Host}}, Random: {{randstr}}"
    replaced = VariableReplacer.replace(test_text, test_url)
    print(f"    原始: {test_text}")
    print(f"    替换: {replaced}")

    # 如果提供了目标，执行测试
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"\n[+] 执行测试: {target}")

        if template:
            result = engine.execute(target, template)
            print(f"    成功: {result.success}")
            print(f"    漏洞: {result.vulnerable}")
            print(f"    耗时: {result.execution_time_ms:.1f}ms")

            if result.error:
                print(f"    错误: {result.error}")
