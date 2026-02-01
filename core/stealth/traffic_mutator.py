#!/usr/bin/env python3
"""
流量变异模块 - Traffic Mutator
功能: 请求特征伪装、流量人性化、规避WAF/IDS检测
"""

import hashlib
import logging
import random
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)


@dataclass
class MutationConfig:
    """变异配置"""

    # 时间变异
    min_delay: float = 0.5
    max_delay: float = 3.0
    jitter_factor: float = 0.3

    # Header变异
    rotate_ua: bool = True
    randomize_headers: bool = True
    add_noise_headers: bool = True

    # 参数变异
    shuffle_params: bool = True
    case_mutation: bool = True
    encoding_mutation: bool = True

    # 路径变异
    path_mutation: bool = True
    add_fake_params: bool = False


class UserAgentRotator:
    """User-Agent 轮换器"""

    # 真实浏览器 UA 库 (2024-2025)
    CHROME_UA = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    FIREFOX_UA = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    EDGE_UA = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]

    SAFARI_UA = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ]

    # 移动端 UA
    MOBILE_UA = [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    ]

    # 安全扫描器 UA (用于对比检测)
    SCANNER_UA = [
        "sqlmap/1.7",
        "Nikto/2.5.0",
        "Nessus/10.0",
    ]

    def __init__(self, browser_type: str = "mixed"):
        """
        Args:
            browser_type: chrome, firefox, edge, safari, mobile, mixed
        """
        self.browser_type = browser_type
        self._ua_pool = self._build_pool()
        self._current_idx = 0

    def _build_pool(self) -> List[str]:
        if self.browser_type == "chrome":
            return self.CHROME_UA
        elif self.browser_type == "firefox":
            return self.FIREFOX_UA
        elif self.browser_type == "edge":
            return self.EDGE_UA
        elif self.browser_type == "safari":
            return self.SAFARI_UA
        elif self.browser_type == "mobile":
            return self.MOBILE_UA
        else:  # mixed
            return self.CHROME_UA + self.FIREFOX_UA + self.EDGE_UA + self.SAFARI_UA

    def get_random(self) -> str:
        """获取随机 UA"""
        return random.choice(self._ua_pool)

    def get_next(self) -> str:
        """顺序获取 UA (轮换)"""
        ua = self._ua_pool[self._current_idx]
        self._current_idx = (self._current_idx + 1) % len(self._ua_pool)
        return ua

    def get_consistent(self, seed: str) -> str:
        """基于seed获取一致的UA (同一目标使用同一UA)"""
        idx = int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(self._ua_pool)
        return self._ua_pool[idx]


class HeaderMutator:
    """HTTP Header 变异器"""

    # 常见的合法 Headers
    ACCEPT_HEADERS = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    ]

    ACCEPT_LANGUAGE = [
        "en-US,en;q=0.9",
        "en-US,en;q=0.5",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    ]

    ACCEPT_ENCODING = [
        "gzip, deflate, br",
        "gzip, deflate",
        "gzip, deflate, br, zstd",
    ]

    # 噪声 Headers (增加指纹复杂度)
    NOISE_HEADERS = {
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    }

    def __init__(self, ua_rotator: Optional[UserAgentRotator] = None):
        self.ua_rotator = ua_rotator or UserAgentRotator()

    def generate_headers(
        self,
        base_headers: Optional[Dict[str, str]] = None,
        target_host: Optional[str] = None,
        add_noise: bool = True,
    ) -> Dict[str, str]:
        """生成伪装 Headers"""
        headers = base_headers.copy() if base_headers else {}

        # User-Agent
        if "User-Agent" not in headers:
            if target_host:
                headers["User-Agent"] = self.ua_rotator.get_consistent(target_host)
            else:
                headers["User-Agent"] = self.ua_rotator.get_random()

        # Accept headers
        if "Accept" not in headers:
            headers["Accept"] = random.choice(self.ACCEPT_HEADERS)

        if "Accept-Language" not in headers:
            headers["Accept-Language"] = random.choice(self.ACCEPT_LANGUAGE)

        if "Accept-Encoding" not in headers:
            headers["Accept-Encoding"] = random.choice(self.ACCEPT_ENCODING)

        # Host header
        if target_host and "Host" not in headers:
            headers["Host"] = target_host

        # 添加噪声 Headers
        if add_noise:
            # 随机选择部分噪声 header
            noise_keys = random.sample(
                list(self.NOISE_HEADERS.keys()), k=random.randint(3, len(self.NOISE_HEADERS))
            )
            for key in noise_keys:
                if key not in headers:
                    headers[key] = self.NOISE_HEADERS[key]

        # 随机化 header 顺序
        items = list(headers.items())
        random.shuffle(items)
        return dict(items)

    def mutate_header_case(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Header 名称大小写变异 (部分服务器不区分)"""
        mutations = []
        for key, value in headers.items():
            mutated_key = self._random_case(key)
            mutations.append((mutated_key, value))
        return dict(mutations)

    def _random_case(self, s: str) -> str:
        """随机大小写"""
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


class ParameterMutator:
    """参数变异器 - 用于绕过参数签名检测"""

    # URL 编码变体
    ENCODING_CHARS = {
        " ": ["%20", "+", "%09"],
        "/": ["%2f", "%2F", "/", "%252f"],
        "\\": ["%5c", "%5C", "\\", "%255c"],
        ".": ["%2e", "%2E", "."],
        ":": ["%3a", "%3A", ":"],
        "=": ["%3d", "%3D", "="],
        "&": ["%26", "&"],
        "?": ["%3f", "%3F", "?"],
        "#": ["%23", "#"],
        "%": ["%25", "%"],
    }

    # 假参数 (增加噪声)
    FAKE_PARAMS = [
        ("_", lambda: str(int(time.time() * 1000))),  # 时间戳
        ("cache", lambda: str(random.randint(1, 99999))),
        ("rand", lambda: hashlib.md5(str(random.random()).encode()).hexdigest()[:8]),
        ("v", lambda: f"{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(0,9)}"),
        ("nocache", lambda: "1"),
        ("t", lambda: str(int(time.time()))),
    ]

    def shuffle_params(self, params: Dict[str, str]) -> Dict[str, str]:
        """打乱参数顺序"""
        items = list(params.items())
        random.shuffle(items)
        return dict(items)

    def add_fake_params(self, params: Dict[str, str], count: int = 2) -> Dict[str, str]:
        """添加假参数"""
        result = params.copy()
        selected = random.sample(self.FAKE_PARAMS, min(count, len(self.FAKE_PARAMS)))
        for key, value_fn in selected:
            if key not in result:
                result[key] = value_fn()
        return result

    def mutate_encoding(self, value: str, level: int = 1) -> str:
        """
        编码变异
        level: 1=单次编码, 2=双重编码, 3=混合编码
        """
        if level == 1:
            return quote(value)
        elif level == 2:
            return quote(quote(value))
        else:
            # 混合编码
            result = []
            for char in value:
                if char in self.ENCODING_CHARS and random.random() > 0.5:
                    result.append(random.choice(self.ENCODING_CHARS[char]))
                else:
                    result.append(char)
            return "".join(result)

    def mutate_case(self, value: str) -> str:
        """SQL关键字大小写变异"""
        keywords = [
            "SELECT",
            "UNION",
            "FROM",
            "WHERE",
            "AND",
            "OR",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "EXEC",
            "SCRIPT",
            "ALERT",
        ]
        result = value
        for kw in keywords:
            if kw.lower() in value.lower():
                mutated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in kw)
                result = re.sub(kw, mutated, result, flags=re.IGNORECASE)
        return result


class PathMutator:
    """URL 路径变异器"""

    def add_trailing_chars(self, path: str) -> str:
        """添加尾部字符"""
        suffixes = ["/", "//", "/.", "/./", "/..;/", "%20", "%00", ";"]
        return path + random.choice(suffixes)

    def add_path_traversal_bypass(self, path: str) -> str:
        """路径遍历绕过变体"""
        bypasses = [
            "//",
            "/./",
            "/.//",
            "/%2e/",
            "/%2e%2e/",
            "/..;/",
            "/.%00/",
        ]
        return random.choice(bypasses).join(path.split("/"))

    def mutate_extension(self, path: str) -> str:
        """扩展名变异"""
        if "." in path:
            base, ext = path.rsplit(".", 1)
            mutations = [
                f"{base}.{ext}",
                f"{base}.{ext}%00",
                f"{base}.{ext}%20",
                f"{base};.{ext}",
                f"{base}.{ext.upper()}",
            ]
            return random.choice(mutations)
        return path


class RequestHumanizer:
    """请求人性化处理器 - 模拟真实用户行为"""

    def __init__(self, config: Optional[MutationConfig] = None):
        self.config = config or MutationConfig()
        self._last_request_time = 0.0

    def calculate_delay(self) -> float:
        """计算人性化延迟"""
        base_delay = random.uniform(self.config.min_delay, self.config.max_delay)
        jitter = base_delay * self.config.jitter_factor * (random.random() - 0.5) * 2
        return max(0.1, base_delay + jitter)

    def wait_human_like(self) -> float:
        """执行人性化等待"""
        delay = self.calculate_delay()
        time.sleep(delay)
        self._last_request_time = time.time()
        return delay

    def should_pause(self, request_count: int) -> Tuple[bool, float]:
        """判断是否需要暂停 (模拟用户思考/阅读)"""
        # 每 10-20 个请求后有 30% 概率暂停
        if request_count > 0 and request_count % random.randint(10, 20) == 0:
            if random.random() < 0.3:
                pause_time = random.uniform(5.0, 15.0)
                return True, pause_time
        return False, 0.0

    def add_referrer(self, url: str, previous_url: Optional[str] = None) -> str:
        """生成合理的 Referrer"""
        if previous_url:
            return previous_url

        parsed = urlparse(url)
        # 返回同域首页作为 referrer
        return f"{parsed.scheme}://{parsed.netloc}/"


class TrafficMutator:
    """
    流量变异器 - 综合流量伪装

    Usage:
        mutator = TrafficMutator()

        # 变异请求
        mutated = mutator.mutate_request(
            url="http://target.com/api/user?id=1",
            method="GET",
            headers={"Content-Type": "application/json"},
            params={"id": "1"}
        )

        # 使用变异后的请求
        response = requests.request(**mutated)
    """

    def __init__(self, config: Optional[MutationConfig] = None):
        self.config = config or MutationConfig()
        self.ua_rotator = UserAgentRotator()
        self.header_mutator = HeaderMutator(self.ua_rotator)
        self.param_mutator = ParameterMutator()
        self.path_mutator = PathMutator()
        self.humanizer = RequestHumanizer(self.config)

        # 统计
        self._request_count = 0

    def mutate_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        humanize: bool = True,
    ) -> Dict[str, Any]:
        """
        变异HTTP请求

        Returns:
            Dict with keys: url, method, headers, params, data
        """
        self._request_count += 1

        # 解析URL
        parsed = urlparse(url)
        target_host = parsed.netloc

        # 1. Headers 变异
        mutated_headers = self.header_mutator.generate_headers(
            base_headers=headers, target_host=target_host, add_noise=self.config.add_noise_headers
        )

        # 2. 参数变异
        mutated_params = params.copy() if params else {}

        if self.config.shuffle_params and mutated_params:
            mutated_params = self.param_mutator.shuffle_params(mutated_params)

        if self.config.add_fake_params and mutated_params:
            mutated_params = self.param_mutator.add_fake_params(mutated_params)

        # 3. 路径变异
        mutated_path = parsed.path
        if self.config.path_mutation and random.random() < 0.3:
            mutated_path = self.path_mutator.add_trailing_chars(mutated_path)

        # 重建 URL
        mutated_url = f"{parsed.scheme}://{parsed.netloc}{mutated_path}"
        if parsed.query:
            mutated_url += f"?{parsed.query}"

        # 4. 人性化延迟
        delay = 0.0
        if humanize:
            delay = self.humanizer.calculate_delay()

            # 检查是否需要额外暂停
            should_pause, pause_time = self.humanizer.should_pause(self._request_count)
            if should_pause:
                delay += pause_time
                logger.debug(f"Adding human-like pause: {pause_time:.1f}s")

        # 5. 添加 Referrer
        if "Referer" not in mutated_headers:
            mutated_headers["Referer"] = self.humanizer.add_referrer(url)

        return {
            "url": mutated_url,
            "method": method,
            "headers": mutated_headers,
            "params": mutated_params if mutated_params else None,
            "data": data,
            "delay": delay,  # 建议延迟时间
        }

    def mutate_payload(self, payload: str, vuln_type: str = "sqli", encoding_level: int = 1) -> str:
        """
        变异攻击载荷

        Args:
            payload: 原始payload
            vuln_type: 漏洞类型 (sqli, xss, lfi, cmd)
            encoding_level: 编码级别 (1-3)
        """
        mutated = payload

        # 大小写变异
        if self.config.case_mutation:
            mutated = self.param_mutator.mutate_case(mutated)

        # 编码变异
        if self.config.encoding_mutation:
            mutated = self.param_mutator.mutate_encoding(mutated, encoding_level)

        return mutated

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_requests": self._request_count,
            "config": {
                "delay_range": f"{self.config.min_delay}-{self.config.max_delay}s",
                "ua_rotation": self.config.rotate_ua,
                "param_shuffle": self.config.shuffle_params,
            },
        }

    def reset_stats(self):
        """重置统计"""
        self._request_count = 0


# 便捷函数
def create_stealth_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
    stealth_level: int = 2,
) -> Dict[str, Any]:
    """
    创建隐蔽请求 (便捷函数)

    Args:
        stealth_level: 1=低, 2=中, 3=高
    """
    config = MutationConfig()

    if stealth_level >= 2:
        config.add_noise_headers = True
        config.shuffle_params = True

    if stealth_level >= 3:
        config.add_fake_params = True
        config.path_mutation = True
        config.min_delay = 1.0
        config.max_delay = 5.0

    mutator = TrafficMutator(config)
    return mutator.mutate_request(url, method, headers, params)


if __name__ == "__main__":
    # 测试
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    mutator = TrafficMutator()

    result = mutator.mutate_request(
        url="http://example.com/api/user", params={"id": "1", "name": "test"}
    )

    logger.info("Mutated Request:")
    logger.info(f"  URL: {result['url']}")
    logger.info(f"  Headers: {list(result['headers'].keys())}")
    logger.info(f"  Params: {result['params']}")
    logger.info(f"  Delay: {result['delay']:.2f}s")
