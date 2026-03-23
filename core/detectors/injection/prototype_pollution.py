"""
Prototype Pollution 检测器

检测 JavaScript 原型链污染漏洞，包括:
- 服务端 Prototype Pollution (Node.js): 通过 JSON body 注入 __proto__
- 客户端 Prototype Pollution: 通过 URL 参数/fragment 污染 Object.prototype
- 参数合并污染: 利用深度合并函数 (lodash.merge, jQuery.extend 等)

技术原理:
1. __proto__、constructor.prototype 属性可被利用修改 JavaScript 对象原型
2. 服务端: 通过 JSON body 中的 __proto__ key 注入属性到 Object.prototype
3. 客户端: 通过 URL 查询参数/hash 注入，利用不安全的参数解析库
4. 污染成功后可影响所有对象实例，可能导致 RCE/XSS/认证绕过

参考:
- https://portswigger.net/web-security/prototype-pollution
- Olivier Arteau, "Prototype Pollution Attack in NodeJS" (2018)
"""

import json
import logging
import random
import string
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)

# 用于检测原型污染的 canary 属性名
# 使用随机属性名避免影响目标应用
CANARY_PREFIX = "pptest"

# 服务端 PP payload 模板
SERVER_PAYLOADS = [
    # 标准 __proto__ 注入
    {"__proto__": {"{key}": "{value}"}},
    # constructor.prototype 路径
    {"constructor": {"prototype": {"{key}": "{value}"}}},
    # 嵌套 __proto__
    {"__proto__": {"__proto__": {"{key}": "{value}"}}},
    # 数组索引绕过
    {"__proto__[{key}]": "{value}"},
    # JSON 特殊编码
    {"\\u005f\\u005fproto\\u005f\\u005f": {"{key}": "{value}"}},
]

# 客户端 PP payload 模板 (URL 参数形式)
CLIENT_PAYLOADS = [
    "__proto__[{key}]={value}",
    "__proto__.{key}={value}",
    "constructor[prototype][{key}]={value}",
    "constructor.prototype.{key}={value}",
    # 方括号嵌套
    "__proto__%5B{key}%5D={value}",
]


def _random_canary() -> tuple:
    """生成随机 canary key/value 对"""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    key = f"{CANARY_PREFIX}{suffix}"
    value = f"v{suffix}"
    return key, value


@register_detector("prototype_pollution")
class PrototypePollutionDetector(BaseDetector):
    """Prototype Pollution 检测器

    检测服务端和客户端的 JavaScript 原型链污染漏洞。
    使用无害的 canary 属性验证污染是否成功。

    使用示例:
        detector = PrototypePollutionDetector()
        results = detector.detect("https://example.com/api/settings", method="PUT")
    """

    name = "prototype_pollution"
    description = "Prototype Pollution 原型链污染检测器"
    vuln_type = "prototype_pollution"
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION
    version = "1.0.0"

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 Prototype Pollution 漏洞

        Args:
            url: 目标 URL
            **kwargs: 额外参数
                method: HTTP 方法 (默认 POST)
                params: 额外请求参数
                content_type: 请求内容类型

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        parsed = urlparse(url)
        if not parsed.hostname:
            logger.warning("[%s] 无效URL: %s", self.name, url)
            return results

        method = kwargs.get("method", "POST")
        content_type = kwargs.get("content_type", "application/json")

        # 1. 服务端 PP 检测 (JSON body)
        if content_type == "application/json":
            server_results = self._detect_server_pp(url, method)
            results.extend(server_results)

        # 2. 客户端 PP 检测 (URL 参数)
        client_results = self._detect_client_pp(url)
        results.extend(client_results)

        # 3. 参数合并检测 (query + body 混合)
        merge_result = self._detect_merge_pp(url, method)
        if merge_result:
            results.append(merge_result)

        self._log_detection_end(url, results)
        return results

    def _detect_server_pp(self, url: str, method: str = "POST") -> List[DetectionResult]:
        """检测服务端原型链污染

        通过 JSON body 发送 __proto__ payload，
        然后请求检查污染属性是否出现在后续响应中。
        """
        results = []

        for payload_template in SERVER_PAYLOADS:
            canary_key, canary_value = _random_canary()

            # 构建 payload
            payload = self._build_payload(payload_template, canary_key, canary_value)
            if payload is None:
                continue

            payload_str = json.dumps(payload, ensure_ascii=False)

            # 发送污染请求
            resp = self._safe_request(
                method,
                url,
                json_data=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            status = getattr(resp, "status_code", 0)
            body = getattr(resp, "text", "") or ""

            # 检查1: 污染值是否直接出现在响应中
            if canary_value in body:
                # 再次请求（无 payload）验证持久性
                verify_resp = self._safe_request("GET", url)
                verify_body = getattr(verify_resp, "text", "") if verify_resp else ""

                if canary_value in verify_body:
                    # 持久污染 — 高置信度
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            payload=payload_str,
                            evidence=(
                                f"服务端原型链污染: canary 属性 '{canary_key}' "
                                f"在后续请求中持久存在，确认 Object.prototype 被污染。"
                            ),
                            confidence=0.90,
                            verified=True,
                            remediation=self._get_remediation(),
                            references=self._get_references(),
                            extra={
                                "pp_type": "server_persistent",
                                "canary_key": canary_key,
                                "method": method,
                                "status_code": status,
                            },
                        )
                    )
                    return results  # 已确认，无需继续
                else:
                    # 非持久反射 — 可能只是响应回显
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            payload=payload_str,
                            evidence=(
                                f"原型链污染迹象: canary '{canary_key}' "
                                f"在污染请求响应中出现，但未在后续请求中持久。"
                                f"可能为非持久 PP 或响应回显。"
                            ),
                            confidence=0.55,
                            verified=False,
                            remediation=self._get_remediation(),
                            references=self._get_references(),
                            extra={
                                "pp_type": "server_reflected",
                                "canary_key": canary_key,
                                "method": method,
                                "status_code": status,
                            },
                        )
                    )

            # 检查2: 状态码异常 (500 可能表示 PP 导致内部错误)
            if status == 500 and "__proto__" in payload_str:
                # 发送正常 JSON 对比
                normal_resp = self._safe_request(
                    method,
                    url,
                    json_data={"test": "normal"},
                    headers={"Content-Type": "application/json"},
                )
                normal_status = getattr(normal_resp, "status_code", 0) if normal_resp else 0

                if normal_status != 500:
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            payload=payload_str,
                            evidence=(
                                f"原型链污染导致 500 错误: __proto__ payload "
                                f"触发服务端异常 (正常请求返回 {normal_status})。"
                                f"表明后端不安全地处理了 __proto__ 属性。"
                            ),
                            confidence=0.65,
                            verified=False,
                            remediation=self._get_remediation(),
                            references=self._get_references(),
                            extra={
                                "pp_type": "server_error",
                                "canary_key": canary_key,
                                "method": method,
                                "error_status": status,
                                "normal_status": normal_status,
                            },
                        )
                    )

        return results

    def _detect_client_pp(self, url: str) -> List[DetectionResult]:
        """检测客户端原型链污染

        通过 URL 查询参数注入 __proto__ payload，
        检查响应 HTML/JS 中是否包含可利用的客户端代码模式。
        """
        results = []

        # 先获取基线响应
        baseline_resp = self._safe_request("GET", url)
        if baseline_resp is None:
            return results

        baseline_body = getattr(baseline_resp, "text", "") or ""

        # 检查响应是否为 HTML/JS (客户端 PP 仅影响前端)
        content_type = ""
        if hasattr(baseline_resp, "headers") and baseline_resp.headers:
            content_type = str(
                baseline_resp.headers.get("content-type", "")
                if hasattr(baseline_resp.headers, "get")
                else ""
            ).lower()

        if "html" not in content_type and "javascript" not in content_type:
            return results

        for payload_template in CLIENT_PAYLOADS:
            canary_key, canary_value = _random_canary()
            payload_param = payload_template.format(key=canary_key, value=canary_value)

            # 构建带 payload 的 URL
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{payload_param}"

            resp = self._safe_request("GET", test_url)
            if resp is None:
                continue

            body = getattr(resp, "text", "") or ""

            # 检查 canary 是否在响应中出现
            if canary_value in body and canary_value not in baseline_body:
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=payload_param,
                        evidence=(
                            f"客户端原型链污染: URL 参数 '{payload_param}' "
                            f"的 canary 值出现在响应中 (基线响应中不存在)。"
                        ),
                        confidence=0.70,
                        verified=False,
                        remediation=self._get_remediation(),
                        references=self._get_references(),
                        extra={
                            "pp_type": "client",
                            "canary_key": canary_key,
                            "payload_param": payload_param,
                        },
                    )
                )
                return results  # 已发现客户端 PP

        return results

    def _detect_merge_pp(self, url: str, method: str = "POST") -> Optional[DetectionResult]:
        """检测参数合并导致的原型链污染

        一些应用会合并 query params 和 body params，
        利用这种行为可通过 query 参数中的 __proto__ 触发污染。
        """
        canary_key, canary_value = _random_canary()

        # 通过 query 参数发送 __proto__ + 正常 JSON body
        separator = "&" if "?" in url else "?"
        test_url = f"{url}{separator}__proto__[{canary_key}]={canary_value}"

        resp = self._safe_request(
            method,
            test_url,
            json_data={"action": "test"},
            headers={"Content-Type": "application/json"},
        )
        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status_code", 0)

        if canary_value in body:
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=f"query: __proto__[{canary_key}]={canary_value} + JSON body",
                evidence=(
                    f"参数合并原型链污染: query 参数中的 __proto__[{canary_key}] "
                    f"被合并到对象中，canary 值出现在响应里。"
                ),
                confidence=0.75,
                verified=False,
                remediation=self._get_remediation(),
                references=self._get_references(),
                extra={
                    "pp_type": "merge",
                    "canary_key": canary_key,
                    "method": method,
                    "status_code": status,
                },
            )

        return None

    def _build_payload(self, template: Any, key: str, value: str) -> Optional[Dict]:
        """从模板构建 payload，替换 {key} 和 {value} 占位符"""
        if isinstance(template, dict):
            result = {}
            for k, v in template.items():
                new_key = k.replace("{key}", key).replace("{value}", value)
                if isinstance(v, dict):
                    new_value = self._build_payload(v, key, value)
                elif isinstance(v, str):
                    new_value = v.replace("{key}", key).replace("{value}", value)
                else:
                    new_value = v
                result[new_key] = new_value
            return result
        elif isinstance(template, str):
            return None  # 字符串模板用于 URL 参数，不用于 JSON body
        return None

    @staticmethod
    def _get_remediation() -> str:
        return (
            "1. 使用 Object.create(null) 创建无原型的对象\n"
            "2. 冻结 Object.prototype: Object.freeze(Object.prototype)\n"
            "3. 使用 Map 代替普通对象存储用户输入\n"
            "4. 过滤 JSON 输入中的 __proto__、constructor 键\n"
            "5. 使用安全的深度合并库 (如 lodash >= 4.17.12)\n"
            "6. Node.js 可使用 --disable-proto=throw 启动参数"
        )

    @staticmethod
    def _get_references() -> List[str]:
        return [
            "https://portswigger.net/web-security/prototype-pollution",
            "https://cwe.mitre.org/data/definitions/1321.html",
            "https://github.com/nicknisi/prototype-pollution",
        ]
