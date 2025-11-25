"""
Fingerprint Engine - 指纹识别引擎
识别Web技术栈、WAF、CDN等
"""

import re
import hashlib
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Fingerprint:
    name: str
    version: str = ""
    confidence: float = 0.0
    category: str = ""


class WebFingerprint:
    """Web技术指纹库"""
    
    # HTTP Header指纹
    HEADER_FINGERPRINTS = {
        # Web服务器
        "server": {
            r"Apache/?([\d.]+)?": ("Apache", "webserver"),
            r"nginx/?([\d.]+)?": ("Nginx", "webserver"),
            r"Microsoft-IIS/?([\d.]+)?": ("IIS", "webserver"),
            r"LiteSpeed": ("LiteSpeed", "webserver"),
            r"openresty/?([\d.]+)?": ("OpenResty", "webserver"),
            r"Tengine/?([\d.]+)?": ("Tengine", "webserver"),
            r"Caddy": ("Caddy", "webserver"),
        },
        "x-powered-by": {
            r"PHP/?([\d.]+)?": ("PHP", "language"),
            r"ASP\.NET": ("ASP.NET", "framework"),
            r"Express": ("Express.js", "framework"),
            r"Servlet/?([\d.]+)?": ("Java Servlet", "framework"),
            r"JSF/?([\d.]+)?": ("JSF", "framework"),
            r"Phusion Passenger": ("Passenger", "appserver"),
            r"Next\.js": ("Next.js", "framework"),
        },
        "x-aspnet-version": {
            r"([\d.]+)": ("ASP.NET", "framework"),
        },
        "x-generator": {
            r"Drupal": ("Drupal", "cms"),
            r"WordPress": ("WordPress", "cms"),
            r"Joomla": ("Joomla", "cms"),
        },
    }
    
    # Cookie指纹
    COOKIE_FINGERPRINTS = {
        "PHPSESSID": ("PHP", "language"),
        "JSESSIONID": ("Java", "language"),
        "ASP.NET_SessionId": ("ASP.NET", "framework"),
        "CFID": ("ColdFusion", "framework"),
        "CFTOKEN": ("ColdFusion", "framework"),
        "ci_session": ("CodeIgniter", "framework"),
        "laravel_session": ("Laravel", "framework"),
        "XSRF-TOKEN": ("Laravel/Angular", "framework"),
        "_rails_session": ("Ruby on Rails", "framework"),
        "connect.sid": ("Express.js", "framework"),
        "wp-settings": ("WordPress", "cms"),
        "__cfduid": ("Cloudflare", "cdn"),
    }
    
    # HTML内容指纹
    HTML_FINGERPRINTS = [
        # CMS
        (r'wp-content|wp-includes', "WordPress", "cms"),
        (r'/sites/default/files|Drupal\.settings', "Drupal", "cms"),
        (r'/components/com_|/administrator/components', "Joomla", "cms"),
        (r'<meta name="generator" content="TYPO3', "TYPO3", "cms"),
        (r'Powered by.*?vBulletin', "vBulletin", "cms"),
        (r'/skin/frontend/|/js/mage/', "Magento", "ecommerce"),
        (r'Shopify\.theme|cdn\.shopify\.com', "Shopify", "ecommerce"),
        
        # 框架
        (r'<script[^>]*react', "React", "jsframework"),
        (r'ng-app|ng-controller|angular', "Angular", "jsframework"),
        (r'__NEXT_DATA__|_next/static', "Next.js", "framework"),
        (r'__NUXT__|_nuxt/', "Nuxt.js", "framework"),
        (r'vue\.js|Vue\.component', "Vue.js", "jsframework"),
        (r'data-ember|ember\.js', "Ember.js", "jsframework"),
        (r'csrfmiddlewaretoken', "Django", "framework"),
        (r'laravel|Laravel', "Laravel", "framework"),
        (r'Symfony Web Debug Toolbar|sf2-', "Symfony", "framework"),
        (r'Spring Framework|spring-', "Spring", "framework"),
        (r'struts|\.action', "Struts", "framework"),
        (r'__viewstate|__eventvalidation', "ASP.NET WebForms", "framework"),
        
        # 前端库
        (r'jquery[.-]?([\d.]+)?\.js', "jQuery", "jslib"),
        (r'bootstrap[.-]?([\d.]+)?\.css', "Bootstrap", "csslib"),
        (r'tailwindcss|tailwind', "Tailwind CSS", "csslib"),
        
        # 分析和追踪
        (r'google-analytics|ga\.js|gtag', "Google Analytics", "analytics"),
        (r'googletagmanager', "Google Tag Manager", "analytics"),
        (r'facebook\.net/.*?fbevents', "Facebook Pixel", "analytics"),
        (r'hotjar\.com', "Hotjar", "analytics"),
    ]
    
    # Favicon Hash指纹
    FAVICON_HASHES = {
        # hash -> (name, category)
        "1808881093": ("Confluence", "wiki"),
        "-1166125018": ("JIRA", "issuetracker"),
        "116323821": ("Spring Boot", "framework"),
        "-297069493": ("Grafana", "monitoring"),
        "-1950415971": ("Jenkins", "ci"),
        "81586312": ("GitLab", "git"),
        "-1293291885": ("Atlassian", "enterprise"),
    }


class WAFDetector:
    """WAF检测器"""
    
    WAF_SIGNATURES = {
        # Header检测
        "headers": {
            "cloudflare": [r"cf-ray", r"__cfduid", r"cloudflare"],
            "aws_waf": [r"x-amzn-requestid", r"x-amz-cf-id"],
            "akamai": [r"akamai", r"x-akamai"],
            "incapsula": [r"incap_ses", r"visid_incap"],
            "sucuri": [r"x-sucuri-id", r"sucuri"],
            "f5_bigip": [r"x-wa-info", r"bigipserver"],
            "fortinet": [r"fortigate", r"fortiweb"],
            "barracuda": [r"barra_counter_session"],
            "imperva": [r"x-iinfo"],
            "radware": [r"x-sl-compstate"],
            "safedog": [r"safedog"],
            "360": [r"360wzws", r"anyu"],
            "baidu": [r"yunjiasu"],
            "aliyun": [r"ali-cdn", r"aliyun"],
            "tencent": [r"tencent", r"qcloud"],
        },
        # Body检测
        "body": {
            "cloudflare": [r"Cloudflare Ray ID", r"cf-browser-verification"],
            "mod_security": [r"mod_security", r"NOYB"],
            "aws_waf": [r"Request blocked"],
            "akamai": [r"Access Denied.*?Akamai"],
            "sucuri": [r"Sucuri WebSite Firewall"],
            "wordfence": [r"Generated by Wordfence"],
            "comodo": [r"Protected by COMODO"],
            "yunsuo": [r"yunsuo_session"],
        }
    }
    
    def detect(self, headers: Dict, body: str) -> List[str]:
        """检测WAF"""
        detected = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        
        # Header检测
        for waf, patterns in self.WAF_SIGNATURES["headers"].items():
            for pattern in patterns:
                header_str = " ".join(headers_lower.keys()) + " ".join(headers_lower.values())
                if re.search(pattern, header_str, re.I):
                    detected.append(waf)
                    break
        
        # Body检测
        for waf, patterns in self.WAF_SIGNATURES["body"].items():
            for pattern in patterns:
                if re.search(pattern, body_lower, re.I):
                    if waf not in detected:
                        detected.append(waf)
                    break
        
        return detected


class CDNDetector:
    """CDN检测器"""
    
    CDN_SIGNATURES = {
        "cloudflare": [r"cloudflare", r"cf-ray"],
        "fastly": [r"fastly", r"x-fastly"],
        "akamai": [r"akamai", r"x-akamai"],
        "cloudfront": [r"cloudfront", r"x-amz-cf"],
        "azure_cdn": [r"azure", r"x-azure"],
        "google_cdn": [r"x-goog-", r"google"],
        "aliyun_cdn": [r"ali-cdn", r"aliyun"],
        "tencent_cdn": [r"tencent", r"qcloud"],
        "baidu_cdn": [r"yunjiasu", r"baidu"],
        "keycdn": [r"keycdn"],
        "stackpath": [r"stackpath", r"maxcdn"],
        "jsdelivr": [r"jsdelivr"],
        "unpkg": [r"unpkg"],
    }
    
    def detect(self, headers: Dict, cname: str = "") -> List[str]:
        """检测CDN"""
        detected = []
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        
        for cdn, patterns in self.CDN_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, headers_str, re.I):
                    detected.append(cdn)
                    break
                if cname and re.search(pattern, cname, re.I):
                    if cdn not in detected:
                        detected.append(cdn)
                    break
        
        return detected


class FingerprintEngine:
    """综合指纹识别引擎"""
    
    def __init__(self):
        self.web_fp = WebFingerprint()
        self.waf_detector = WAFDetector()
        self.cdn_detector = CDNDetector()
    
    def analyze(self, url: str, status: int, headers: Dict, body: str) -> Dict:
        """分析响应并提取指纹"""
        results = {
            "technologies": [],
            "waf": [],
            "cdn": [],
            "server": "",
            "framework": "",
            "cms": "",
        }
        
        # Header指纹
        for header_name, patterns in self.web_fp.HEADER_FINGERPRINTS.items():
            header_value = headers.get(header_name, "") or headers.get(header_name.replace("-", "_"), "")
            if not header_value:
                continue
            
            for pattern, (name, category) in patterns.items():
                match = re.search(pattern, header_value, re.I)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    fp = Fingerprint(name=name, version=version, confidence=0.9, category=category)
                    results["technologies"].append(fp)
                    
                    if category == "webserver":
                        results["server"] = f"{name}/{version}" if version else name
        
        # Cookie指纹
        cookies = headers.get("set-cookie", "") or headers.get("cookie", "")
        for cookie_name, (name, category) in self.web_fp.COOKIE_FINGERPRINTS.items():
            if cookie_name.lower() in cookies.lower():
                results["technologies"].append(
                    Fingerprint(name=name, confidence=0.8, category=category)
                )
        
        # HTML指纹
        for pattern, name, category in self.web_fp.HTML_FINGERPRINTS:
            if re.search(pattern, body, re.I):
                results["technologies"].append(
                    Fingerprint(name=name, confidence=0.7, category=category)
                )
                if category == "cms" and not results["cms"]:
                    results["cms"] = name
                if category == "framework" and not results["framework"]:
                    results["framework"] = name
        
        # WAF检测
        results["waf"] = self.waf_detector.detect(headers, body)
        
        # CDN检测
        results["cdn"] = self.cdn_detector.detect(headers)
        
        return results
