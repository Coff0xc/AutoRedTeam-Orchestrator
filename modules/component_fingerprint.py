#!/usr/bin/env python3
"""
组件指纹库 - 用于识别Web技术栈和推荐相应payload
"""

import re
from typing import Dict, List, Optional


# 组件指纹数据库
FINGERPRINTS = {
    # ============ Web服务器 ============
    "nginx": {
        "headers": ["nginx", "openresty"],
        "patterns": [r"nginx/[\d.]+", r"openresty/[\d.]+"],
        "payloads": ["nginx_path_traversal", "nginx_alias_traversal"],
        "cves": ["CVE-2021-23017", "CVE-2019-20372", "CVE-2017-7529"]
    },
    "apache": {
        "headers": ["apache", "httpd"],
        "patterns": [r"Apache/[\d.]+", r"httpd"],
        "payloads": ["apache_mod_cgi", "apache_path_traversal", "apache_struts"],
        "cves": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2019-0211"]
    },
    "iis": {
        "headers": ["microsoft-iis", "asp.net"],
        "patterns": [r"IIS/[\d.]+", r"ASP\.NET"],
        "payloads": ["iis_shortname", "iis_webdav", "aspnet_viewstate"],
        "cves": ["CVE-2017-7269", "CVE-2020-0646"]
    },
    "tomcat": {
        "headers": ["apache-coyote", "tomcat"],
        "patterns": [r"Tomcat/[\d.]+", r"Apache-Coyote"],
        "payloads": ["tomcat_manager", "tomcat_ajp", "tomcat_ghostcat"],
        "cves": ["CVE-2020-1938", "CVE-2019-0232", "CVE-2020-9484"]
    },
    
    # ============ CMS系统 ============
    "wordpress": {
        "patterns": [r"wp-content", r"wp-includes", r"wp-json", r"/wp-admin/"],
        "payloads": ["wp_xmlrpc", "wp_user_enum", "wp_plugin_vuln"],
        "cves": ["CVE-2023-2982", "CVE-2022-21661", "CVE-2021-29447"]
    },
    "drupal": {
        "patterns": [r"Drupal", r"/sites/default/", r"drupal.js"],
        "payloads": ["drupalgeddon", "drupal_rce", "drupal_sqli"],
        "cves": ["CVE-2018-7600", "CVE-2019-6340", "CVE-2018-7602"]
    },
    "joomla": {
        "patterns": [r"Joomla", r"/administrator/", r"com_content"],
        "payloads": ["joomla_sqli", "joomla_rce", "joomla_user_enum"],
        "cves": ["CVE-2023-23752", "CVE-2017-8917", "CVE-2015-8562"]
    },
    "dedecms": {
        "patterns": [r"DedeCMS", r"/dede/", r"dedeajax"],
        "payloads": ["dedecms_sqli", "dedecms_rce", "dedecms_file_upload"],
        "cves": []
    },
    "phpcms": {
        "patterns": [r"phpcms", r"/phpcms/"],
        "payloads": ["phpcms_sqli", "phpcms_authkey"],
        "cves": []
    },
    "discuz": {
        "patterns": [r"Discuz", r"/uc_server/"],
        "payloads": ["discuz_ssrf", "discuz_sqli"],
        "cves": []
    },
    
    # ============ 框架 ============
    "spring": {
        "patterns": [r"spring", r"Whitelabel Error Page", r"X-Application-Context"],
        "payloads": ["spring4shell", "spring_actuator", "spring_spel", "spring_cloud_gateway"],
        "cves": ["CVE-2022-22965", "CVE-2022-22963", "CVE-2020-5398", "CVE-2022-22947"]
    },
    "struts": {
        "patterns": [r"\.action", r"struts", r"\.do"],
        "payloads": ["struts2_ognl", "struts2_s2_045", "struts2_s2_057", "struts2_s2_061"],
        "cves": ["CVE-2017-5638", "CVE-2018-11776", "CVE-2020-17530", "CVE-2021-31805"]
    },
    "thinkphp": {
        "patterns": [r"thinkphp", r"think_", r"/index\.php\?s="],
        "payloads": ["thinkphp_rce", "thinkphp_5x_rce", "thinkphp_sqli"],
        "cves": ["CVE-2018-20062", "CVE-2019-9082"]
    },
    "laravel": {
        "patterns": [r"laravel", r"X-Powered-By.*Laravel", r"laravel_session"],
        "payloads": ["laravel_debug_rce", "laravel_ignition", "laravel_sqli"],
        "cves": ["CVE-2021-3129"]
    },
    "fastjson": {
        "patterns": [r"fastjson", r"com\.alibaba\.fastjson", r"@type"],
        "payloads": ["fastjson_autotype", "fastjson_1247", "fastjson_deserialization"],
        "cves": ["CVE-2022-25845", "CVE-2020-8840", "CVE-2019-12086"]
    },
    "shiro": {
        "patterns": [r"rememberMe", r"shiro", r"deleteMe"],
        "payloads": ["shiro_deserialization", "shiro_padding_oracle", "shiro_rce"],
        "cves": ["CVE-2016-4437", "CVE-2020-1957", "CVE-2020-11989"]
    },
    "django": {
        "patterns": [r"django", r"csrfmiddlewaretoken", r"DJANGO_SETTINGS_MODULE"],
        "payloads": ["django_debug", "django_sqli", "django_ssti"],
        "cves": ["CVE-2022-34265", "CVE-2021-35042"]
    },
    "flask": {
        "patterns": [r"flask", r"werkzeug", r"jinja2"],
        "payloads": ["flask_ssti", "flask_debug_pin", "flask_session"],
        "cves": []
    },
    "express": {
        "patterns": [r"express", r"X-Powered-By.*Express"],
        "payloads": ["express_prototype_pollution", "express_sqli"],
        "cves": []
    },
    
    # ============ 中间件 ============
    "weblogic": {
        "patterns": [r"WebLogic", r"/console/", r"7001", r"wls"],
        "payloads": ["weblogic_t3", "weblogic_iiop", "weblogic_xmldecoder", "weblogic_cve_2023"],
        "cves": ["CVE-2023-21839", "CVE-2020-14882", "CVE-2019-2725", "CVE-2020-14883"]
    },
    "jboss": {
        "patterns": [r"JBoss", r"/jmx-console/", r"/invoker/"],
        "payloads": ["jboss_jmx", "jboss_invoker", "jboss_deserialization"],
        "cves": ["CVE-2017-12149", "CVE-2015-7501"]
    },
    "websphere": {
        "patterns": [r"WebSphere", r"/ibm/console/"],
        "payloads": ["websphere_java_deserialization"],
        "cves": ["CVE-2020-4450"]
    },
    
    # ============ 数据库 ============
    "mysql": {
        "patterns": [r"mysql", r"3306", r"MariaDB"],
        "payloads": ["mysql_auth_bypass", "mysql_udf", "mysql_sqli"],
        "cves": ["CVE-2012-2122"]
    },
    "mssql": {
        "patterns": [r"mssql", r"1433", r"SQL Server"],
        "payloads": ["mssql_xp_cmdshell", "mssql_sqli"],
        "cves": ["CVE-2020-0618"]
    },
    "postgresql": {
        "patterns": [r"postgresql", r"5432", r"postgres"],
        "payloads": ["postgresql_sqli", "postgresql_rce"],
        "cves": ["CVE-2019-9193"]
    },
    "redis": {
        "patterns": [r"redis", r"6379"],
        "payloads": ["redis_unauthorized", "redis_lua_rce", "redis_master_slave"],
        "cves": ["CVE-2022-0543", "CVE-2015-8080"]
    },
    "mongodb": {
        "patterns": [r"mongodb", r"27017"],
        "payloads": ["mongodb_unauth", "mongodb_nosqli"],
        "cves": []
    },
    "elasticsearch": {
        "patterns": [r"elasticsearch", r"9200", r"cluster_name"],
        "payloads": ["es_unauth", "es_groovy_rce", "es_script_rce"],
        "cves": ["CVE-2015-1427", "CVE-2014-3120"]
    },
    
    # ============ DevOps ============
    "jenkins": {
        "patterns": [r"Jenkins", r"X-Jenkins", r"/jenkins/"],
        "payloads": ["jenkins_script", "jenkins_cli_rce", "jenkins_auth_bypass"],
        "cves": ["CVE-2024-23897", "CVE-2019-1003000", "CVE-2018-1000861"]
    },
    "gitlab": {
        "patterns": [r"gitlab", r"X-Gitlab", r"/users/sign_in"],
        "payloads": ["gitlab_ssrf", "gitlab_rce", "gitlab_file_read"],
        "cves": ["CVE-2021-22205", "CVE-2023-7028", "CVE-2021-22214"]
    },
    "harbor": {
        "patterns": [r"harbor", r"Harbor"],
        "payloads": ["harbor_cve"],
        "cves": ["CVE-2019-16097"]
    },
    "nexus": {
        "patterns": [r"Nexus", r"nexus-content"],
        "payloads": ["nexus_rce"],
        "cves": ["CVE-2020-10199", "CVE-2020-10204"]
    },
    
    # ============ 网络设备 ============
    "cisco": {
        "patterns": [r"cisco", r"Cisco"],
        "payloads": ["cisco_smart_install", "cisco_default_creds"],
        "cves": ["CVE-2018-0171"]
    },
    "huawei": {
        "patterns": [r"huawei", r"Huawei"],
        "payloads": ["huawei_default_creds"],
        "cves": []
    },
    "fortinet": {
        "patterns": [r"FortiOS", r"fortinet", r"FortiGate"],
        "payloads": ["fortinet_auth_bypass", "fortinet_rce"],
        "cves": ["CVE-2022-40684", "CVE-2023-27997"]
    },
    
    # ============ 安全设备 ============
    "sangfor": {
        "patterns": [r"sangfor", r"深信服"],
        "payloads": ["sangfor_rce", "sangfor_arbitrary_login"],
        "cves": []
    },
    "qianxin": {
        "patterns": [r"qianxin", r"奇安信", r"天擎"],
        "payloads": [],
        "cves": []
    }
}


class ComponentIdentifier:
    """组件识别器"""
    
    def __init__(self):
        self.fingerprints = FINGERPRINTS
        self.detected = []
    
    def identify_from_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """从HTTP头识别组件"""
        results = []
        headers_str = str(headers).lower()
        
        for name, fp in self.fingerprints.items():
            for header in fp.get("headers", []):
                if header.lower() in headers_str:
                    results.append({
                        "component": name,
                        "confidence": "high",
                        "source": "header",
                        "payloads": fp.get("payloads", []),
                        "cves": fp.get("cves", [])
                    })
                    break
        
        return results
    
    def identify_from_body(self, body: str) -> List[Dict]:
        """从响应体识别组件"""
        results = []
        
        for name, fp in self.fingerprints.items():
            for pattern in fp.get("patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    if name not in [r["component"] for r in results]:
                        results.append({
                            "component": name,
                            "confidence": "medium",
                            "source": "body",
                            "pattern": pattern,
                            "payloads": fp.get("payloads", []),
                            "cves": fp.get("cves", [])
                        })
                    break
        
        return results
    
    def identify_from_url(self, url: str) -> List[Dict]:
        """从URL识别组件"""
        results = []
        
        patterns = {
            "wordpress": [r"/wp-", r"wordpress"],
            "drupal": [r"/sites/", r"drupal"],
            "joomla": [r"/administrator/", r"joomla"],
            "spring": [r"/actuator", r"/swagger"],
            "struts": [r"\.action", r"\.do"],
            "tomcat": [r"/manager/", r":8080"],
            "weblogic": [r":7001", r"/console"],
            "jenkins": [r"/jenkins", r":8080/jenkins"],
            "gitlab": [r"gitlab", r"/users/sign_in"],
        }
        
        for comp, pats in patterns.items():
            for pat in pats:
                if re.search(pat, url, re.IGNORECASE):
                    if comp in self.fingerprints:
                        results.append({
                            "component": comp,
                            "confidence": "low",
                            "source": "url",
                            "payloads": self.fingerprints[comp].get("payloads", []),
                            "cves": self.fingerprints[comp].get("cves", [])
                        })
                    break
        
        return results
    
    def get_recommended_payloads(self, components: List[str]) -> Dict[str, List[str]]:
        """根据组件获取推荐的payload类型"""
        from .payload_library import PayloadLibrary
        
        recommendations = {}
        
        for comp in components:
            if comp in self.fingerprints:
                fp = self.fingerprints[comp]
                payload_types = fp.get("payloads", [])
                
                for ptype in payload_types:
                    if "sqli" in ptype.lower():
                        if "sqli" not in recommendations:
                            recommendations["sqli"] = []
                        recommendations["sqli"].extend(PayloadLibrary.get_all("sqli", "detection")[:5])
                    
                    elif "rce" in ptype.lower() or "cmd" in ptype.lower():
                        if "rce" not in recommendations:
                            recommendations["rce"] = []
                        recommendations["rce"].extend(PayloadLibrary.get_all("rce", "command_injection")[:5])
                    
                    elif "lfi" in ptype.lower() or "path" in ptype.lower():
                        if "lfi" not in recommendations:
                            recommendations["lfi"] = []
                        recommendations["lfi"].extend(PayloadLibrary.get_all("lfi", "linux")[:5])
                    
                    elif "xss" in ptype.lower():
                        if "xss" not in recommendations:
                            recommendations["xss"] = []
                        recommendations["xss"].extend(PayloadLibrary.get_all("xss", "basic")[:5])
        
        # 去重
        for k in recommendations:
            recommendations[k] = list(set(recommendations[k]))
        
        return recommendations
    
    def get_cves_for_component(self, component: str) -> List[str]:
        """获取组件相关的CVE"""
        if component in self.fingerprints:
            return self.fingerprints[component].get("cves", [])
        return []
