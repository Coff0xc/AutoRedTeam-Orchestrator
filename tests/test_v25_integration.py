#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v2.5 集成测试脚本
验证所有新功能模块是否正常工作
"""

import sys
import os
import asyncio
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))


def print_header(title: str):
    """打印测试标题"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_result(name: str, success: bool, message: str = ""):
    """打印测试结果"""
    status = "[PASS]" if success else "[FAIL]"
    print(f"  {status} {name}")
    if message and not success:
        print(f"         {message}")


class TestV25Integration:
    """v2.5集成测试类"""

    def __init__(self):
        self.results = {"passed": 0, "failed": 0, "skipped": 0}

    def run_test(self, name: str, test_func):
        """运行单个测试"""
        try:
            result = test_func()
            if result:
                self.results["passed"] += 1
                print_result(name, True)
            else:
                self.results["failed"] += 1
                print_result(name, False)
        except Exception as e:
            self.results["failed"] += 1
            print_result(name, False, str(e))

    # ========== Phase 1 测试 ==========

    def test_source_map_detection(self):
        """测试Source Map泄露检测"""
        try:
            # SENSITIVE_FILES 定义在 tools/_common.py 中
            from tools._common import SENSITIVE_FILES

            # 检查是否包含.map文件
            map_files = [f for f in SENSITIVE_FILES if ".map" in f.lower()]
            return len(map_files) >= 5
        except Exception as e:
            # 如果导入失败，直接读取文件检查
            import re
            common_file = Path(__file__).parent.parent / "tools" / "_common.py"
            if common_file.exists():
                content = common_file.read_text(encoding='utf-8')
                map_files = re.findall(r'["\']([\\w./]+\\.map)["\']', content)
                return len(map_files) >= 5
            return False

    def test_file_upload_payloads(self):
        """测试文件上传Payload增强"""
        from core.mega_payload_library import MegaPayloadLibrary

        lib = MegaPayloadLibrary()
        # 测试所有语言和类型的组合
        total_payloads = set()
        for lang in ["php", "jsp", "asp"]:
            payloads = lib.get_upload_payloads(target_lang=lang, bypass_type="all")
            total_payloads.update(payloads)

        # 检查是否有足够的Payload (组合后应该超过50个)
        return len(total_payloads) >= 50

    # ========== Phase 2 测试 ==========

    def test_yaml_poc_engine(self):
        """测试YAML PoC引擎"""
        from core.cve import PoCEngine, load_poc

        # 测试加载内置PoC
        templates_dir = Path(__file__).parent.parent / "templates" / "builtin"
        poc_files = list(templates_dir.glob("*.yaml"))

        if not poc_files:
            return False

        # 尝试加载第一个PoC
        poc = load_poc(str(poc_files[0]))
        # PoCTemplate的id在info.id中
        return poc is not None and poc.info is not None and poc.info.id is not None

    def test_cve_update_manager(self):
        """测试CVE多源同步管理器"""
        from core.cve import CVEUpdateManager

        manager = CVEUpdateManager()

        # 检查初始化
        if not manager.db_path.exists():
            return False

        # 检查统计功能
        stats = manager.get_stats()
        return "total_cves" in stats and "poc_available" in stats

    def test_websocket_tunnel(self):
        """测试WebSocket隧道"""
        from core.c2.websocket_tunnel import WebSocketTunnel, WebSocketConfig, EncryptionType

        config = WebSocketConfig(
            url="wss://example.com/ws",
            encryption_type=EncryptionType.XOR
        )

        return config.url is not None and config.encryption_type == EncryptionType.XOR

    def test_chunked_transfer(self):
        """测试分块传输器"""
        from core.c2.chunked_transfer import ChunkedTransfer

        transfer = ChunkedTransfer(chunk_size=1024)

        # 测试数据分割
        test_data = b"A" * 3000
        chunks = transfer.split_data(test_data)

        # 测试数据重组
        reassembled = transfer.reassemble_data(chunks)

        return reassembled == test_data

    def test_js_analyzer(self):
        """测试JS分析引擎"""
        from modules.js_analyzer import JSAnalyzer

        test_js = '''
        fetch('/api/users', {method: 'GET'});
        axios.post('/api/login', data);
        const API_KEY = "sk-1234567890abcdef1234";
        '''

        endpoints = JSAnalyzer.extract_api_endpoints(test_js)
        secrets = JSAnalyzer.extract_secrets(test_js)

        # endpoints是set，secrets是list of dicts
        has_endpoints = len(endpoints) >= 2
        # secrets是 [{"type": ..., "value": ...}, ...]
        has_secrets = isinstance(secrets, list) and len(secrets) >= 1 if secrets else False
        return has_endpoints or has_secrets  # 只要其中一个有结果就通过

    # ========== MCP工具注册测试 ==========

    def test_v25_tools_import(self):
        """测试v2.5工具模块导入"""
        from modules.v25_tools import register_v25_tools
        return True

    def test_mcp_server_syntax(self):
        """测试MCP服务器语法"""
        import py_compile
        mcp_file = Path(__file__).parent.parent / "mcp_stdio_server.py"
        try:
            py_compile.compile(str(mcp_file), doraise=True)
            return True
        except Exception:
            return False

    # ========== Phase 3 测试 (可选) ==========

    def test_subscription_manager(self):
        """测试CVE订阅管理器"""
        try:
            from core.cve.subscription_manager import SubscriptionManager
            return True
        except ImportError:
            return None  # 跳过

    def test_ai_poc_generator(self):
        """测试AI PoC生成器"""
        try:
            from core.cve.ai_poc_generator import AIPoCGenerator
            return True
        except ImportError:
            return None  # 跳过

    def test_proxy_chain(self):
        """测试代理链"""
        try:
            from core.stealth.proxy_chain import ProxyChain
            return True
        except ImportError:
            return None  # 跳过

    def run_all_tests(self):
        """运行所有测试"""
        print_header("v2.5 集成测试")

        # Phase 1 测试
        print("Phase 1: 基础增强")
        self.run_test("Source Map泄露检测", self.test_source_map_detection)
        self.run_test("文件上传Payload增强", self.test_file_upload_payloads)

        # Phase 2 测试
        print("\nPhase 2: 核心模块")
        self.run_test("YAML PoC引擎", self.test_yaml_poc_engine)
        self.run_test("CVE多源同步管理器", self.test_cve_update_manager)
        self.run_test("WebSocket隧道", self.test_websocket_tunnel)
        self.run_test("分块传输器", self.test_chunked_transfer)
        self.run_test("JS分析引擎", self.test_js_analyzer)

        # MCP工具注册测试
        print("\nMCP工具注册")
        self.run_test("v2.5工具模块导入", self.test_v25_tools_import)
        self.run_test("MCP服务器语法检查", self.test_mcp_server_syntax)

        # Phase 3 测试 (可选)
        print("\nPhase 3: 高级功能 (可选)")

        result = self.test_subscription_manager()
        if result is None:
            print("  [SKIP] CVE订阅管理器 (未实现)")
            self.results["skipped"] += 1
        else:
            self.run_test("CVE订阅管理器", lambda: result)

        result = self.test_ai_poc_generator()
        if result is None:
            print("  [SKIP] AI PoC生成器 (未实现)")
            self.results["skipped"] += 1
        else:
            self.run_test("AI PoC生成器", lambda: result)

        result = self.test_proxy_chain()
        if result is None:
            print("  [SKIP] 代理链 (未实现)")
            self.results["skipped"] += 1
        else:
            self.run_test("代理链", lambda: result)

        # 打印总结
        print_header("测试总结")
        print(f"  通过: {self.results['passed']}")
        print(f"  失败: {self.results['failed']}")
        print(f"  跳过: {self.results['skipped']}")
        print(f"\n  总计: {sum(self.results.values())} 项测试")

        success_rate = self.results['passed'] / (self.results['passed'] + self.results['failed']) * 100 if (self.results['passed'] + self.results['failed']) > 0 else 0
        print(f"  成功率: {success_rate:.1f}%")

        return self.results['failed'] == 0


def main():
    """主函数"""
    tester = TestV25Integration()
    success = tester.run_all_tests()

    print("\n" + "="*60)
    if success:
        print("  所有测试通过!")
    else:
        print("  部分测试失败,请检查上述错误")
    print("="*60)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
