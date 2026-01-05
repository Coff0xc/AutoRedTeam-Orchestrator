#!/usr/bin/env python3
"""
优化模块测试脚本
验证所有新增优化模块的功能
"""

import sys
import os
import json
import time

# 修复Windows编码问题
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_ai_decision_engine():
    """测试AI决策引擎"""
    print("\n" + "="*50)
    print("测试 AI决策引擎")
    print("="*50)

    try:
        from modules.ai_decision_engine import get_decision_engine, TargetContext

        engine = get_decision_engine()

        # 创建测试上下文
        context = TargetContext(
            url="https://example.com",
            tech_stack={"language": "php", "framework": "laravel"},
            open_ports=[80, 443, 3306],
            waf_detected="cloudflare",
            vulnerabilities_found=["sqli_detect"]
        )

        # 获取攻击建议
        suggestion = engine.suggest_next_action(context)
        print(f"✓ 攻击建议: {suggestion['action']}")
        print(f"  原因: {suggestion['reason']}")
        print(f"  置信度: {suggestion['confidence']}")

        # 获取攻击链
        chains = engine.get_attack_chain(context, max_depth=3)
        print(f"✓ 生成攻击链: {len(chains)} 条")
        if chains:
            print(f"  示例: {' -> '.join(chains[0])}")

        # 记录结果
        engine.record_result("sqli_detect", True, 2.5)
        print("✓ 结果记录成功")

        return True
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False


def test_async_scanner():
    """测试异步扫描器"""
    print("\n" + "="*50)
    print("测试 异步扫描器")
    print("="*50)

    try:
        from modules.async_scanner import (
            async_port_scan,
            async_dir_scan,
            async_subdomain_scan
        )

        # 测试端口扫描（本地）
        print("测试端口扫描...")
        start = time.time()
        result = async_port_scan("127.0.0.1", [80, 443, 8080, 22, 3306])
        print(f"✓ 端口扫描完成: {result['duration']}s")
        print(f"  开放端口: {[p['port'] for p in result['open_ports']]}")

        # 测试目录扫描（模拟）
        print("✓ 目录扫描模块已加载")

        # 测试子域名扫描（模拟）
        print("✓ 子域名扫描模块已加载")

        return True
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False


def test_adaptive_payload():
    """测试自适应Payload引擎"""
    print("\n" + "="*50)
    print("测试 自适应Payload引擎")
    print("="*50)

    try:
        from modules.adaptive_payload_engine import (
            get_payload_engine,
            smart_select_payloads,
            mutate_for_waf,
            PayloadResult
        )

        engine = get_payload_engine()

        # 选择SQL注入Payload
        payloads = smart_select_payloads("sqli", waf="cloudflare", top_n=5)
        print(f"✓ SQL注入Payload选择: {len(payloads)} 个")
        print(f"  Top 3: {payloads[:3]}")

        # WAF绕过变异
        mutations = mutate_for_waf("' OR '1'='1", "cloudflare")
        print(f"✓ WAF绕过变异: {len(mutations)} 个")
        print(f"  示例: {mutations[:2]}")

        # 记录结果
        result = PayloadResult(
            payload="' OR '1'='1",
            success=True,
            response_time=0.5
        )
        engine.record_result("sqli", "' OR '1'='1", result)
        print("✓ Payload结果记录成功")

        # 获取统计
        stats = engine.get_stats("sqli")
        print(f"✓ 统计信息: {stats}")

        return True
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False


def test_vuln_correlation():
    """测试漏洞关联分析"""
    print("\n" + "="*50)
    print("测试 漏洞关联分析引擎")
    print("="*50)

    try:
        from modules.vuln_correlation_engine import (
            get_correlation_engine,
            Vulnerability,
            VulnSeverity
        )

        engine = get_correlation_engine()
        engine.clear()

        # 添加测试漏洞
        engine.add_vulnerability(Vulnerability(
            vuln_type="sqli",
            url="https://example.com/search",
            param="q",
            severity=VulnSeverity.CRITICAL
        ))
        engine.add_vulnerability(Vulnerability(
            vuln_type="xss",
            url="https://example.com/comment",
            param="content",
            severity=VulnSeverity.HIGH
        ))

        # 分析关联
        analysis = engine.analyze_correlations()
        print(f"✓ 发现漏洞: {analysis['found_vulns']}")
        print(f"✓ 关联关系: {len(analysis['correlations'])} 个")
        print(f"✓ 利用链: {len(analysis['exploit_chains'])} 条")

        if analysis['exploit_chains']:
            chain = analysis['exploit_chains'][0]
            print(f"  最佳利用链: {chain['name']}")

        # 风险评分
        risk = analysis['risk_score']
        print(f"✓ 风险评分: {risk['score']}/100 ({risk['level']})")

        # 下一步建议
        suggestions = engine.suggest_next_tests()
        print(f"✓ 下一步测试建议: {len(suggestions)} 个")

        return True
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False


def test_smart_cache():
    """测试智能缓存"""
    print("\n" + "="*50)
    print("测试 智能缓存系统")
    print("="*50)

    try:
        from modules.smart_cache import get_smart_cache

        cache = get_smart_cache()

        # 测试DNS缓存
        cache.cache_dns("example.com", ["1.2.3.4", "5.6.7.8"])
        result = cache.get_dns("example.com")
        print(f"✓ DNS缓存: {result}")

        # 测试技术栈缓存
        cache.cache_tech("https://example.com", {"language": "php"})
        result = cache.get_tech("https://example.com")
        print(f"✓ 技术栈缓存: {result}")

        # 获取统计
        stats = cache.stats()
        print(f"✓ 缓存统计: {json.dumps(stats['dns'], indent=2)}")

        # 清理
        cleaned = cache.cleanup()
        print(f"✓ 清理过期: {cleaned}")

        return True
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False


def test_performance_monitor():
    """测试性能监控"""
    print("\n" + "="*50)
    print("测试 性能监控模块")
    print("="*50)

    try:
        from modules.performance_monitor import get_performance_monitor

        monitor = get_performance_monitor()

        # 模拟执行
        with monitor.track("test_tool_1"):
            time.sleep(0.1)

        with monitor.track("test_tool_2"):
            time.sleep(0.2)

        # 获取统计
        summary = monitor.get_summary()
        print(f"✓ 总调用次数: {summary['total_calls']}")
        print(f"✓ 平均执行时间: {summary['avg_execution_time']}s")

        # 获取工具统计
        stats = monitor.get_tool_stats("test_tool_1")
        print(f"✓ test_tool_1 统计: {stats}")

        # 识别瓶颈
        bottlenecks = monitor.identify_bottlenecks()
        print(f"✓ 瓶颈分析: {len(bottlenecks.get('slow_tools', []))} 个慢工具")

        return True
    except Exception as e:
        print(f"✗ 错误: {e}")
        return False


def main():
    """运行所有测试"""
    print("\n" + "#"*60)
    print("# AutoRedTeam 优化模块测试")
    print("#"*60)

    results = {
        "AI决策引擎": test_ai_decision_engine(),
        "异步扫描器": test_async_scanner(),
        "自适应Payload": test_adaptive_payload(),
        "漏洞关联分析": test_vuln_correlation(),
        "智能缓存": test_smart_cache(),
        "性能监控": test_performance_monitor(),
    }

    print("\n" + "="*60)
    print("测试结果汇总")
    print("="*60)

    passed = 0
    failed = 0
    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n总计: {passed} 通过, {failed} 失败")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
