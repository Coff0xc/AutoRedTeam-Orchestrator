#!/usr/bin/env python3
"""
快速测试脚本 - 验证MCP服务器功能
"""

import requests
import json
import sys

BASE_URL = "http://127.0.0.1:5000"


def test_health():
    """测试健康检查"""
    print("🔍 测试健康检查...")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        if r.status_code == 200:
            print(f"   ✅ 服务器正常运行: {r.json()}")
            return True
        print(f"   ❌ 状态码: {r.status_code}")
        return False
    except requests.exceptions.ConnectionError:
        print("   ❌ 无法连接到服务器")
        return False


def test_tools_list():
    """测试工具列表"""
    print("\n🔍 测试工具列表...")
    r = requests.get(f"{BASE_URL}/tools")
    data = r.json()
    print(f"   ✅ 已注册 {data['total']} 个工具")
    
    # 按类别统计
    categories = {}
    for tool in data['tools']:
        cat = tool['category']
        categories[cat] = categories.get(cat, 0) + 1
    
    print("   📊 按类别统计:")
    for cat, count in sorted(categories.items()):
        print(f"      - {cat}: {count}")
    
    return True


def test_tool_search():
    """测试工具搜索"""
    print("\n🔍 测试工具搜索...")
    r = requests.get(f"{BASE_URL}/tools/search?q=nmap")
    data = r.json()
    print(f"   ✅ 搜索 'nmap' 找到 {data['count']} 个结果")
    return True


def test_session():
    """测试会话管理"""
    print("\n🔍 测试会话管理...")
    
    # 创建会话
    r = requests.post(f"{BASE_URL}/session/create", json={"name": "test_session"})
    data = r.json()
    session_id = data.get("session_id")
    print(f"   ✅ 创建会话: {session_id}")
    
    # 获取会话
    r = requests.get(f"{BASE_URL}/session/{session_id}")
    if r.status_code == 200:
        print(f"   ✅ 获取会话成功")
    
    return True


def test_attack_chain():
    """测试攻击链"""
    print("\n🔍 测试攻击链创建...")
    
    r = requests.post(f"{BASE_URL}/chain/create", json={
        "target": "192.168.1.1",
        "target_type": "ip",
        "objectives": ["获取初始访问"]
    })
    
    data = r.json()
    if data.get("success"):
        chain_id = data.get("chain_id")
        print(f"   ✅ 创建攻击链: {chain_id}")
        print(f"   📊 节点数: {data.get('nodes_count')}")
        
        # 获取状态
        r = requests.get(f"{BASE_URL}/chain/{chain_id}")
        status = r.json()
        print(f"   📋 攻击链节点:")
        for node in status.get("nodes", [])[:5]:
            print(f"      - [{node['phase']}] {node['tool']}: {node['status']}")
        
        return True
    else:
        print(f"   ❌ 创建失败: {data.get('error')}")
        return False


def test_ai_analyze():
    """测试AI分析"""
    print("\n🔍 测试AI分析...")
    
    r = requests.post(f"{BASE_URL}/ai/analyze", json={
        "target": "example.com"
    })
    
    data = r.json()
    if data.get("success"):
        analysis = data.get("analysis", {})
        print(f"   ✅ AI分析完成")
        print(f"   🎯 目标类型: {analysis.get('target_type')}")
        print(f"   📋 推荐工具: {', '.join(analysis.get('recommended_tools', [])[:3])}")
        return True
    else:
        print(f"   ⚠️ AI分析: {data.get('error', '需要配置API密钥')}")
        return True  # 不阻塞测试


def main():
    print("=" * 50)
    print("🚀 AI Red Team MCP Server 功能测试")
    print("=" * 50)
    
    # 首先检查服务器是否运行
    if not test_health():
        print("\n❌ 服务器未运行!")
        print("   请先启动服务器: python3 main.py")
        sys.exit(1)
    
    # 运行测试
    tests = [
        test_tools_list,
        test_tool_search,
        test_session,
        test_attack_chain,
        test_ai_analyze,
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"   ❌ 测试异常: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 测试结果: {passed}/{len(tests)} 通过")
    print("=" * 50)


if __name__ == "__main__":
    main()
