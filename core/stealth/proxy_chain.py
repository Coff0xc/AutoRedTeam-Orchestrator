#!/usr/bin/env python3
"""
代理链执行增强模块 - Enhanced Proxy Chain Executor
功能: 多级代理链、智能轮换、健康检查、负载均衡、失败自动恢复
"""

import asyncio
import random
import time
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import json
import tempfile
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# 尝试导入请求库
try:
    import requests
    from requests.exceptions import RequestException, ProxyError, Timeout
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    logger.warning("requests not installed, limited functionality")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from PySocks import socks  # 需要 PySocks 库支持 SOCKS 代理
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False
    logger.debug("PySocks not installed, SOCKS proxy support disabled")

# 导入代理池模块
try:
    from .proxy_pool import Proxy, ProxyType, ProxyPool, ProxyAnonymity, ProxyValidator
except ImportError:
    from proxy_pool import Proxy, ProxyType, ProxyPool, ProxyAnonymity, ProxyValidator


class ChainStrategy(Enum):
    """代理链策略"""
    STRICT = "strict"  # 严格模式 - 必须全部经过所有代理
    DYNAMIC = "dynamic"  # 动态模式 - 跳过失效代理
    RANDOM = "random"  # 随机模式 - 随机选择代理链路
    FAILOVER = "failover"  # 故障转移 - 失败自动切换下一个链


class LoadBalanceMode(Enum):
    """负载均衡模式"""
    ROUND_ROBIN = "round_robin"  # 轮询
    RANDOM = "random"  # 随机
    WEIGHTED = "weighted"  # 加权 (基于成功率)
    LEAST_USED = "least_used"  # 最少使用


@dataclass
class ChainMetrics:
    """代理链指标"""
    total_requests: int = 0
    success_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0.0
    last_used: float = 0.0

    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.total_requests == 0:
            return 0.0
        return self.success_requests / self.total_requests

    @property
    def avg_response_time(self) -> float:
        """平均响应时间"""
        if self.success_requests == 0:
            return 0.0
        return self.total_response_time / self.success_requests


class ProxyChain:
    """
    增强版代理链管理器

    Usage:
        # 创建代理链
        chain = ProxyChain(name="chain1", strategy=ChainStrategy.DYNAMIC)

        # 添加代理节点
        chain.add_proxy("http://proxy1.com:8080")
        chain.add_proxy("socks5://proxy2.com:1080")

        # 发送请求
        response = chain.request("https://example.com", method="GET")

        # 获取链状态
        status = chain.get_status()
    """

    def __init__(self,
                 name: str = "default",
                 strategy: ChainStrategy = ChainStrategy.DYNAMIC,
                 max_retry: int = 3,
                 timeout: float = 30.0,
                 jitter: Tuple[float, float] = (0.5, 2.0)):
        """
        Args:
            name: 链名称
            strategy: 代理链策略
            max_retry: 最大重试次数
            timeout: 请求超时时间(秒)
            jitter: 请求延迟抖动范围(秒)
        """
        self.name = name
        self.strategy = strategy
        self.max_retry = max_retry
        self.timeout = timeout
        self.jitter = jitter

        self._proxies: List[Proxy] = []
        self._metrics = ChainMetrics()
        self._enabled = True

    def add_proxy(self, proxy_url: str) -> bool:
        """
        添加代理到链

        Args:
            proxy_url: 代理URL (如 "http://host:port" 或 "socks5://user:pass@host:port")

        Returns:
            是否添加成功
        """
        pool = ProxyPool(auto_validate=False)
        temp_proxy = pool._parse_proxy_string(proxy_url)

        if not temp_proxy:
            logger.error(f"Invalid proxy URL: {proxy_url}")
            return False

        # 检查重复
        if temp_proxy in self._proxies:
            logger.debug(f"Proxy already in chain: {proxy_url}")
            return False

        self._proxies.append(temp_proxy)
        logger.info(f"[{self.name}] Added proxy: {proxy_url}")
        return True

    def remove_proxy(self, index: int) -> bool:
        """
        移除代理节点

        Args:
            index: 代理索引

        Returns:
            是否移除成功
        """
        if 0 <= index < len(self._proxies):
            removed = self._proxies.pop(index)
            logger.info(f"[{self.name}] Removed proxy at index {index}: {removed.url}")
            return True
        logger.warning(f"[{self.name}] Invalid proxy index: {index}")
        return False

    def get_chain(self) -> List[str]:
        """
        获取当前代理链

        Returns:
            代理URL列表
        """
        return [p.url for p in self._proxies]

    def rotate(self):
        """轮换代理顺序 (将第一个移到最后)"""
        if len(self._proxies) > 1:
            self._proxies.append(self._proxies.pop(0))
            logger.debug(f"[{self.name}] Rotated proxy chain")

    def verify_proxy(self, proxy_url: str, timeout: float = 10.0) -> Tuple[bool, float]:
        """
        验证单个代理是否可用

        Args:
            proxy_url: 代理URL
            timeout: 超时时间

        Returns:
            (是否可用, 响应时间)
        """
        if not HAS_REQUESTS:
            logger.warning("requests not installed, cannot verify proxy")
            return True, 0.0

        validator = ProxyValidator(timeout=timeout)
        pool = ProxyPool(auto_validate=False)
        proxy = pool._parse_proxy_string(proxy_url)

        if not proxy:
            return False, 0.0

        return validator.validate_sync(proxy)

    def verify_all(self, timeout: float = 10.0) -> Dict[str, Any]:
        """
        验证链中所有代理

        Returns:
            验证结果统计
        """
        results = {
            "total": len(self._proxies),
            "valid": 0,
            "invalid": 0,
            "details": []
        }

        for i, proxy in enumerate(self._proxies):
            is_valid, response_time = self.verify_proxy(proxy.url, timeout)
            proxy.is_valid = is_valid
            proxy.response_time = response_time

            if is_valid:
                results["valid"] += 1
            else:
                results["invalid"] += 1

            results["details"].append({
                "index": i,
                "url": proxy.url,
                "valid": is_valid,
                "response_time": response_time
            })

        logger.info(f"[{self.name}] Verified {results['valid']}/{results['total']} proxies")
        return results

    def request_through_chain(self,
                             url: str,
                             method: str = "GET",
                             use_jitter: bool = True,
                             auto_cleanup: bool = True,
                             **kwargs) -> Optional[requests.Response]:
        """
        通过代理链发送请求

        注意: 标准 HTTP 库不支持真正的代理链 (Client -> Proxy1 -> Proxy2 -> Target)
              此方法实现的是依次尝试不同代理，非嵌套代理链

        Args:
            url: 目标URL
            method: HTTP方法
            use_jitter: 是否使用延迟抖动
            auto_cleanup: 自动清理失效代理
            **kwargs: 传递给 requests 的其他参数

        Returns:
            响应对象或 None
        """
        if not HAS_REQUESTS:
            logger.error("requests not installed")
            return None

        if not self._enabled:
            logger.warning(f"[{self.name}] Chain is disabled")
            return None

        if not self._proxies:
            logger.error(f"[{self.name}] No proxies in chain")
            return None

        # 延迟抖动
        if use_jitter:
            delay = random.uniform(*self.jitter)
            time.sleep(delay)

        # 获取有效代理列表
        valid_proxies = [p for p in self._proxies if p.is_valid] if auto_cleanup else self._proxies

        if not valid_proxies:
            logger.error(f"[{self.name}] No valid proxies available")
            return None

        # 根据策略选择代理
        if self.strategy == ChainStrategy.RANDOM:
            selected_proxies = [random.choice(valid_proxies)]
        elif self.strategy == ChainStrategy.FAILOVER:
            selected_proxies = valid_proxies  # 尝试所有代理直到成功
        else:  # STRICT / DYNAMIC
            selected_proxies = valid_proxies

        # 依次尝试代理
        last_error = None
        for attempt in range(self.max_retry):
            for proxy in selected_proxies:
                try:
                    start_time = time.time()

                    # 设置代理
                    kwargs.setdefault("proxies", proxy.dict_format)
                    kwargs.setdefault("timeout", self.timeout)
                    kwargs.setdefault("verify", False)  # 某些代理有SSL问题

                    # 发送请求
                    response = requests.request(method, url, **kwargs)
                    response_time = time.time() - start_time

                    # 更新代理统计
                    proxy.success_count += 1
                    proxy.response_time = response_time

                    # 更新链统计
                    self._metrics.total_requests += 1
                    self._metrics.success_requests += 1
                    self._metrics.total_response_time += response_time
                    self._metrics.last_used = time.time()

                    logger.info(f"[{self.name}] Request success via {proxy.url} ({response_time:.2f}s)")
                    return response

                except (ProxyError, Timeout, RequestException) as e:
                    last_error = e
                    proxy.fail_count += 1

                    logger.debug(f"[{self.name}] Request failed via {proxy.url}: {e}")

                    # 标记失效代理
                    if auto_cleanup and proxy.fail_count >= 3:
                        proxy.is_valid = False
                        logger.warning(f"[{self.name}] Proxy marked invalid: {proxy.url}")

                    # STRICT 模式下失败即停止
                    if self.strategy == ChainStrategy.STRICT:
                        break

                    # FAILOVER 模式下继续尝试下一个
                    continue

            # 重试延迟
            if attempt < self.max_retry - 1:
                retry_delay = random.uniform(1, 3)
                logger.debug(f"[{self.name}] Retrying in {retry_delay:.1f}s (attempt {attempt+1}/{self.max_retry})")
                time.sleep(retry_delay)

        # 所有尝试失败
        self._metrics.total_requests += 1
        self._metrics.failed_requests += 1
        logger.error(f"[{self.name}] All proxy attempts failed: {last_error}")
        return None

    def request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """快捷方法 - 通过代理链发送请求"""
        return self.request_through_chain(url, method, **kwargs)

    def get_status(self) -> Dict[str, Any]:
        """获取代理链状态"""
        return {
            "name": self.name,
            "strategy": self.strategy.value,
            "enabled": self._enabled,
            "proxy_count": len(self._proxies),
            "valid_proxies": sum(1 for p in self._proxies if p.is_valid),
            "chain": [
                {
                    "url": p.url,
                    "type": p.proxy_type.value,
                    "valid": p.is_valid,
                    "success_rate": p.success_rate,
                    "response_time": p.response_time,
                }
                for p in self._proxies
            ],
            "metrics": {
                "total_requests": self._metrics.total_requests,
                "success_requests": self._metrics.success_requests,
                "failed_requests": self._metrics.failed_requests,
                "success_rate": self._metrics.success_rate,
                "avg_response_time": self._metrics.avg_response_time,
                "last_used": self._metrics.last_used,
            }
        }

    def enable(self):
        """启用代理链"""
        self._enabled = True
        logger.info(f"[{self.name}] Chain enabled")

    def disable(self):
        """禁用代理链"""
        self._enabled = False
        logger.info(f"[{self.name}] Chain disabled")

    def clear(self):
        """清空代理链"""
        self._proxies.clear()
        logger.info(f"[{self.name}] Chain cleared")

    def export_proxychains_config(self, filepath: str):
        """
        导出 proxychains 配置文件

        注意: 这适用于需要真正代理链的场景 (需要配合 proxychains 工具使用)
        """
        lines = [
            f"# ProxyChain Configuration: {self.name}",
            "# Generated by AutoRedTeam-Orchestrator",
            "",
            "dynamic_chain" if self.strategy == ChainStrategy.DYNAMIC else "strict_chain",
            "proxy_dns",
            f"tcp_read_time_out {int(self.timeout * 1000)}",
            f"tcp_connect_time_out {int(self.timeout * 1000)}",
            "",
            "[ProxyList]",
        ]

        for proxy in self._proxies:
            proxy_type = proxy.proxy_type.value
            if proxy_type == "https":
                proxy_type = "http"

            if proxy.username and proxy.password:
                lines.append(
                    f"{proxy_type} {proxy.host} {proxy.port} {proxy.username} {proxy.password}"
                )
            else:
                lines.append(f"{proxy_type} {proxy.host} {proxy.port}")

        config = '\n'.join(lines)
        Path(filepath).write_text(config, encoding='utf-8')
        logger.info(f"[{self.name}] Exported proxychains config to {filepath}")


class ProxyChainManager:
    """
    代理链管理器 - 管理多个代理链

    Usage:
        manager = ProxyChainManager()

        # 创建代理链
        manager.create_chain("chain1", strategy=ChainStrategy.DYNAMIC)
        manager.add_proxy_to_chain("chain1", "http://proxy1.com:8080")

        # 发送请求 (自动负载均衡)
        response = manager.request("https://example.com")

        # 获取统计
        stats = manager.get_stats()
    """

    def __init__(self,
                 pool: Optional[ProxyPool] = None,
                 load_balance: LoadBalanceMode = LoadBalanceMode.ROUND_ROBIN):
        """
        Args:
            pool: 代理池 (可选)
            load_balance: 负载均衡模式
        """
        self._chains: Dict[str, ProxyChain] = {}
        self._pool = pool
        self._load_balance = load_balance
        self._chain_queue = deque()  # 用于 round-robin

    def create_chain(self,
                    name: str,
                    strategy: ChainStrategy = ChainStrategy.DYNAMIC,
                    **kwargs) -> ProxyChain:
        """创建代理链"""
        if name in self._chains:
            logger.warning(f"Chain '{name}' already exists")
            return self._chains[name]

        chain = ProxyChain(name=name, strategy=strategy, **kwargs)
        self._chains[name] = chain
        self._chain_queue.append(name)

        logger.info(f"Created chain: {name}")
        return chain

    def remove_chain(self, name: str) -> bool:
        """移除代理链"""
        if name in self._chains:
            del self._chains[name]
            if name in self._chain_queue:
                self._chain_queue.remove(name)
            logger.info(f"Removed chain: {name}")
            return True
        return False

    def get_chain(self, name: str) -> Optional[ProxyChain]:
        """获取代理链"""
        return self._chains.get(name)

    def add_proxy_to_chain(self, chain_name: str, proxy_url: str) -> bool:
        """添加代理到指定链"""
        chain = self.get_chain(chain_name)
        if chain:
            return chain.add_proxy(proxy_url)
        logger.error(f"Chain not found: {chain_name}")
        return False

    def integrate_proxy_pool(self, pool: ProxyPool, chain_name: str, count: int = 5) -> int:
        """
        从代理池集成代理到链

        Args:
            pool: 代理池
            chain_name: 目标链名称
            count: 添加数量

        Returns:
            实际添加数量
        """
        chain = self.get_chain(chain_name)
        if not chain:
            logger.error(f"Chain not found: {chain_name}")
            return 0

        added = 0
        for _ in range(count):
            proxy = pool.get_proxy(strategy="fastest")
            if proxy:
                chain.add_proxy(proxy.url)
                added += 1

        logger.info(f"Integrated {added} proxies from pool to chain '{chain_name}'")
        return added

    def select_chain(self) -> Optional[ProxyChain]:
        """根据负载均衡策略选择链"""
        if not self._chains:
            return None

        # 只选择启用的链
        enabled_chains = [c for c in self._chains.values() if c._enabled]
        if not enabled_chains:
            return None

        if self._load_balance == LoadBalanceMode.RANDOM:
            return random.choice(enabled_chains)

        elif self._load_balance == LoadBalanceMode.ROUND_ROBIN:
            # 轮询
            while self._chain_queue:
                name = self._chain_queue[0]
                self._chain_queue.rotate(-1)  # 移到队尾

                chain = self._chains.get(name)
                if chain and chain._enabled:
                    return chain
            return None

        elif self._load_balance == LoadBalanceMode.WEIGHTED:
            # 基于成功率加权
            weights = [max(0.1, c._metrics.success_rate) for c in enabled_chains]
            return random.choices(enabled_chains, weights=weights, k=1)[0]

        elif self._load_balance == LoadBalanceMode.LEAST_USED:
            # 选择使用次数最少的
            return min(enabled_chains, key=lambda c: c._metrics.total_requests)

        return enabled_chains[0]

    def request(self, url: str, method: str = "GET", chain_name: Optional[str] = None, **kwargs):
        """
        发送请求 (支持自动负载均衡)

        Args:
            url: 目标URL
            method: HTTP方法
            chain_name: 指定链名称 (None=自动选择)
            **kwargs: 传递给 requests 的其他参数
        """
        if chain_name:
            chain = self.get_chain(chain_name)
            if not chain:
                logger.error(f"Chain not found: {chain_name}")
                return None
        else:
            chain = self.select_chain()
            if not chain:
                logger.error("No available chains")
                return None

        return chain.request(url, method, **kwargs)

    def verify_all_chains(self, timeout: float = 10.0) -> Dict[str, Any]:
        """验证所有链中的代理"""
        results = {}
        for name, chain in self._chains.items():
            results[name] = chain.verify_all(timeout)
        return results

    def get_stats(self) -> Dict[str, Any]:
        """获取所有链的统计信息"""
        return {
            "total_chains": len(self._chains),
            "enabled_chains": sum(1 for c in self._chains.values() if c._enabled),
            "load_balance_mode": self._load_balance.value,
            "chains": {name: chain.get_status() for name, chain in self._chains.items()}
        }

    def auto_cleanup(self):
        """自动清理失效代理"""
        cleaned = 0
        for chain in self._chains.values():
            before = len(chain._proxies)
            chain._proxies = [p for p in chain._proxies if p.is_valid]
            cleaned += before - len(chain._proxies)

        if cleaned > 0:
            logger.info(f"Auto cleanup: removed {cleaned} invalid proxies")
        return cleaned


# 便捷函数

def create_chain_from_list(proxies: List[str],
                          name: str = "default",
                          strategy: ChainStrategy = ChainStrategy.DYNAMIC) -> ProxyChain:
    """
    从代理列表创建代理链

    Args:
        proxies: 代理URL列表
        name: 链名称
        strategy: 链策略

    Returns:
        代理链对象
    """
    chain = ProxyChain(name=name, strategy=strategy)
    for proxy_url in proxies:
        chain.add_proxy(proxy_url)
    return chain


def create_chain_from_pool(pool: ProxyPool,
                          count: int = 5,
                          name: str = "pool_chain",
                          strategy: ChainStrategy = ChainStrategy.DYNAMIC) -> ProxyChain:
    """
    从代理池创建代理链

    Args:
        pool: 代理池
        count: 提取代理数量
        name: 链名称
        strategy: 链策略

    Returns:
        代理链对象
    """
    chain = ProxyChain(name=name, strategy=strategy)

    for _ in range(count):
        proxy = pool.get_proxy(strategy="fastest")
        if proxy:
            chain.add_proxy(proxy.url)

    return chain


if __name__ == "__main__":
    # 测试代码
    from utils.logger import configure_root_logger

    configure_root_logger(level=logging.INFO, log_to_file=True, log_to_console=True)

    print("=== ProxyChain Test ===\n")

    # 1. 创建代理链
    chain = ProxyChain(name="test_chain", strategy=ChainStrategy.DYNAMIC)

    # 2. 添加测试代理 (这里使用示例，实际需要真实代理)
    chain.add_proxy("http://127.0.0.1:8080")
    chain.add_proxy("socks5://127.0.0.1:1080")

    print(f"Proxy chain: {chain.get_chain()}")

    # 3. 验证代理
    print("\nVerifying proxies...")
    result = chain.verify_all(timeout=5)
    print(f"Verification result: {json.dumps(result, indent=2)}")

    # 4. 获取状态
    print("\nChain status:")
    status = chain.get_status()
    print(json.dumps(status, indent=2))

    # 5. 测试代理链管理器
    print("\n=== ProxyChainManager Test ===\n")

    manager = ProxyChainManager(load_balance=LoadBalanceMode.ROUND_ROBIN)

    # 创建多个链
    manager.create_chain("chain1", ChainStrategy.DYNAMIC)
    manager.create_chain("chain2", ChainStrategy.FAILOVER)

    manager.add_proxy_to_chain("chain1", "http://proxy1.com:8080")
    manager.add_proxy_to_chain("chain2", "http://proxy2.com:8080")

    # 获取统计
    stats = manager.get_stats()
    print("Manager stats:")
    print(json.dumps(stats, indent=2))

    print("\nTest completed successfully")
