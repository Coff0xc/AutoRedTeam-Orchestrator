#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分块传输器 - 绕过流量大小检测
支持数据分块、校验、重传、压缩
"""

import asyncio
import base64
import gzip
import hashlib
import random
import time
from typing import Callable, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class TransferStats:
    """传输统计信息"""
    total_chunks: int = 0
    sent_chunks: int = 0
    retries: int = 0
    start_time: float = 0
    end_time: float = 0

    @property
    def duration(self) -> float:
        """传输耗时"""
        return self.end_time - self.start_time if self.end_time > 0 else 0

    @property
    def success_rate(self) -> float:
        """成功率"""
        return (self.sent_chunks / self.total_chunks * 100) if self.total_chunks > 0 else 0


class ChunkedTransfer:
    """
    分块传输器

    功能:
    1. 数据分块传输（绕过流量大小检测）
    2. 序列号和MD5校验
    3. 随机延迟（Jitter）
    4. 丢包重传机制
    5. 数据压缩支持
    """

    def __init__(
        self,
        chunk_size: int = 1024,
        delay_range: Tuple[float, float] = (0.5, 2.0),
        max_retries: int = 3,
        enable_compression: bool = True
    ):
        """
        初始化分块传输器

        Args:
            chunk_size: 每块数据大小（字节）
            delay_range: 延迟范围（秒）
            max_retries: 最大重试次数
            enable_compression: 是否启用压缩
        """
        self.chunk_size = chunk_size
        self.delay_range = delay_range
        self.max_retries = max_retries
        self.enable_compression = enable_compression
        self.stats = TransferStats()

    def _compress_data(self, data: bytes) -> bytes:
        """压缩数据"""
        if self.enable_compression:
            return gzip.compress(data)
        return data

    def _decompress_data(self, data: bytes) -> bytes:
        """解压数据"""
        if self.enable_compression:
            try:
                return gzip.decompress(data)
            except gzip.BadGzipFile:
                return data
        return data

    def _calculate_checksum(self, data: bytes) -> str:
        """计算MD5校验和"""
        return hashlib.md5(data).hexdigest()

    def split_data(self, data: bytes) -> List[dict]:
        """
        分割数据为多个块

        Args:
            data: 原始数据

        Returns:
            分块列表
        """
        # 压缩数据
        compressed_data = self._compress_data(data)

        # 分块
        chunks = []
        total_chunks = (len(compressed_data) + self.chunk_size - 1) // self.chunk_size

        for i in range(total_chunks):
            start = i * self.chunk_size
            end = min((i + 1) * self.chunk_size, len(compressed_data))
            chunk_data = compressed_data[start:end]

            chunk = {
                "seq": i,
                "total": total_chunks,
                "checksum": self._calculate_checksum(chunk_data),
                "data": base64.b64encode(chunk_data).decode(),
                "timestamp": int(time.time()),
                "compressed": self.enable_compression
            }
            chunks.append(chunk)

        return chunks

    def reassemble_data(self, chunks: List[dict]) -> Optional[bytes]:
        """
        重组数据

        Args:
            chunks: 分块列表

        Returns:
            原始数据或None（校验失败）
        """
        # 按序列号排序
        sorted_chunks = sorted(chunks, key=lambda x: x["seq"])

        # 检查完整性
        total = sorted_chunks[0]["total"] if sorted_chunks else 0
        if len(sorted_chunks) != total:
            return None

        # 重组数据
        reassembled = b""
        for chunk in sorted_chunks:
            chunk_data = base64.b64decode(chunk["data"])

            # 校验和验证
            if self._calculate_checksum(chunk_data) != chunk["checksum"]:
                return None

            reassembled += chunk_data

        # 解压数据
        if sorted_chunks[0].get("compressed", False):
            return self._decompress_data(reassembled)
        return reassembled

    async def _send_with_retry(
        self,
        chunk: dict,
        send_func: Callable,
        retry_count: int = 0
    ) -> bool:
        """
        带重试的发送

        Args:
            chunk: 分块数据
            send_func: 发送函数
            retry_count: 当前重试次数

        Returns:
            是否成功
        """
        try:
            # 调用发送函数
            result = await send_func(chunk)
            return result
        except (asyncio.TimeoutError, ConnectionError, OSError):
            if retry_count < self.max_retries:
                self.stats.retries += 1
                await asyncio.sleep(random.uniform(*self.delay_range))
                return await self._send_with_retry(chunk, send_func, retry_count + 1)
            return False

    async def send_chunked(
        self,
        data: bytes,
        send_func: Callable
    ) -> bool:
        """
        分块发送数据

        Args:
            data: 原始数据
            send_func: 发送函数 async def send(chunk: dict) -> bool

        Returns:
            是否全部发送成功
        """
        # 初始化统计
        self.stats = TransferStats()
        self.stats.start_time = time.time()

        # 分割数据
        chunks = self.split_data(data)
        self.stats.total_chunks = len(chunks)

        # 发送分块
        for chunk in chunks:
            # 随机延迟（Jitter）
            await asyncio.sleep(random.uniform(*self.delay_range))

            # 发送
            success = await self._send_with_retry(chunk, send_func)
            if success:
                self.stats.sent_chunks += 1
            else:
                self.stats.end_time = time.time()
                return False

        self.stats.end_time = time.time()
        return True

    async def receive_chunked(
        self,
        receive_func: Callable,
        timeout: float = 60.0
    ) -> Optional[bytes]:
        """
        接收分块数据

        Args:
            receive_func: 接收函数 async def receive() -> dict
            timeout: 接收超时（秒）

        Returns:
            原始数据或None
        """
        chunks = []
        start_time = time.time()

        # 接收第一个块（获取总块数）
        try:
            first_chunk = await asyncio.wait_for(receive_func(), timeout=timeout)
            total_chunks = first_chunk["total"]
            chunks.append(first_chunk)
        except asyncio.TimeoutError:
            return None

        # 接收剩余块
        while len(chunks) < total_chunks:
            if time.time() - start_time > timeout:
                return None

            try:
                chunk = await asyncio.wait_for(
                    receive_func(),
                    timeout=max(1.0, timeout - (time.time() - start_time))
                )
                chunks.append(chunk)
            except asyncio.TimeoutError:
                return None

        # 重组数据
        return self.reassemble_data(chunks)

    def get_stats(self) -> dict:
        """
        获取传输统计信息

        Returns:
            统计信息字典
        """
        return {
            "total_chunks": self.stats.total_chunks,
            "sent_chunks": self.stats.sent_chunks,
            "retries": self.stats.retries,
            "duration": round(self.stats.duration, 2),
            "success_rate": round(self.stats.success_rate, 2)
        }
