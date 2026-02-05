"""
core.c2 模块单元测试

测试 C2 通信模块的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import base64

# 模块级别标记 - 标识为单元测试和安全测试
pytestmark = [pytest.mark.unit, pytest.mark.security]


class TestC2Status:
    """测试 C2Status 枚举"""

    def test_status_values(self):
        """测试状态值"""
        from core.c2 import C2Status

        assert C2Status is not None
        # 检查常见状态
        if hasattr(C2Status, 'IDLE'):
            assert C2Status.IDLE is not None
        if hasattr(C2Status, 'CONNECTED'):
            assert C2Status.CONNECTED is not None
        if hasattr(C2Status, 'RUNNING'):
            assert C2Status.RUNNING is not None


class TestTunnelType:
    """测试 TunnelType 枚举"""

    def test_tunnel_types(self):
        """测试隧道类型"""
        from core.c2 import TunnelType

        assert TunnelType is not None
        # 检查常见类型
        if hasattr(TunnelType, 'HTTP'):
            assert TunnelType.HTTP is not None
        if hasattr(TunnelType, 'DNS'):
            assert TunnelType.DNS is not None
        if hasattr(TunnelType, 'WEBSOCKET'):
            assert TunnelType.WEBSOCKET is not None


class TestC2Config:
    """测试 C2Config 配置类"""

    def test_default_config(self):
        """测试默认配置"""
        from core.c2 import C2Config

        config = C2Config(server="test.example.com")

        assert config is not None
        assert config.server == "test.example.com"

    def test_custom_config(self):
        """测试自定义配置"""
        from core.c2 import C2Config

        config = C2Config(
            server="c2.example.com",
            port=443
        )

        assert config.server == "c2.example.com"
        assert config.port == 443


class TestTask:
    """测试 Task 类"""

    def test_task_creation(self):
        """测试任务创建"""
        from core.c2 import Task

        task = Task(
            id="task-001",
            type="shell",
            payload="whoami"
        )

        assert task is not None
        assert task.id == "task-001"

    def test_task_to_dict(self):
        """测试任务转字典"""
        from core.c2 import Task

        task = Task(
            id="task-001",
            type="shell",
            payload="whoami"
        )

        if hasattr(task, 'to_dict'):
            task_dict = task.to_dict()
            assert isinstance(task_dict, dict)


class TestTaskResult:
    """测试 TaskResult 类"""

    def test_result_creation(self):
        """测试任务结果创建"""
        from core.c2 import TaskResult

        result = TaskResult(
            task_id="task-001",
            success=True,
            output="NT AUTHORITY\\SYSTEM"
        )

        assert result is not None
        assert result.success is True

    def test_result_failure(self):
        """测试失败结果"""
        from core.c2 import TaskResult

        result = TaskResult(
            task_id="task-001",
            success=False,
            error="Command not found"
        )

        assert result.success is False
        assert result.error == "Command not found"


class TestBeaconInfo:
    """测试 BeaconInfo 类"""

    def test_beacon_info_creation(self):
        """测试 Beacon 信息创建"""
        from core.c2 import BeaconInfo

        info = BeaconInfo(
            beacon_id="beacon-001",
            hostname="WORKSTATION-01",
            username="admin"
        )

        assert info is not None
        assert info.beacon_id == "beacon-001"


class TestBeaconConfig:
    """测试 BeaconConfig 类"""

    def test_beacon_config_creation(self):
        """测试 Beacon 配置创建"""
        from core.c2 import BeaconConfig

        config = BeaconConfig(
            server="c2.example.com",
            port=443,
            protocol="https"
        )

        assert config is not None
        assert config.server == "c2.example.com"

    def test_beacon_config_interval(self):
        """测试心跳间隔配置"""
        from core.c2 import BeaconConfig

        config = BeaconConfig(
            server="c2.example.com",
            interval=60
        )

        assert config.interval == 60


class TestBeaconMode:
    """测试 BeaconMode 枚举"""

    def test_beacon_modes(self):
        """测试 Beacon 模式"""
        from core.c2 import BeaconMode

        assert BeaconMode is not None
        # 检查常见模式
        if hasattr(BeaconMode, 'INTERACTIVE'):
            assert BeaconMode.INTERACTIVE is not None
        if hasattr(BeaconMode, 'SLEEP'):
            assert BeaconMode.SLEEP is not None


class TestBeacon:
    """测试 Beacon 类"""

    def test_beacon_creation(self):
        """测试 Beacon 创建"""
        from core.c2 import Beacon, BeaconConfig

        config = BeaconConfig(
            server="c2.example.com",
            port=443
        )
        beacon = Beacon(config=config)

        assert beacon is not None

    def test_create_beacon_function(self):
        """测试 create_beacon 函数"""
        from core.c2 import create_beacon

        beacon = create_beacon("c2.example.com")

        assert beacon is not None


class TestHTTPTunnel:
    """测试 HTTPTunnel 类"""

    def test_http_tunnel_creation(self):
        """测试 HTTP 隧道创建"""
        from core.c2 import HTTPTunnel, C2Config

        config = C2Config(
            server="c2.example.com",
            port=443
        )
        tunnel = HTTPTunnel(config)

        assert tunnel is not None

    def test_http_tunnel_url(self):
        """测试 HTTP 隧道 URL"""
        from core.c2 import HTTPTunnel, C2Config

        config = C2Config(
            server="c2.example.com",
            port=443,
            protocol="https"
        )
        tunnel = HTTPTunnel(config)

        if hasattr(tunnel, 'url'):
            assert "https" in tunnel.url or "c2.example.com" in tunnel.url


class TestDNSTunnel:
    """测试 DNSTunnel 类"""

    def test_dns_tunnel_creation(self):
        """测试 DNS 隧道创建"""
        from core.c2 import DNSTunnel, C2Config

        config = C2Config(
            server="c2.example.com",
            port=53
        )
        tunnel = DNSTunnel(config)

        assert tunnel is not None


class TestWebSocketTunnel:
    """测试 WebSocketTunnel 类"""

    def test_websocket_tunnel_creation(self):
        """测试 WebSocket 隧道创建"""
        from core.c2 import WebSocketTunnel, C2Config

        config = C2Config(
            server="c2.example.com",
            port=443
        )
        tunnel = WebSocketTunnel(config)

        assert tunnel is not None


class TestTunnelRegistry:
    """测试隧道注册表"""

    def test_list_available_tunnels(self):
        """测试列出可用隧道"""
        from core.c2 import list_available_tunnels

        tunnels = list_available_tunnels()

        assert isinstance(tunnels, (list, dict))
        assert len(tunnels) > 0

    def test_get_tunnel_class(self):
        """测试获取隧道类"""
        from core.c2 import get_tunnel_class

        http_class = get_tunnel_class("http")

        assert http_class is not None

    def test_create_tunnel(self):
        """测试创建隧道"""
        from core.c2 import create_tunnel

        tunnel = create_tunnel("http", "c2.example.com", 443)

        assert tunnel is not None


class TestC2Crypto:
    """测试 C2Crypto 加密类"""

    def test_crypto_creation(self):
        """测试加密器创建"""
        from core.c2 import C2Crypto

        crypto = C2Crypto()

        assert crypto is not None

    def test_crypto_with_algorithm(self):
        """测试指定算法"""
        from core.c2 import C2Crypto

        crypto = C2Crypto(algorithm="aes256_gcm")

        assert crypto is not None

    def test_encrypt_decrypt(self):
        """测试加密解密"""
        from core.c2 import C2Crypto

        crypto = C2Crypto()
        plaintext = b"secret message"

        if hasattr(crypto, 'encrypt') and hasattr(crypto, 'decrypt'):
            encrypted = crypto.encrypt(plaintext)

            if encrypted is not None:
                # 解密
                if hasattr(encrypted, 'ciphertext'):
                    decrypted = crypto.decrypt(
                        encrypted.ciphertext,
                        encrypted.iv if hasattr(encrypted, 'iv') else None,
                        encrypted.tag if hasattr(encrypted, 'tag') else None
                    )
                    assert decrypted == plaintext

    def test_quick_encrypt(self):
        """测试快速加密"""
        from core.c2 import quick_encrypt, quick_decrypt
        import os

        plaintext = b"test data"
        key = os.urandom(32)  # 256-bit key

        encrypted = quick_encrypt(plaintext, key)
        assert encrypted is not None

        decrypted = quick_decrypt(encrypted, key)
        assert decrypted == plaintext


class TestCryptoAlgorithm:
    """测试 CryptoAlgorithm 枚举"""

    def test_crypto_algorithms(self):
        """测试加密算法"""
        from core.c2 import CryptoAlgorithm

        assert CryptoAlgorithm is not None


class TestC2Encoder:
    """测试 C2Encoder 编码类"""

    def test_encoder_creation(self):
        """测试编码器创建"""
        from core.c2 import C2Encoder

        encoder = C2Encoder()

        assert encoder is not None

    def test_base64_encode(self):
        """测试 Base64 编码"""
        from core.c2 import base64_encode, base64_decode

        data = b"test data"

        encoded = base64_encode(data)
        assert encoded is not None

        decoded = base64_decode(encoded)
        assert decoded == data

    def test_base32_encode(self):
        """测试 Base32 编码"""
        from core.c2 import base32_encode, base32_decode

        data = b"test data"

        encoded = base32_encode(data)
        assert encoded is not None

        decoded = base32_decode(encoded)
        assert decoded == data

    def test_url_safe_encode(self):
        """测试 URL 安全编码"""
        from core.c2 import url_safe_encode, url_safe_decode

        data = b"test data with special chars: +/="

        encoded = url_safe_encode(data)
        assert encoded is not None
        assert "+" not in encoded
        assert "/" not in encoded

        decoded = url_safe_decode(encoded)
        assert decoded == data


class TestEncodingType:
    """测试 EncodingType 枚举"""

    def test_encoding_types(self):
        """测试编码类型"""
        from core.c2 import EncodingType

        assert EncodingType is not None


class TestChunkEncoder:
    """测试 ChunkEncoder 类"""

    def test_chunk_encoder_creation(self):
        """测试分块编码器创建"""
        from core.c2 import ChunkEncoder

        encoder = ChunkEncoder()

        assert encoder is not None

    def test_chunk_encoding(self):
        """测试分块编码"""
        from core.c2 import ChunkEncoder

        encoder = ChunkEncoder(chunk_size=10)
        data = b"This is a long message that needs to be chunked"

        if hasattr(encoder, 'encode'):
            chunks = encoder.encode(data)
            assert isinstance(chunks, (list, tuple))


class TestTrafficObfuscator:
    """测试 TrafficObfuscator 类"""

    def test_obfuscator_creation(self):
        """测试流量混淆器创建"""
        from core.c2 import TrafficObfuscator

        obfuscator = TrafficObfuscator()

        assert obfuscator is not None


class TestProtocol:
    """测试协议相关"""

    def test_protocol_constants(self):
        """测试协议常量"""
        from core.c2 import PROTOCOL_MAGIC, PROTOCOL_VERSION, HEADER_SIZE

        assert PROTOCOL_MAGIC is not None
        assert PROTOCOL_VERSION is not None
        assert HEADER_SIZE > 0

    def test_message_type(self):
        """测试消息类型"""
        from core.c2 import MessageType

        assert MessageType is not None

    def test_message_flags(self):
        """测试消息标志"""
        from core.c2 import MessageFlags

        assert MessageFlags is not None

    def test_message_header(self):
        """测试消息头"""
        from core.c2 import MessageHeader

        header = MessageHeader()

        assert header is not None

    def test_message(self):
        """测试消息"""
        from core.c2 import Message, MessageHeader

        header = MessageHeader()
        msg = Message(header=header, payload=b"test")

        assert msg is not None

    def test_protocol_codec(self):
        """测试协议编解码器"""
        from core.c2 import ProtocolCodec

        codec = ProtocolCodec()

        assert codec is not None


class TestProtocolFunctions:
    """测试协议函数"""

    def test_encode_heartbeat(self):
        """测试编码心跳"""
        from core.c2 import encode_heartbeat

        heartbeat = encode_heartbeat(beacon_id="test-beacon-001")

        assert heartbeat is not None

    def test_decode_heartbeat(self):
        """测试解码心跳"""
        from core.c2 import encode_heartbeat, decode_heartbeat

        encoded = encode_heartbeat(beacon_id="test-beacon-001")

        if encoded:
            decoded = decode_heartbeat(encoded)
            assert decoded is not None

    def test_encode_tasks(self):
        """测试编码任务"""
        from core.c2 import encode_tasks, Task

        tasks = [
            Task(id="1", type="shell", payload="whoami")
        ]

        encoded = encode_tasks(tasks)

        assert encoded is not None

    def test_encode_result(self):
        """测试编码结果"""
        from core.c2 import encode_result, TaskResult

        result = TaskResult(
            task_id="1",
            success=True,
            output="test"
        )

        encoded = encode_result(result)

        assert encoded is not None


class TestHTTPProtocolAdapter:
    """测试 HTTP 协议适配器"""

    def test_adapter_creation(self):
        """测试适配器创建"""
        from core.c2 import HTTPProtocolAdapter

        adapter = HTTPProtocolAdapter()

        assert adapter is not None


class TestBackwardCompatibility:
    """测试向后兼容性"""

    def test_light_beacon_alias(self):
        """测试 LightBeacon 别名"""
        from core.c2 import LightBeacon, Beacon

        assert LightBeacon is Beacon

    def test_tunnel_config_alias(self):
        """测试 TunnelConfig 别名"""
        from core.c2 import TunnelConfig, C2Config

        assert TunnelConfig is C2Config


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
