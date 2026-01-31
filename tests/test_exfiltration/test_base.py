#!/usr/bin/env python3
"""
数据外泄基类测试
"""

import pytest
from core.exfiltration.base import (
    ExfilChannel,
    ExfilStatus,
    EncryptionType,
    ExfilConfig,
    ExfilProgress,
    ExfilResult,
)


class TestExfilChannel:
    """测试外泄通道枚举"""

    def test_channels_exist(self):
        """测试所有通道都存在"""
        assert ExfilChannel.HTTP.value == 'http'
        assert ExfilChannel.HTTPS.value == 'https'
        assert ExfilChannel.DNS.value == 'dns'
        assert ExfilChannel.ICMP.value == 'icmp'
        assert ExfilChannel.SMB.value == 'smb'

    def test_all_channels_have_values(self):
        """测试所有通道都有值"""
        for channel in ExfilChannel:
            assert channel.value is not None
            assert len(channel.value) > 0


class TestExfilStatus:
    """测试外泄状态枚举"""

    def test_statuses_exist(self):
        """测试所有状态都存在"""
        assert ExfilStatus.IDLE.value == 'idle'
        assert ExfilStatus.PREPARING.value == 'preparing'
        assert ExfilStatus.TRANSFERRING.value == 'transferring'
        assert ExfilStatus.COMPLETED.value == 'completed'
        assert ExfilStatus.FAILED.value == 'failed'
        assert ExfilStatus.PAUSED.value == 'paused'


class TestEncryptionType:
    """测试加密类型枚举"""

    def test_encryption_types_exist(self):
        """测试所有加密类型都存在"""
        assert EncryptionType.NONE.value == 'none'
        assert EncryptionType.XOR.value == 'xor'
        assert EncryptionType.AES_256_GCM.value == 'aes256gcm'
        assert EncryptionType.CHACHA20_POLY1305.value == 'chacha20'


class TestExfilConfig:
    """测试外泄配置数据类"""

    def test_default_config(self):
        """测试默认配置"""
        config = ExfilConfig()

        assert config.channel == ExfilChannel.HTTPS
        assert config.destination == ''
        assert config.encryption is True
        assert config.chunk_size == 4096
        assert config.rate_limit == 0.0
        assert config.retry_count == 3
        assert config.timeout == 30.0
        assert config.stealth is False

    def test_custom_config(self):
        """测试自定义配置"""
        config = ExfilConfig(
            channel=ExfilChannel.DNS,
            destination='exfil.example.com',
            encryption=False,
            chunk_size=1024,
            stealth=True
        )

        assert config.channel == ExfilChannel.DNS
        assert config.destination == 'exfil.example.com'
        assert config.encryption is False
        assert config.chunk_size == 1024
        assert config.stealth is True

    def test_dns_specific_config(self):
        """测试DNS特定配置"""
        config = ExfilConfig(
            channel=ExfilChannel.DNS,
            dns_domain='data.attacker.com',
            dns_subdomain_length=32
        )

        assert config.dns_domain == 'data.attacker.com'
        assert config.dns_subdomain_length == 32


class TestExfilProgress:
    """测试外泄进度数据类"""

    def test_progress_creation(self):
        """测试创建进度对象"""
        progress = ExfilProgress(
            total_size=10000,
            transferred=5000,
            chunks_sent=5,
            current_speed=1000.0
        )

        assert progress.total_size == 10000
        assert progress.transferred == 5000
        assert progress.chunks_sent == 5
        assert progress.progress_percent == 50.0

    def test_progress_percentage_calculation(self):
        """测试进度百分比计算"""
        progress = ExfilProgress(
            total_size=1000,
            transferred=250
        )
        assert progress.progress_percent == 25.0

        progress2 = ExfilProgress(
            total_size=0,
            transferred=0
        )
        assert progress2.progress_percent == 0.0

    def test_progress_to_dict(self):
        """测试进度转换为字典"""
        progress = ExfilProgress(
            total_size=10000,
            transferred=7500,
            chunks_sent=10
        )

        d = progress.to_dict()

        assert d['total_size'] == 10000
        assert d['transferred'] == 7500
        assert d['chunks_sent'] == 10
        assert d['progress_percent'] == 75.0


class TestExfilResult:
    """测试外泄结果数据类"""

    def test_successful_result(self):
        """测试成功的外泄结果"""
        result = ExfilResult(
            success=True,
            channel=ExfilChannel.HTTPS,
            total_size=10000,
            transferred=10000,
            duration=5.0,
            chunks_sent=10
        )

        assert result.success is True
        assert result.channel == ExfilChannel.HTTPS
        assert result.total_size == 10000
        assert result.transferred == 10000
        assert result.chunks_sent == 10
        assert bool(result) is True

    def test_failed_result(self):
        """测试失败的外泄结果"""
        result = ExfilResult(
            success=False,
            channel=ExfilChannel.DNS,
            total_size=10000,
            transferred=3000,
            error="Channel blocked by firewall"
        )

        assert result.success is False
        assert result.transferred == 3000
        assert result.error == "Channel blocked by firewall"
        assert bool(result) is False

    def test_to_dict(self):
        """测试转换为字典"""
        result = ExfilResult(
            success=True,
            channel=ExfilChannel.HTTPS,
            total_size=10000,
            transferred=10000,
            duration=2.5,
            chunks_sent=10
        )

        d = result.to_dict()

        assert d['success'] is True
        assert d['channel'] == 'https'
        assert d['total_size'] == 10000
        assert d['transferred'] == 10000
        assert d['duration'] == 2.5
        assert d['transfer_rate'] == 4000.0  # 10000 / 2.5


class TestExfilResultTransferRate:
    """测试传输速率计算"""

    def test_transfer_rate_calculation(self):
        """测试传输速率计算"""
        result = ExfilResult(
            success=True,
            channel=ExfilChannel.HTTPS,
            transferred=10000,
            duration=5.0
        )

        d = result.to_dict()
        assert d['transfer_rate'] == 2000.0

    def test_transfer_rate_zero_duration(self):
        """测试零时长时的传输速率"""
        result = ExfilResult(
            success=True,
            channel=ExfilChannel.HTTPS,
            transferred=10000,
            duration=0.0
        )

        d = result.to_dict()
        assert d['transfer_rate'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
