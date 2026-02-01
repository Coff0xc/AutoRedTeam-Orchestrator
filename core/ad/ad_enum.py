# -*- coding: utf-8 -*-
"""
Active Directory 枚举模块 (AD Enumeration)
ATT&CK Technique: T1087 - Account Discovery

纯Python实现的AD枚举工具,支持:
- LDAP匿名/认证查询
- 域用户/组/计算机枚举
- GPO策略枚举
- 信任关系发现
- SPN服务主体名枚举

注意: 仅用于授权的渗透测试和安全研究
"""

import logging

logger = logging.getLogger(__name__)

import base64
import json
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ADObjectType(Enum):
    """AD对象类型"""

    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    OU = "organizationalUnit"
    GPO = "groupPolicyContainer"
    TRUST = "trustedDomain"
    SPN = "servicePrincipalName"


@dataclass
class ADObject:
    """AD对象数据结构"""

    object_type: ADObjectType
    dn: str
    name: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.object_type.value,
            "dn": self.dn,
            "name": self.name,
            "attributes": self.attributes,
        }


@dataclass
class EnumResult:
    """枚举结果"""

    success: bool
    target: str
    object_type: str
    objects: List[ADObject] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "target": self.target,
            "type": self.object_type,
            "count": len(self.objects),
            "objects": [o.to_dict() for o in self.objects],
            "error": self.error,
        }


class SimpleLDAPClient:
    """
    简化的LDAP客户端实现

    使用纯Python实现LDAP协议的基本操作
    """

    # LDAP协议常量
    LDAP_VERSION = 3
    LDAP_BIND_REQUEST = 0x60
    LDAP_BIND_RESPONSE = 0x61
    LDAP_SEARCH_REQUEST = 0x63
    LDAP_SEARCH_RESULT_ENTRY = 0x64
    LDAP_SEARCH_RESULT_DONE = 0x65
    LDAP_UNBIND_REQUEST = 0x42

    def __init__(self, host: str, port: int = 389, use_ssl: bool = False, timeout: int = 10):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock = None
        self.message_id = 0
        self.bound = False

    def _next_message_id(self) -> int:
        """生成下一个消息ID"""
        self.message_id += 1
        return self.message_id

    def _encode_length(self, length: int) -> bytes:
        """编码BER长度"""
        if length < 128:
            return bytes([length])
        else:
            length_bytes = []
            while length > 0:
                length_bytes.insert(0, length & 0xFF)
                length >>= 8
            return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)

    def _decode_length(self, data: bytes, offset: int) -> Tuple[int, int]:
        """解码BER长度"""
        if data[offset] < 128:
            return data[offset], offset + 1
        else:
            num_bytes = data[offset] & 0x7F
            length = 0
            for i in range(num_bytes):
                length = (length << 8) | data[offset + 1 + i]
            return length, offset + 1 + num_bytes

    def _encode_string(self, s: str, tag: int = 0x04) -> bytes:
        """编码LDAP字符串"""
        encoded = s.encode("utf-8")
        return bytes([tag]) + self._encode_length(len(encoded)) + encoded

    def _encode_integer(self, value: int) -> bytes:
        """编码整数"""
        if value == 0:
            return bytes([0x02, 0x01, 0x00])

        result = []
        while value > 0:
            result.insert(0, value & 0xFF)
            value >>= 8

        # 如果最高位是1,需要添加0x00前缀
        if result[0] & 0x80:
            result.insert(0, 0x00)

        return bytes([0x02]) + self._encode_length(len(result)) + bytes(result)

    def _encode_sequence(self, data: bytes, tag: int = 0x30) -> bytes:
        """编码序列"""
        return bytes([tag]) + self._encode_length(len(data)) + data

    def connect(self) -> bool:
        """连接到LDAP服务器"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.sock = context.wrap_socket(self.sock, server_hostname=self.host)

            return True
        except Exception as e:
            return False

    def bind(self, username: str = "", password: str = "") -> bool:
        """
        LDAP绑定 (认证)

        Args:
            username: 用户名 (DN格式或UPN格式)
            password: 密码

        Returns:
            是否绑定成功
        """
        if not self.sock:
            if not self.connect():
                return False

        msg_id = self._next_message_id()

        # 构建Bind Request
        version = self._encode_integer(self.LDAP_VERSION)
        name = self._encode_string(username)
        auth = self._encode_string(password, tag=0x80)  # Simple authentication

        bind_request = version + name + auth
        bind_request = self._encode_sequence(bind_request, tag=self.LDAP_BIND_REQUEST)

        # 封装为LDAP消息
        message = self._encode_integer(msg_id)[1:] + bind_request  # 跳过0x02标签
        message = bytes([0x02]) + self._encode_length(1) + bytes([msg_id]) + bind_request
        message = self._encode_sequence(message)

        try:
            self.sock.send(message)

            # 接收响应
            response = self.sock.recv(4096)
            if len(response) > 10:
                # 简单解析响应,检查resultCode
                # 找到BIND_RESPONSE标签
                for i in range(len(response) - 5):
                    if response[i] == self.LDAP_BIND_RESPONSE:
                        # 找到resultCode (应该是第一个INTEGER)
                        for j in range(i, min(i + 20, len(response) - 2)):
                            if response[j] == 0x0A:  # ENUMERATED (resultCode)
                                length = response[j + 1]
                                result_code = response[j + 2]
                                if result_code == 0:
                                    self.bound = True
                                    return True
                                break
                        break
            return False
        except Exception as e:
            return False

    def search(
        self,
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: int = 2,  # SCOPE_SUBTREE
        attributes: List[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        LDAP搜索

        Args:
            base_dn: 搜索基础DN
            filter_str: LDAP过滤器
            scope: 搜索范围 (0=BASE, 1=ONELEVEL, 2=SUBTREE)
            attributes: 要返回的属性列表

        Returns:
            搜索结果列表
        """
        if not self.bound:
            if not self.bind():
                return []

        msg_id = self._next_message_id()

        # 构建Search Request
        base = self._encode_string(base_dn)
        search_scope = bytes([0x0A, 0x01, scope])  # ENUMERATED
        deref_aliases = bytes([0x0A, 0x01, 0x00])  # neverDerefAliases
        size_limit = self._encode_integer(1000)
        time_limit = self._encode_integer(60)
        types_only = bytes([0x01, 0x01, 0x00])  # FALSE

        # 简单过滤器编码
        filter_encoded = self._encode_filter(filter_str)

        # 属性列表
        attrs_data = b""
        if attributes:
            for attr in attributes:
                attrs_data += self._encode_string(attr)
        attrs_seq = self._encode_sequence(attrs_data)

        search_request = (
            base
            + search_scope
            + deref_aliases
            + size_limit
            + time_limit
            + types_only
            + filter_encoded
            + attrs_seq
        )
        search_request = self._encode_sequence(search_request, tag=self.LDAP_SEARCH_REQUEST)

        # 封装消息
        message = bytes([0x02, 0x01, msg_id]) + search_request
        message = self._encode_sequence(message)

        results = []
        try:
            self.sock.send(message)

            # 接收所有响应
            while True:
                response = self.sock.recv(65535)
                if not response:
                    break

                # 解析响应
                entries, done = self._parse_search_response(response)
                results.extend(entries)

                if done:
                    break

        except socket.timeout:
            logger.debug("LDAP search timed out")
        except Exception as e:
            logger.debug(f"LDAP search failed: {e}")

        return results

    def _encode_filter(self, filter_str: str) -> bytes:
        """
        编码LDAP过滤器

        支持简单过滤器格式: (attribute=value)
        """
        # 简单实现,仅支持等值过滤
        match = re.match(r"\(([^=]+)=([^)]*)\)", filter_str)
        if match:
            attr = match.group(1)
            value = match.group(2)

            if value == "*":
                # Present filter
                return bytes([0x87]) + self._encode_length(len(attr)) + attr.encode("utf-8")
            else:
                # Equality filter
                attr_encoded = self._encode_string(attr)
                value_encoded = self._encode_string(value)
                return self._encode_sequence(attr_encoded + value_encoded, tag=0xA3)

        # 默认返回简单过滤器
        return bytes([0x87]) + self._encode_length(11) + b"objectClass"

    def _parse_search_response(self, data: bytes) -> Tuple[List[Dict], bool]:
        """解析搜索响应"""
        results = []
        done = False

        offset = 0
        while offset < len(data):
            try:
                # 跳过SEQUENCE标签
                if data[offset] != 0x30:
                    offset += 1
                    continue

                offset += 1
                msg_len, offset = self._decode_length(data, offset)

                # 跳过message ID
                if data[offset] == 0x02:
                    offset += 1
                    id_len, offset = self._decode_length(data, offset)
                    offset += id_len

                # 检查响应类型
                response_type = data[offset]

                if response_type == self.LDAP_SEARCH_RESULT_ENTRY:
                    entry = self._parse_search_entry(data, offset)
                    if entry:
                        results.append(entry)

                elif response_type == self.LDAP_SEARCH_RESULT_DONE:
                    done = True
                    break

                offset += 1

            except (IndexError, KeyError, struct.error):
                break

        return results, done

    def _parse_search_entry(self, data: bytes, offset: int) -> Optional[Dict]:
        """解析单个搜索结果条目"""
        try:
            # 跳过标签和长度
            offset += 1
            entry_len, offset = self._decode_length(data, offset)

            # 解析DN
            if data[offset] != 0x04:
                return None
            offset += 1
            dn_len, offset = self._decode_length(data, offset)
            dn = data[offset : offset + dn_len].decode("utf-8", errors="ignore")
            offset += dn_len

            entry = {"dn": dn, "attributes": {}}

            # 解析属性
            if data[offset] == 0x30:
                offset += 1
                attrs_len, offset = self._decode_length(data, offset)
                end_offset = offset + attrs_len

                while offset < end_offset:
                    if data[offset] == 0x30:
                        offset += 1
                        attr_len, offset = self._decode_length(data, offset)

                        # 属性名
                        if data[offset] == 0x04:
                            offset += 1
                            name_len, offset = self._decode_length(data, offset)
                            attr_name = data[offset : offset + name_len].decode(
                                "utf-8", errors="ignore"
                            )
                            offset += name_len

                            # 属性值
                            values = []
                            if data[offset] == 0x31:
                                offset += 1
                                values_len, offset = self._decode_length(data, offset)
                                values_end = offset + values_len

                                while offset < values_end:
                                    if data[offset] == 0x04:
                                        offset += 1
                                        val_len, offset = self._decode_length(data, offset)
                                        value = data[offset : offset + val_len]
                                        try:
                                            values.append(value.decode("utf-8"))
                                        except UnicodeDecodeError:
                                            values.append(base64.b64encode(value).decode("ascii"))
                                        offset += val_len
                                    else:
                                        offset += 1

                            entry["attributes"][attr_name] = values
                        else:
                            offset += 1
                    else:
                        offset += 1

            return entry

        except (IndexError, KeyError, struct.error, UnicodeDecodeError):
            return None

    def close(self):
        """关闭连接"""
        if self.sock:
            try:
                # 发送Unbind
                message = bytes([0x30, 0x05, 0x02, 0x01, self.message_id, 0x42, 0x00])
                self.sock.send(message)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            finally:
                self.sock.close()
                self.sock = None
                self.bound = False


class ADEnumerator:
    """
    Active Directory枚举器

    提供完整的AD枚举功能
    """

    def __init__(
        self,
        domain: str,
        dc_ip: str = None,
        username: str = "",
        password: str = "",
        use_ssl: bool = False,
        verbose: bool = False,
    ):
        """
        初始化AD枚举器

        Args:
            domain: 域名 (如 contoso.com)
            dc_ip: 域控IP (可选,自动解析)
            username: 用户名 (可选,匿名枚举)
            password: 密码
            use_ssl: 是否使用LDAPS
            verbose: 是否输出详细日志
        """
        self.domain = domain
        self.dc_ip = dc_ip or self._resolve_dc()
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.verbose = verbose
        self.base_dn = self._domain_to_dn(domain)
        self.ldap = None

    def _log(self, message: str):
        """日志输出"""
        if self.verbose:
            logger.debug(f"[ADEnum] {message}")

    def _domain_to_dn(self, domain: str) -> str:
        """将域名转换为DN"""
        parts = domain.split(".")
        return ",".join(f"DC={p}" for p in parts)

    def _resolve_dc(self) -> str:
        """解析域控IP"""
        try:
            # 尝试解析常见的DC DNS记录
            dc_names = [f"_ldap._tcp.{self.domain}", f"dc.{self.domain}", self.domain]

            for name in dc_names:
                try:
                    result = socket.gethostbyname(name.replace("_ldap._tcp.", ""))
                    return result
                except (socket.gaierror, socket.herror, OSError):
                    continue

            return self.domain  # 返回域名让后续解析
        except (socket.gaierror, socket.herror, OSError):
            return self.domain

    def connect(self) -> bool:
        """建立LDAP连接"""
        port = 636 if self.use_ssl else 389
        self.ldap = SimpleLDAPClient(self.dc_ip, port, self.use_ssl)

        if not self.ldap.connect():
            self._log(f"Failed to connect to {self.dc_ip}:{port}")
            return False

        # 绑定
        bind_name = ""
        if self.username:
            if "@" not in self.username and "\\" not in self.username:
                bind_name = f"{self.username}@{self.domain}"
            else:
                bind_name = self.username

        if not self.ldap.bind(bind_name, self.password):
            self._log("LDAP bind failed")
            return False

        self._log("LDAP connection established")
        return True

    def enum_users(self, detailed: bool = False) -> EnumResult:
        """
        枚举域用户

        Args:
            detailed: 是否获取详细属性

        Returns:
            枚举结果
        """
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "users", error="Connection failed")

        attributes = ["sAMAccountName", "cn", "mail"]
        if detailed:
            attributes.extend(
                [
                    "userPrincipalName",
                    "description",
                    "memberOf",
                    "lastLogon",
                    "pwdLastSet",
                    "userAccountControl",
                    "adminCount",
                    "servicePrincipalName",
                ]
            )

        results = self.ldap.search(self.base_dn, "(objectClass=user)", attributes=attributes)

        objects = []
        for entry in results:
            attrs = entry.get("attributes", {})
            name = attrs.get("sAMAccountName", [""])[0] or attrs.get("cn", ["Unknown"])[0]

            obj = ADObject(
                object_type=ADObjectType.USER, dn=entry.get("dn", ""), name=name, attributes=attrs
            )
            objects.append(obj)
            self._log(f"Found user: {name}")

        return EnumResult(True, self.dc_ip, "users", objects)

    def enum_groups(self) -> EnumResult:
        """枚举域组"""
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "groups", error="Connection failed")

        results = self.ldap.search(
            self.base_dn,
            "(objectClass=group)",
            attributes=["sAMAccountName", "cn", "description", "member", "memberOf"],
        )

        objects = []
        for entry in results:
            attrs = entry.get("attributes", {})
            name = attrs.get("sAMAccountName", [""])[0] or attrs.get("cn", ["Unknown"])[0]

            obj = ADObject(
                object_type=ADObjectType.GROUP, dn=entry.get("dn", ""), name=name, attributes=attrs
            )
            objects.append(obj)
            self._log(f"Found group: {name}")

        return EnumResult(True, self.dc_ip, "groups", objects)

    def enum_computers(self) -> EnumResult:
        """枚举域计算机"""
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "computers", error="Connection failed")

        results = self.ldap.search(
            self.base_dn,
            "(objectClass=computer)",
            attributes=[
                "cn",
                "dNSHostName",
                "operatingSystem",
                "operatingSystemVersion",
                "lastLogon",
            ],
        )

        objects = []
        for entry in results:
            attrs = entry.get("attributes", {})
            name = attrs.get("cn", ["Unknown"])[0]

            obj = ADObject(
                object_type=ADObjectType.COMPUTER,
                dn=entry.get("dn", ""),
                name=name,
                attributes=attrs,
            )
            objects.append(obj)
            self._log(f"Found computer: {name}")

        return EnumResult(True, self.dc_ip, "computers", objects)

    def enum_domain_admins(self) -> EnumResult:
        """枚举域管理员"""
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "domain_admins", error="Connection failed")

        # 搜索Domain Admins组
        results = self.ldap.search(self.base_dn, "(cn=Domain Admins)", attributes=["member"])

        objects = []
        for entry in results:
            members = entry.get("attributes", {}).get("member", [])
            for member_dn in members:
                # 从DN提取用户名
                cn_match = re.search(r"CN=([^,]+)", member_dn)
                name = cn_match.group(1) if cn_match else member_dn

                obj = ADObject(
                    object_type=ADObjectType.USER,
                    dn=member_dn,
                    name=name,
                    attributes={"memberOf": ["Domain Admins"]},
                )
                objects.append(obj)
                self._log(f"Found Domain Admin: {name}")

        return EnumResult(True, self.dc_ip, "domain_admins", objects)

    def enum_spn(self) -> EnumResult:
        """
        枚举SPN (Service Principal Names)
        用于Kerberoasting攻击的目标发现
        """
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "spn", error="Connection failed")

        # 搜索设置了SPN的用户账户
        results = self.ldap.search(
            self.base_dn,
            "(&(objectClass=user)(servicePrincipalName=*))",
            attributes=["sAMAccountName", "servicePrincipalName", "cn", "memberOf"],
        )

        objects = []
        for entry in results:
            attrs = entry.get("attributes", {})
            name = attrs.get("sAMAccountName", [""])[0]
            spns = attrs.get("servicePrincipalName", [])

            for spn in spns:
                obj = ADObject(
                    object_type=ADObjectType.SPN,
                    dn=entry.get("dn", ""),
                    name=name,
                    attributes={"spn": spn, "account": name, "kerberoastable": True},
                )
                objects.append(obj)
                self._log(f"Found SPN: {spn} ({name})")

        return EnumResult(True, self.dc_ip, "spn", objects)

    def enum_gpo(self) -> EnumResult:
        """枚举GPO (组策略对象)"""
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "gpo", error="Connection failed")

        gpo_base = f"CN=Policies,CN=System,{self.base_dn}"

        results = self.ldap.search(
            gpo_base,
            "(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "cn"],
        )

        objects = []
        for entry in results:
            attrs = entry.get("attributes", {})
            name = attrs.get("displayName", [""])[0] or attrs.get("cn", ["Unknown"])[0]

            obj = ADObject(
                object_type=ADObjectType.GPO, dn=entry.get("dn", ""), name=name, attributes=attrs
            )
            objects.append(obj)
            self._log(f"Found GPO: {name}")

        return EnumResult(True, self.dc_ip, "gpo", objects)

    def enum_trusts(self) -> EnumResult:
        """枚举域信任关系"""
        if not self.ldap or not self.ldap.bound:
            if not self.connect():
                return EnumResult(False, self.dc_ip, "trusts", error="Connection failed")

        results = self.ldap.search(
            f"CN=System,{self.base_dn}",
            "(objectClass=trustedDomain)",
            attributes=["cn", "trustDirection", "trustType", "trustAttributes"],
        )

        objects = []
        for entry in results:
            attrs = entry.get("attributes", {})
            name = attrs.get("cn", ["Unknown"])[0]

            obj = ADObject(
                object_type=ADObjectType.TRUST, dn=entry.get("dn", ""), name=name, attributes=attrs
            )
            objects.append(obj)
            self._log(f"Found trust: {name}")

        return EnumResult(True, self.dc_ip, "trusts", objects)

    def enum_all(self) -> Dict[str, EnumResult]:
        """执行完整枚举"""
        results = {}

        results["users"] = self.enum_users(detailed=True)
        results["groups"] = self.enum_groups()
        results["computers"] = self.enum_computers()
        results["domain_admins"] = self.enum_domain_admins()
        results["spn"] = self.enum_spn()
        results["gpo"] = self.enum_gpo()
        results["trusts"] = self.enum_trusts()

        return results

    def close(self):
        """关闭连接"""
        if self.ldap:
            self.ldap.close()


# 便捷函数
def ad_enumerate(
    domain: str,
    dc_ip: str = None,
    username: str = "",
    password: str = "",
    enum_type: str = "all",
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    AD枚举便捷函数

    Args:
        domain: 域名
        dc_ip: 域控IP
        username: 用户名 (可选)
        password: 密码 (可选)
        enum_type: 枚举类型 (users/groups/computers/spn/gpo/trusts/all)
        verbose: 是否输出详细日志

    Returns:
        枚举结果字典
    """
    enumerator = ADEnumerator(
        domain=domain, dc_ip=dc_ip, username=username, password=password, verbose=verbose
    )

    try:
        if enum_type == "all":
            results = enumerator.enum_all()
            return {k: v.to_dict() for k, v in results.items()}
        elif enum_type == "users":
            return enumerator.enum_users(detailed=True).to_dict()
        elif enum_type == "groups":
            return enumerator.enum_groups().to_dict()
        elif enum_type == "computers":
            return enumerator.enum_computers().to_dict()
        elif enum_type == "spn":
            return enumerator.enum_spn().to_dict()
        elif enum_type == "gpo":
            return enumerator.enum_gpo().to_dict()
        elif enum_type == "trusts":
            return enumerator.enum_trusts().to_dict()
        elif enum_type == "domain_admins":
            return enumerator.enum_domain_admins().to_dict()
        else:
            return {"error": f"Unknown enum type: {enum_type}"}
    finally:
        enumerator.close()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        logger.info("Usage: python ad_enum.py <domain> [dc_ip] [username]")
        logger.info("Example: python ad_enum.py contoso.com 192.168.1.1 admin")
        logger.info("Password will be prompted or read from AD_PASSWORD env var")
        sys.exit(1)

    import getpass as _getpass

    domain = sys.argv[1]
    dc_ip = sys.argv[2] if len(sys.argv) > 2 else None
    username = sys.argv[3] if len(sys.argv) > 3 else ""
    # 安全方式获取密码：优先环境变量，否则提示输入
    password = os.environ.get("AD_PASSWORD", "")
    if not password and username:
        password = _getpass.getpass(f"Password for {username}: ")

    logger.info(f"=== AD Enumeration: {domain} ===")
    result = ad_enumerate(domain, dc_ip, username, password, "all", verbose=True)
    logger.info(json.dumps(result, indent=2, ensure_ascii=False))
