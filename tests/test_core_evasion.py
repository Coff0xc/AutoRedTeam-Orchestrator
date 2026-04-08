"""
core/evasion 模块测试

测试目标:
- PayloadObfuscator: 各编码器的编码/解码可逆性、多层混淆
- CodeTransformer: 垃圾代码注入、字符串编码、代码压缩
- ShellcodeObfuscator: XOR混淆可逆性、NOP sled、垃圾指令插入
- WAFBypassEngine: 大小写变换、URL编码绕过、空格替代、SQL/XSS bypass
- VariableObfuscator: 变量名混淆
"""

import base64

import pytest

from core.evasion.payload_obfuscator import (
    Base64Encoder,
    CodeTransformer,
    EncodingType,
    HexEncoder,
    ObfuscationResult,
    PayloadObfuscator,
    ROT13Encoder,
    ShellcodeObfuscator,
    VariableObfuscator,
    XOREncoder,
    obfuscate_payload,
    obfuscate_python_code,
)
from core.evasion.waf_bypass_engine import (
    BypassResult,
    BypassTechnique,
    ChunkedEncoder,
    HeaderManipulator,
    PathNormalizer,
    PayloadMutator,
    WAFBypassEngine,
    WAFDetector,
    WAFFingerprint,
    WAFType,
    bypass_waf,
    detect_waf,
    normalize_waf_type,
)


# ==================== PayloadObfuscator 测试 ====================


@pytest.mark.unit
class TestXOREncoder:
    """XOR 编码器测试"""

    def test_xor_encode_decode_reversible(self):
        """XOR 编码/解码可逆性"""
        encoder = XOREncoder(key="testkey123")
        original = b"Hello World! This is a test payload."
        encoded = encoder.encode(original)
        decoded = encoder.decode(encoded)
        assert decoded == original

    def test_xor_encode_changes_data(self):
        """XOR 编码后数据应改变"""
        encoder = XOREncoder(key="secret")
        original = b"plain text data"
        encoded = encoder.encode(original)
        assert encoded != original

    def test_xor_auto_key_generation(self):
        """未指定 key 时自动生成"""
        encoder = XOREncoder()
        assert len(encoder.key) == 16
        assert encoder.key.isalnum()

    def test_xor_get_decoder_code(self):
        """解码器代码生成"""
        encoder = XOREncoder(key="k")
        code = encoder.get_decoder_code("payload")
        assert "payload" in code
        assert "_xd" in code


@pytest.mark.unit
class TestBase64Encoder:
    """Base64 编码器测试"""

    def test_base64_encode_decode_reversible(self):
        """Base64 编码/解码可逆性"""
        encoder = Base64Encoder()
        original = b"print('hello world')"
        encoded = encoder.encode(original)
        decoded = encoder.decode(encoded)
        assert decoded == original

    def test_base64_encode_output_valid(self):
        """编码输出是合法 Base64"""
        encoder = Base64Encoder()
        encoded = encoder.encode(b"test data")
        # 验证可以被标准 base64 解码
        base64.b64decode(encoded)


@pytest.mark.unit
class TestHexEncoder:
    """Hex 编码器测试"""

    def test_hex_encode_decode_reversible(self):
        """Hex 编码/解码可逆性"""
        encoder = HexEncoder()
        original = b"\x00\x01\xff\xfe binary data"
        encoded = encoder.encode(original)
        decoded = encoder.decode(encoded)
        assert decoded == original


@pytest.mark.unit
class TestROT13Encoder:
    """ROT13 编码器测试"""

    def test_rot13_double_apply_is_identity(self):
        """ROT13 应用两次等于原文"""
        encoder = ROT13Encoder()
        original = b"Hello World ABCxyz"
        encoded = encoder.encode(original)
        decoded = encoder.decode(encoded)
        assert decoded == original

    def test_rot13_preserves_non_alpha(self):
        """ROT13 保留非字母字符"""
        encoder = ROT13Encoder()
        original = b"123!@#"
        encoded = encoder.encode(original)
        assert encoded == original


@pytest.mark.unit
class TestPayloadObfuscator:
    """PayloadObfuscator 主类测试"""

    def test_obfuscate_xor_returns_success(self):
        """XOR 混淆返回成功结果"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate("print('hello')", EncodingType.XOR)
        assert isinstance(result, ObfuscationResult)
        assert result.success is True
        assert result.original_size == len("print('hello')")
        assert result.obfuscated_size > 0
        assert result.encoding == "xor"

    def test_obfuscate_base64_returns_success(self):
        """Base64 混淆返回成功结果"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate("print('test')", EncodingType.BASE64)
        assert result.success is True
        assert "base64" in result.decoder

    def test_obfuscate_rot13(self):
        """ROT13 混淆"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate("test", EncodingType.ROT13)
        assert result.success is True

    def test_obfuscate_with_custom_key(self):
        """使用自定义密钥混淆"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate("payload", EncodingType.XOR, key="mykey")
        assert result.success is True
        assert result.key == "mykey"

    def test_obfuscate_without_decoder(self):
        """不添加解码器的混淆"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate("test", EncodingType.BASE64, add_decoder=False)
        assert result.success is True
        assert result.decoder == ""

    def test_obfuscate_multilayer(self):
        """多层混淆"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate_multilayer(
            "print('hello')",
            encodings=[EncodingType.XOR, EncodingType.BASE64],
        )
        assert result.success is True
        assert result.layers == 2
        assert "xor" in result.encoding
        assert "base64" in result.encoding

    def test_obfuscate_multilayer_default_encodings(self):
        """多层混淆使用默认编码"""
        obfuscator = PayloadObfuscator()
        result = obfuscator.obfuscate_multilayer("test payload")
        assert result.success is True
        assert result.layers == 2

    def test_unsupported_encoding_error(self):
        """不支持的编码类型（AES 无 pycryptodome 时）失败处理"""
        obfuscator = PayloadObfuscator()
        # 若 AES 不在 _encoders 中，应返回失败
        if EncodingType.AES not in obfuscator._encoders:
            result = obfuscator.obfuscate("test", EncodingType.AES)
            assert result.success is False


@pytest.mark.unit
class TestVariableObfuscator:
    """变量名混淆器测试"""

    def test_obfuscate_code_renames_variables(self):
        """混淆代码中的变量名"""
        obfuscator = VariableObfuscator(prefix="_")
        code = "x = 10\ny = x + 5"
        obfuscated, mapping = obfuscator.obfuscate_code(code)
        # 原始变量名应被替换
        assert "x" in mapping or "y" in mapping
        # 映射中的新变量名以 _ 开头
        for new_name in mapping.values():
            assert new_name.startswith("_")

    def test_obfuscate_preserves_builtins(self):
        """混淆不影响内置名称"""
        obfuscator = VariableObfuscator()
        code = "print('hello')"
        obfuscated, mapping = obfuscator.obfuscate_code(code)
        # print 不应被替换
        assert "print" not in mapping

    def test_obfuscate_invalid_syntax_returns_original(self):
        """语法错误的代码返回原始代码"""
        obfuscator = VariableObfuscator()
        code = "def (invalid syntax"
        obfuscated, mapping = obfuscator.obfuscate_code(code)
        assert obfuscated == code
        assert mapping == {}


# ==================== CodeTransformer 测试 ====================


@pytest.mark.unit
class TestCodeTransformer:
    """代码变形器测试"""

    def test_string_to_chr_concat(self):
        """字符串转 chr() 拼接"""
        result = CodeTransformer.string_to_chr_concat("AB")
        assert result == "chr(65)+chr(66)"

    def test_string_to_hex_decode(self):
        """字符串转十六进制解码"""
        result = CodeTransformer.string_to_hex_decode("Hi")
        assert "bytes.fromhex" in result
        assert "4869" in result  # "Hi" 的 hex

    def test_compress_code_valid_python(self):
        """compress_code 输出是合法 Python 语法"""
        code = "x = 1\nprint(x)"
        result = CodeTransformer.compress_code(code)
        assert "zlib" in result
        assert "base64" in result
        assert "exec" in result
        # 验证是合法 Python 语法（能编译）
        compile(result, "<test>", "exec")

    def test_add_junk_code_increases_length(self):
        """添加垃圾代码后长度增长"""
        code = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5"
        # ratio=1.0 保证每行都插入垃圾
        result = CodeTransformer.add_junk_code(code, ratio=1.0)
        assert len(result) > len(code)

    def test_add_junk_code_preserves_original_lines(self):
        """垃圾代码不修改原始行"""
        code = "x = 1\ny = 2"
        result = CodeTransformer.add_junk_code(code, ratio=1.0)
        assert "x = 1" in result
        assert "y = 2" in result

    def test_obfuscate_strings(self):
        """字符串混淆"""
        code = 'x = "hi"'
        result = CodeTransformer.obfuscate_strings(code)
        # 短字符串使用 chr() 拼接
        assert "chr(" in result


# ==================== ShellcodeObfuscator 测试 ====================


@pytest.mark.unit
class TestShellcodeObfuscator:
    """Shellcode 混淆器测试"""

    def test_xor_shellcode_reversible(self):
        """XOR shellcode 混淆可逆性"""
        original = b"\xcc\x90\x31\xc0\x50\x68"
        obfuscated, key = ShellcodeObfuscator.xor_shellcode(original)
        # 用相同 key 解密
        restored = bytes([obfuscated[i] ^ key[i % len(key)] for i in range(len(obfuscated))])
        assert restored == original

    def test_xor_shellcode_with_custom_key(self):
        """使用自定义 key 的 XOR 混淆"""
        original = b"\x90\x90\x90"
        key = b"\xff"
        obfuscated, used_key = ShellcodeObfuscator.xor_shellcode(original, key)
        assert used_key == key
        assert obfuscated == bytes([0x90 ^ 0xff] * 3)

    def test_add_nop_sled_length(self):
        """NOP sled 长度正确"""
        shellcode = b"\xcc\x31\xc0"
        result = ShellcodeObfuscator.add_nop_sled(shellcode, length=32)
        assert len(result) == 32 + len(shellcode)
        assert result[:32] == b"\x90" * 32
        assert result[32:] == shellcode

    def test_add_nop_sled_default_length(self):
        """默认 NOP sled 长度为 16"""
        shellcode = b"\xcc"
        result = ShellcodeObfuscator.add_nop_sled(shellcode)
        assert len(result) == 16 + 1
        assert result[:16] == b"\x90" * 16

    def test_insert_garbage_increases_size(self):
        """插入垃圾指令后大小增长"""
        shellcode = b"\x90" * 100
        # ratio=1.0 保证每字节都插入垃圾
        result = ShellcodeObfuscator.insert_garbage(shellcode, ratio=1.0)
        assert len(result) > len(shellcode)

    def test_insert_garbage_preserves_original_bytes(self):
        """垃圾指令不替换原始字节（原始字节仍在结果中按序出现）"""
        shellcode = b"\xaa\xbb\xcc"
        result = ShellcodeObfuscator.insert_garbage(shellcode, ratio=0.0)
        # ratio=0 不插入垃圾，结果应与原始一致
        assert result == shellcode


# ==================== 便捷函数测试 ====================


@pytest.mark.unit
class TestConvenienceFunctions:
    """便捷函数测试"""

    def test_obfuscate_payload_xor(self):
        """obfuscate_payload XOR 模式"""
        result = obfuscate_payload("echo hello", encoding="xor")
        assert result["success"] is True
        assert result["encoding"] == "xor"
        assert len(result["payload"]) > 0

    def test_obfuscate_payload_multilayer(self):
        """obfuscate_payload 多层模式"""
        result = obfuscate_payload("test", encoding="base64", multilayer=True)
        assert result["success"] is True
        assert result["layers"] == 2

    def test_obfuscate_python_code_full(self):
        """obfuscate_python_code 完整流程"""
        code = 'x = "hello"\nprint(x)'
        result = obfuscate_python_code(code, compress=False)
        assert result["success"] is True
        assert result["obfuscated_size"] >= result["original_size"]

    def test_obfuscate_python_code_compress(self):
        """obfuscate_python_code 压缩模式"""
        code = "x = 1\nprint(x)"
        result = obfuscate_python_code(code, compress=True)
        assert result["success"] is True
        assert "zlib" in result["code"]


# ==================== WAFBypassEngine 测试 ====================


@pytest.mark.unit
class TestPayloadMutator:
    """Payload 变异器测试"""

    def setup_method(self):
        self.mutator = PayloadMutator()

    def test_random_case(self):
        """随机大小写变换"""
        payload = "SELECT * FROM users"
        result = self.mutator.mutate(payload, "random_case")
        assert result.lower() == payload.lower()
        # 长字符串几乎不可能完全一致（极小概率通过）
        assert len(result) == len(payload)

    def test_alternating_case(self):
        """交替大小写"""
        payload = "select"
        result = self.mutator.mutate(payload, "alternating_case")
        # 偶数索引小写，奇数索引大写
        assert result == "sElEcT"

    def test_url_encode(self):
        """URL 编码"""
        payload = "' OR 1=1--"
        result = self.mutator.mutate(payload, "url_encode")
        assert "%" in result
        assert "'" not in result

    def test_double_url_encode(self):
        """双重 URL 编码"""
        payload = "<script>"
        result = self.mutator.mutate(payload, "double_url_encode")
        assert "%25" in result

    def test_whitespace_tab(self):
        """Tab 替换空格"""
        payload = "SELECT * FROM users"
        result = self.mutator.mutate(payload, "whitespace_tab")
        assert "\t" in result
        assert " " not in result

    def test_whitespace_newline(self):
        """换行符替换空格"""
        payload = "SELECT * FROM users"
        result = self.mutator.mutate(payload, "whitespace_newline")
        assert "\n" in result

    def test_sql_comment_inline(self):
        """SQL 行内注释"""
        payload = "UNION SELECT * FROM users"
        result = self.mutator.mutate(payload, "comment_inline")
        assert "/**/" in result

    def test_sql_comment_multiline(self):
        """多行注释替换空格"""
        payload = "SELECT * FROM users"
        result = self.mutator.mutate(payload, "comment_multiline")
        assert result == "SELECT/**/*/**/FROM/**/users"

    def test_html_entity_encode(self):
        """HTML 实体编码"""
        payload = "<script>"
        result = self.mutator.mutate(payload, "html_entity")
        assert "&#" in result

    def test_mutate_unknown_technique_returns_original(self):
        """未知变异技术返回原始 payload"""
        payload = "test"
        result = self.mutator.mutate(payload, "nonexistent_technique")
        assert result == payload

    def test_mutate_multi(self):
        """多重变异按顺序执行"""
        payload = "SELECT * FROM users"
        result = self.mutator.mutate_multi(payload, ["whitespace_tab", "url_encode"])
        assert "%" in result  # URL 编码了 tab 等字符

    def test_generate_variants(self):
        """生成 payload 变体"""
        payload = "' OR 1=1--"
        variants = self.mutator.generate_variants(payload, max_variants=10)
        assert len(variants) >= 1
        # 第一个是原始 payload
        assert variants[0][0] == payload
        assert variants[0][1] == []


@pytest.mark.unit
class TestWAFDetector:
    """WAF 检测器测试"""

    def setup_method(self):
        self.detector = WAFDetector()

    def test_detect_cloudflare(self):
        """检测 Cloudflare WAF"""
        headers = {"cf-ray": "abc123", "cf-cache-status": "dynamic"}
        result = self.detector.detect(headers, "checking your browser", 403)
        assert result.waf_type == WAFType.CLOUDFLARE
        assert result.confidence > 0.0

    def test_detect_unknown_waf(self):
        """无法识别的 WAF 返回 UNKNOWN"""
        headers = {"Content-Type": "text/html"}
        result = self.detector.detect(headers, "normal page", 200)
        assert result.waf_type == WAFType.UNKNOWN

    def test_detect_modsecurity(self):
        """检测 ModSecurity"""
        headers = {"x-mod-security": "detected"}
        result = self.detector.detect(headers, "modsecurity request rejected", 403)
        assert result.confidence > 0.0


@pytest.mark.unit
class TestWAFBypassEngine:
    """WAF 绕过引擎主类测试"""

    def setup_method(self):
        self.engine = WAFBypassEngine()

    def test_generate_bypass_unknown_waf(self):
        """为未知 WAF 生成绕过 payload"""
        results = self.engine.generate_bypass("' OR 1=1--", WAFType.UNKNOWN)
        assert isinstance(results, list)
        assert len(results) > 0
        for r in results:
            assert isinstance(r, BypassResult)
            assert r.original_payload == "' OR 1=1--"
            assert r.bypassed_payload != ""

    def test_generate_bypass_cloudflare(self):
        """为 Cloudflare 生成绕过 payload"""
        results = self.engine.generate_bypass("SELECT * FROM users", WAFType.CLOUDFLARE)
        assert len(results) > 0

    def test_generate_bypass_xss_payload(self):
        """XSS bypass payload 生成"""
        results = self.engine.generate_bypass("<script>alert(1)</script>", WAFType.UNKNOWN)
        assert len(results) > 0
        # 变体应与原始不同
        for r in results:
            assert r.bypassed_payload != "<script>alert(1)</script>"

    def test_generate_bypass_sqli_payload(self):
        """SQL 注入 bypass payload 生成"""
        results = self.engine.generate_bypass("1 UNION SELECT username FROM users", WAFType.MODSECURITY)
        assert len(results) > 0

    def test_generate_chunked_bypass(self):
        """Chunked Transfer Encoding 绕过"""
        result = self.engine.generate_chunked_bypass(
            "alert(1)", "data=PAYLOAD_PLACEHOLDER"
        )
        assert "Transfer-Encoding" in result["headers"]
        assert result["body_normal"].endswith(b"0\r\n\r\n")

    def test_generate_header_bypass(self):
        """请求头绕过"""
        results = self.engine.generate_header_bypass("/admin")
        assert isinstance(results, list)
        assert len(results) > 0
        for r in results:
            assert "headers" in r
            assert "technique" in r

    def test_generate_path_bypass(self):
        """路径绕过变体"""
        results = self.engine.generate_path_bypass("/admin/config")
        assert isinstance(results, list)
        assert "/admin/config" in results  # 包含原始路径
        assert len(results) > 1  # 有额外变体

    def test_get_recommended_techniques_no_stats(self):
        """无统计时返回默认策略"""
        techniques = self.engine.get_recommended_techniques(WAFType.CLOUDFLARE)
        assert isinstance(techniques, list)
        assert len(techniques) > 0

    def test_update_stats_and_recommend(self):
        """更新统计后推荐正确排序"""
        self.engine._update_stats(WAFType.UNKNOWN, BypassTechnique.ENCODING, True)
        self.engine._update_stats(WAFType.UNKNOWN, BypassTechnique.ENCODING, True)
        self.engine._update_stats(WAFType.UNKNOWN, BypassTechnique.HEADER_INJECTION, False)
        techniques = self.engine.get_recommended_techniques(WAFType.UNKNOWN)
        assert techniques[0] == "encoding"


@pytest.mark.unit
class TestChunkedEncoder:
    """Chunked 编码器测试"""

    def test_encode_basic(self):
        """基本 chunked 编码"""
        data = "ABC"
        result = ChunkedEncoder.encode(data, chunk_size=1)
        # 每个字符一个 chunk + 结束标记
        assert result.endswith(b"0\r\n\r\n")
        assert b"1\r\nA\r\n" in result

    def test_encode_with_junk(self):
        """带垃圾扩展的 chunked 编码"""
        data = "test"
        result = ChunkedEncoder.encode_with_junk(data, chunk_size=1, junk_ratio=1.0)
        assert result.endswith(b"0\r\n\r\n")


@pytest.mark.unit
class TestHeaderManipulator:
    """请求头操纵器测试"""

    def test_get_bypass_headers_all(self):
        """获取所有绕过头"""
        headers = HeaderManipulator.get_bypass_headers("all")
        assert "X-Forwarded-For" in headers
        assert "X-Original-URL" in headers

    def test_get_bypass_headers_category(self):
        """获取特定类别的绕过头"""
        headers = HeaderManipulator.get_bypass_headers("ip_spoof")
        assert "X-Forwarded-For" in headers
        assert "X-Original-URL" not in headers

    def test_get_random_bypass_headers(self):
        """随机选择绕过头"""
        headers = HeaderManipulator.get_random_bypass_headers(count=2)
        assert isinstance(headers, dict)
        assert len(headers) <= 2


@pytest.mark.unit
class TestNormalizeWafType:
    """WAF 类型归一化测试"""

    def test_normalize_cloudflare(self):
        assert normalize_waf_type("cloudflare") == WAFType.CLOUDFLARE

    def test_normalize_case_insensitive(self):
        assert normalize_waf_type("CloudFlare") == WAFType.CLOUDFLARE

    def test_normalize_alias(self):
        assert normalize_waf_type("incapsula") == WAFType.IMPERVA
        assert normalize_waf_type("big-ip") == WAFType.F5_BIGIP

    def test_normalize_none(self):
        assert normalize_waf_type(None) == WAFType.UNKNOWN

    def test_normalize_waf_type_passthrough(self):
        """已经是 WAFType 时直接返回"""
        assert normalize_waf_type(WAFType.AKAMAI) == WAFType.AKAMAI


@pytest.mark.unit
class TestConvenienceWAFFunctions:
    """WAF 便捷函数测试"""

    def test_bypass_waf_returns_list(self):
        """bypass_waf 返回字符串列表"""
        results = bypass_waf("' OR 1=1--", "unknown")
        assert isinstance(results, list)
        for r in results:
            assert isinstance(r, str)

    def test_detect_waf_returns_dict(self):
        """detect_waf 返回字典"""
        result = detect_waf({"cf-ray": "abc"}, "cloudflare", 403)
        assert "waf_type" in result
        assert "confidence" in result
