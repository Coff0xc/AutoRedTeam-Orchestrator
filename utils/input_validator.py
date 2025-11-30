#!/usr/bin/env python3
"""
输入验证器 - 安全性增强
优化点: 统一输入验证，防止命令注入和路径遍历
"""

import re
import ipaddress
from typing import Optional, List, Tuple
from urllib.parse import urlparse


class ValidationError(Exception):
    """验证错误"""
    pass


class InputValidator:
    """输入验证器"""
    
    # 危险字符和命令
    DANGEROUS_CHARS = [';', '|', '&', '$', '`', '\n', '\r', '>', '<']
    DANGEROUS_COMMANDS = ['rm', 'dd', 'mkfs', 'format', ':(){:|:&};:']
    
    # 允许的端口范围
    MIN_PORT = 1
    MAX_PORT = 65535
    
    @staticmethod
    def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
        """
        验证IP地址
        
        Returns:
            (is_valid, error_message)
        """
        try:
            ipaddress.ip_address(ip)
            return True, None
        except ValueError:
            return False, f"无效的IP地址: {ip}"
    
    @staticmethod
    def validate_cidr(cidr: str) -> Tuple[bool, Optional[str]]:
        """验证CIDR网段"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True, None
        except ValueError:
            return False, f"无效的CIDR网段: {cidr}"
    
    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """验证域名"""
        # 域名正则
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if not re.match(domain_pattern, domain):
            return False, f"无效的域名: {domain}"
        
        # 检查长度
        if len(domain) > 253:
            return False, "域名过长"
        
        # 检查每个标签长度
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                return False, f"域名标签过长: {label}"
        
        return True, None
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """验证URL"""
        try:
            result = urlparse(url)
            
            # 必须有scheme和netloc
            if not all([result.scheme, result.netloc]):
                return False, "URL缺少协议或主机名"
            
            # 只允许http和https
            if result.scheme not in ['http', 'https']:
                return False, f"不支持的协议: {result.scheme}"
            
            return True, None
        
        except Exception as e:
            return False, f"URL解析失败: {str(e)}"
    
    @staticmethod
    def validate_port(port: int) -> Tuple[bool, Optional[str]]:
        """验证端口号"""
        if not isinstance(port, int):
            return False, "端口必须是整数"
        
        if port < InputValidator.MIN_PORT or port > InputValidator.MAX_PORT:
            return False, f"端口范围必须在 {InputValidator.MIN_PORT}-{InputValidator.MAX_PORT}"
        
        return True, None
    
    @staticmethod
    def validate_port_range(port_range: str) -> Tuple[bool, Optional[str]]:
        """验证端口范围字符串 (如 "80,443,8000-9000")"""
        try:
            parts = port_range.split(',')
            for part in parts:
                part = part.strip()
                
                if '-' in part:
                    # 范围
                    start, end = part.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    valid, err = InputValidator.validate_port(start_port)
                    if not valid:
                        return False, err
                    
                    valid, err = InputValidator.validate_port(end_port)
                    if not valid:
                        return False, err
                    
                    if start_port > end_port:
                        return False, f"端口范围无效: {part}"
                else:
                    # 单个端口
                    port = int(part)
                    valid, err = InputValidator.validate_port(port)
                    if not valid:
                        return False, err
            
            return True, None
        
        except ValueError:
            return False, f"端口范围格式错误: {port_range}"
    
    @staticmethod
    def sanitize_command_arg(arg: str) -> str:
        """
        清理命令参数，移除危险字符
        
        注意: 这不能完全防止命令注入，最好使用参数化命令
        """
        # 移除危险字符
        for char in InputValidator.DANGEROUS_CHARS:
            arg = arg.replace(char, '')
        
        return arg.strip()
    
    @staticmethod
    def check_dangerous_command(cmd: List[str]) -> Tuple[bool, Optional[str]]:
        """检查是否包含危险命令"""
        cmd_str = ' '.join(cmd).lower()
        
        for dangerous in InputValidator.DANGEROUS_COMMANDS:
            if dangerous in cmd_str:
                return False, f"检测到危险命令: {dangerous}"
        
        return True, None
    
    @staticmethod
    def validate_file_path(path: str, allow_absolute: bool = False) -> Tuple[bool, Optional[str]]:
        """
        验证文件路径，防止路径遍历
        
        Args:
            path: 文件路径
            allow_absolute: 是否允许绝对路径
        """
        # 检查路径遍历
        if '..' in path:
            return False, "路径包含非法字符: .."
        
        # 检查绝对路径
        if not allow_absolute and path.startswith('/'):
            return False, "不允许绝对路径"
        
        # 检查危险路径
        dangerous_paths = ['/etc/', '/sys/', '/proc/', '/dev/']
        for dangerous in dangerous_paths:
            if path.startswith(dangerous):
                return False, f"不允许访问系统路径: {dangerous}"
        
        return True, None
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str, Optional[str]]:
        """
        验证目标（自动识别类型）
        
        Returns:
            (is_valid, target_type, error_message)
        """
        # 尝试IP
        valid, _ = InputValidator.validate_ip(target)
        if valid:
            return True, "ip", None
        
        # 尝试CIDR
        valid, _ = InputValidator.validate_cidr(target)
        if valid:
            return True, "cidr", None
        
        # 尝试URL
        valid, _ = InputValidator.validate_url(target)
        if valid:
            return True, "url", None
        
        # 尝试域名
        valid, _ = InputValidator.validate_domain(target)
        if valid:
            return True, "domain", None
        
        return False, "unknown", f"无法识别目标类型: {target}"
    
    @staticmethod
    def validate_wordlist_path(path: str) -> Tuple[bool, Optional[str]]:
        """验证字典文件路径"""
        import os
        
        # 验证路径安全性
        valid, err = InputValidator.validate_file_path(path, allow_absolute=True)
        if not valid:
            return False, err
        
        # 检查文件是否存在
        if not os.path.exists(path):
            return False, f"字典文件不存在: {path}"
        
        # 检查是否为文件
        if not os.path.isfile(path):
            return False, f"不是有效的文件: {path}"
        
        return True, None


def validate_and_sanitize(
    target: Optional[str] = None,
    port: Optional[int] = None,
    url: Optional[str] = None,
    domain: Optional[str] = None,
    file_path: Optional[str] = None
) -> Dict[str, any]:
    """
    便捷函数: 验证和清理多个输入
    
    Returns:
        Dict with 'valid' (bool) and 'errors' (list) keys
    """
    errors = []
    
    if target is not None:
        valid, target_type, err = InputValidator.validate_target(target)
        if not valid:
            errors.append(err)
    
    if port is not None:
        valid, err = InputValidator.validate_port(port)
        if not valid:
            errors.append(err)
    
    if url is not None:
        valid, err = InputValidator.validate_url(url)
        if not valid:
            errors.append(err)
    
    if domain is not None:
        valid, err = InputValidator.validate_domain(domain)
        if not valid:
            errors.append(err)
    
    if file_path is not None:
        valid, err = InputValidator.validate_file_path(file_path)
        if not valid:
            errors.append(err)
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }
