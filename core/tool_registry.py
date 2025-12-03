#!/usr/bin/env python3
"""
工具注册表 - 管理所有红队工具
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """工具类别"""
    RECON = "recon"                    # 信息收集
    VULN_SCAN = "vuln_scan"            # 漏洞扫描
    WEB_ATTACK = "web_attack"          # Web攻击
    NETWORK = "network"                # 网络攻击
    EXPLOIT = "exploit"                # 漏洞利用
    POST_EXPLOIT = "post_exploit"      # 后渗透
    SOCIAL = "social"                  # 社会工程
    WIRELESS = "wireless"              # 无线攻击
    CRYPTO = "crypto"                  # 密码攻击
    REPORT = "report"                  # 报告生成
    CREDENTIAL_ACCESS = "credential_access"  # 凭证访问


@dataclass
class ToolParameter:
    """工具参数定义"""
    name: str
    type: str
    description: str
    required: bool = True
    default: Any = None
    choices: List[Any] = None


@dataclass
class BaseTool(ABC):
    """工具基类"""
    name: str
    description: str
    category: ToolCategory
    parameters: List[ToolParameter] = field(default_factory=list)
    requires_root: bool = False
    timeout: int = 300  # 默认超时5分钟
    
    @abstractmethod
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        """执行工具"""
        pass
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """验证参数"""
        for param in self.parameters:
            if param.required and param.name not in params:
                if param.default is None:
                    raise ValueError(f"缺少必需参数: {param.name}")
                params[param.name] = param.default
            
            if param.choices and params.get(param.name) not in param.choices:
                raise ValueError(
                    f"参数 {param.name} 值无效, 可选值: {param.choices}"
                )
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description,
                    "required": p.required,
                    "default": p.default,
                    "choices": p.choices
                }
                for p in self.parameters
            ],
            "requires_root": self.requires_root,
            "timeout": self.timeout
        }


class ToolRegistry:
    """工具注册表"""
    
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._categories: Dict[ToolCategory, List[str]] = {
            cat: [] for cat in ToolCategory
        }
        logger.info("工具注册表初始化完成")
    
    def register(self, tool: BaseTool):
        """注册工具"""
        if tool.name in self._tools:
            logger.warning(f"工具 {tool.name} 已存在，将被覆盖")
        
        self._tools[tool.name] = tool
        if tool.name not in self._categories[tool.category]:
            self._categories[tool.category].append(tool.name)
        
        logger.info(f"工具已注册: {tool.name} [{tool.category.value}]")
    
    def unregister(self, tool_name: str):
        """注销工具"""
        if tool_name in self._tools:
            tool = self._tools.pop(tool_name)
            self._categories[tool.category].remove(tool_name)
            logger.info(f"工具已注销: {tool_name}")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """获取工具"""
        return self._tools.get(tool_name)
    
    def list_tools(self, category: ToolCategory = None) -> List[Dict[str, Any]]:
        """列出工具"""
        if category:
            tool_names = self._categories.get(category, [])
            return [self._tools[name].to_dict() for name in tool_names]
        return [tool.to_dict() for tool in self._tools.values()]
    
    def get_tools_by_category(self, category: ToolCategory) -> List[BaseTool]:
        """按类别获取工具"""
        tool_names = self._categories.get(category, [])
        return [self._tools[name] for name in tool_names]
    
    def execute(self, tool_name: str, params: Dict[str, Any], 
                session_id: str = None) -> Dict[str, Any]:
        """执行工具"""
        tool = self.get_tool(tool_name)
        if not tool:
            raise ValueError(f"工具不存在: {tool_name}")
        
        # 验证参数
        tool.validate_params(params)
        
        logger.info(f"执行工具: {tool_name}, 参数: {params}")
        
        try:
            result = tool.execute(params, session_id)
            logger.info(f"工具执行成功: {tool_name}")
            return result
        except Exception as e:
            logger.error(f"工具执行失败: {tool_name}, 错误: {str(e)}")
            raise
    
    def search_tools(self, keyword: str) -> List[Dict[str, Any]]:
        """搜索工具"""
        keyword = keyword.lower()
        results = []
        for tool in self._tools.values():
            if (keyword in tool.name.lower() or 
                keyword in tool.description.lower()):
                results.append(tool.to_dict())
        return results
    
    @property
    def tool_count(self) -> int:
        """工具数量"""
        return len(self._tools)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_tools": self.tool_count,
            "by_category": {
                cat.value: len(tools) 
                for cat, tools in self._categories.items()
            }
        }
