"""
注入点数据模型 - 统一表达 query/form/json/header/path/cookie 等输入面

按照 Web安全能力分析与优化方案.md 6.3 节设计:
- 标准化注入点列表（含类型、位置、参数、请求方法、来源）
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib
import json


class InjectionPointType(Enum):
    """注入点类型"""
    QUERY = "query"           # URL 查询参数 (?key=value)
    FORM = "form"             # 表单字段 (POST body)
    JSON = "json"             # JSON body 字段
    HEADER = "header"         # HTTP 请求头
    PATH = "path"             # URL 路径参数 (/api/{id})
    COOKIE = "cookie"         # Cookie 字段
    FRAGMENT = "fragment"     # URL 片段 (#hash)
    XML = "xml"               # XML body 字段
    MULTIPART = "multipart"   # Multipart 表单字段


class InjectionPointSource(Enum):
    """注入点来源"""
    HTML_FORM = "html_form"           # HTML 表单解析
    HTML_LINK = "html_link"           # HTML 链接提取
    JS_ANALYSIS = "js_analysis"       # JavaScript 静态分析
    API_SPEC = "api_spec"             # OpenAPI/Swagger 规范
    CRAWL = "crawl"                   # 爬虫发现
    MANUAL = "manual"                 # 手动指定
    TRAFFIC = "traffic"               # 流量分析
    PARAM_DISCOVERY = "param_discovery"  # 参数发现/枚举


@dataclass
class InjectionPoint:
    """
    注入点数据模型
    
    表达一个可被测试的输入点，包含其位置、类型、上下文信息。
    """
    
    # 核心标识
    url: str                          # 目标 URL (不含查询参数)
    param: str                        # 参数名称
    point_type: InjectionPointType    # 注入点类型
    method: str = "GET"               # HTTP 方法
    
    # 来源与上下文
    source: InjectionPointSource = InjectionPointSource.MANUAL
    source_url: str = ""              # 发现此注入点的页面 URL
    
    # 参数详情
    original_value: str = ""          # 原始值（如有）
    value_type: str = "string"        # 值类型推断 (string/integer/boolean/array/object)
    required: bool = False            # 是否必填
    
    # JSON/XML 专用
    json_path: str = ""               # JSON 路径 (如 $.user.id)
    parent_key: str = ""              # 父级键名
    
    # 表单专用
    form_action: str = ""             # 表单 action
    form_method: str = ""             # 表单 method
    form_enctype: str = ""            # 表单 enctype
    input_type: str = ""              # input type 属性
    
    # 认证与会话
    requires_auth: bool = False       # 是否需要认证
    session_id: str = ""              # 关联的会话 ID
    
    # 元数据
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """初始化后处理"""
        # 规范化 method
        self.method = self.method.upper()
        
        # 确保 URL 不含查询参数（对于非 QUERY 类型）
        if self.point_type != InjectionPointType.QUERY and "?" in self.url:
            self.url = self.url.split("?")[0]
    
    @property
    def id(self) -> str:
        """生成唯一标识符"""
        key = f"{self.url}|{self.method}|{self.point_type.value}|{self.param}"
        if self.json_path:
            key += f"|{self.json_path}"
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    @property
    def full_location(self) -> str:
        """完整位置描述"""
        loc = f"{self.method} {self.url}"
        if self.point_type == InjectionPointType.QUERY:
            loc += f"?{self.param}=..."
        elif self.point_type == InjectionPointType.JSON:
            loc += f" [JSON: {self.json_path or self.param}]"
        elif self.point_type == InjectionPointType.HEADER:
            loc += f" [Header: {self.param}]"
        elif self.point_type == InjectionPointType.COOKIE:
            loc += f" [Cookie: {self.param}]"
        else:
            loc += f" [{self.point_type.value}: {self.param}]"
        return loc
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于 JSON 序列化）"""
        return {
            "id": self.id,
            "url": self.url,
            "param": self.param,
            "type": self.point_type.value,
            "method": self.method,
            "source": self.source.value,
            "source_url": self.source_url,
            "original_value": self.original_value,
            "value_type": self.value_type,
            "required": self.required,
            "json_path": self.json_path,
            "form_action": self.form_action,
            "input_type": self.input_type,
            "requires_auth": self.requires_auth,
            "discovered_at": self.discovered_at,
            "tags": self.tags,
            "location": self.full_location,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InjectionPoint":
        """从字典创建"""
        return cls(
            url=data["url"],
            param=data["param"],
            point_type=InjectionPointType(data.get("type", "query")),
            method=data.get("method", "GET"),
            source=InjectionPointSource(data.get("source", "manual")),
            source_url=data.get("source_url", ""),
            original_value=data.get("original_value", ""),
            value_type=data.get("value_type", "string"),
            required=data.get("required", False),
            json_path=data.get("json_path", ""),
            form_action=data.get("form_action", ""),
            input_type=data.get("input_type", ""),
            requires_auth=data.get("requires_auth", False),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class InjectionPointCollection:
    """
    注入点集合 - 管理一组注入点
    
    支持去重、过滤、分组等操作。
    """
    
    points: List[InjectionPoint] = field(default_factory=list)
    target: str = ""                  # 主目标
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add(self, point: InjectionPoint) -> bool:
        """添加注入点（自动去重）"""
        if not self._exists(point):
            self.points.append(point)
            return True
        return False
    
    def add_many(self, points: List[InjectionPoint]) -> int:
        """批量添加，返回实际添加数量"""
        added = 0
        for p in points:
            if self.add(p):
                added += 1
        return added
    
    def _exists(self, point: InjectionPoint) -> bool:
        """检查是否已存在"""
        return any(p.id == point.id for p in self.points)
    
    def filter_by_type(self, point_type: InjectionPointType) -> List[InjectionPoint]:
        """按类型过滤"""
        return [p for p in self.points if p.point_type == point_type]
    
    def filter_by_method(self, method: str) -> List[InjectionPoint]:
        """按 HTTP 方法过滤"""
        return [p for p in self.points if p.method.upper() == method.upper()]
    
    def filter_by_source(self, source: InjectionPointSource) -> List[InjectionPoint]:
        """按来源过滤"""
        return [p for p in self.points if p.source == source]
    
    def filter_by_url_pattern(self, pattern: str) -> List[InjectionPoint]:
        """按 URL 模式过滤（简单包含匹配）"""
        return [p for p in self.points if pattern in p.url]
    
    def group_by_url(self) -> Dict[str, List[InjectionPoint]]:
        """按 URL 分组"""
        groups: Dict[str, List[InjectionPoint]] = {}
        for p in self.points:
            if p.url not in groups:
                groups[p.url] = []
            groups[p.url].append(p)
        return groups
    
    def group_by_type(self) -> Dict[str, List[InjectionPoint]]:
        """按类型分组"""
        groups: Dict[str, List[InjectionPoint]] = {}
        for p in self.points:
            key = p.point_type.value
            if key not in groups:
                groups[key] = []
            groups[key].append(p)
        return groups
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        type_counts = {}
        source_counts = {}
        method_counts = {}
        
        for p in self.points:
            # 类型统计
            t = p.point_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
            
            # 来源统计
            s = p.source.value
            source_counts[s] = source_counts.get(s, 0) + 1
            
            # 方法统计
            m = p.method
            method_counts[m] = method_counts.get(m, 0) + 1
        
        return {
            "total": len(self.points),
            "unique_urls": len(set(p.url for p in self.points)),
            "by_type": type_counts,
            "by_source": source_counts,
            "by_method": method_counts,
            "requires_auth": sum(1 for p in self.points if p.requires_auth),
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target": self.target,
            "created_at": self.created_at,
            "stats": self.get_stats(),
            "points": [p.to_dict() for p in self.points],
        }
    
    def to_json(self, indent: int = 2) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InjectionPointCollection":
        """从字典创建"""
        collection = cls(
            target=data.get("target", ""),
            created_at=data.get("created_at", ""),
        )
        for p_data in data.get("points", []):
            collection.add(InjectionPoint.from_dict(p_data))
        return collection
    
    def __len__(self) -> int:
        return len(self.points)
    
    def __iter__(self):
        return iter(self.points)


# 便捷构造函数
def create_query_point(url: str, param: str, **kwargs) -> InjectionPoint:
    """创建 URL 查询参数注入点"""
    return InjectionPoint(
        url=url,
        param=param,
        point_type=InjectionPointType.QUERY,
        method="GET",
        **kwargs
    )


def create_form_point(url: str, param: str, method: str = "POST", **kwargs) -> InjectionPoint:
    """创建表单字段注入点"""
    return InjectionPoint(
        url=url,
        param=param,
        point_type=InjectionPointType.FORM,
        method=method,
        **kwargs
    )


def create_json_point(url: str, param: str, json_path: str = "", **kwargs) -> InjectionPoint:
    """创建 JSON body 注入点"""
    return InjectionPoint(
        url=url,
        param=param,
        point_type=InjectionPointType.JSON,
        method="POST",
        json_path=json_path or f"$.{param}",
        **kwargs
    )


def create_header_point(url: str, header_name: str, **kwargs) -> InjectionPoint:
    """创建 HTTP Header 注入点"""
    return InjectionPoint(
        url=url,
        param=header_name,
        point_type=InjectionPointType.HEADER,
        **kwargs
    )


def create_cookie_point(url: str, cookie_name: str, **kwargs) -> InjectionPoint:
    """创建 Cookie 注入点"""
    return InjectionPoint(
        url=url,
        param=cookie_name,
        point_type=InjectionPointType.COOKIE,
        **kwargs
    )
