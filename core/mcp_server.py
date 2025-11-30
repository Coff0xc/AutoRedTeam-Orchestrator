#!/usr/bin/env python3
"""
AI Red Team MCP Server - 核心服务器
基于Kali Linux的AI自动化红队打点工具
"""

import json
import logging
import os
import sys
from datetime import datetime
from functools import wraps
from typing import Any, Dict, List, Optional, Callable

from flask import Flask, jsonify, request, Response
from flask_cors import CORS

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.tool_registry import ToolRegistry
from core.session_manager import SessionManager
from core.ai_engine import AIDecisionEngine
from core.attack_chain import AttackChainEngine
from utils.logger import setup_logger

# 配置日志
logger = setup_logger("mcp_server")

class MCPServer:
    """MCP服务器核心类"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.config = config or self._load_default_config()
        self.tool_registry = ToolRegistry()
        self.session_manager = SessionManager()
        self.ai_engine = AIDecisionEngine(self.config.get("ai", {}))
        self.attack_chain_engine = None  # 延迟初始化
        
        self._register_routes()
        self._register_error_handlers()
        
        logger.info("MCP服务器初始化完成")
    
    def _get_attack_chain_engine(self):
        """获取攻击链引擎(延迟初始化)"""
        if self.attack_chain_engine is None:
            self.attack_chain_engine = AttackChainEngine(self.tool_registry)
        return self.attack_chain_engine
    
    def _load_default_config(self) -> Dict[str, Any]:
        """加载默认配置"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "config", "config.yaml"
        )
        if os.path.exists(config_path):
            import yaml
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        return {
            "server": {"host": "127.0.0.1", "port": 5000},
            "ai": {"provider": "openai", "model": "gpt-4"},
            "logging": {"level": "INFO"}
        }
    
    def _register_routes(self):
        """注册API路由"""
        
        @self.app.route("/", methods=["GET"])
        def index():
            return jsonify({
                "name": "AI Red Team MCP Server",
                "version": "1.0.0",
                "status": "running",
                "timestamp": datetime.now().isoformat()
            })
        
        @self.app.route("/health", methods=["GET"])
        def health():
            return jsonify({"status": "healthy", "uptime": self._get_uptime()})
        
        @self.app.route("/tools", methods=["GET"])
        def list_tools():
            """列出所有可用工具"""
            tools = self.tool_registry.list_tools()
            return jsonify({
                "tools": tools,
                "total": len(tools)
            })
        
        @self.app.route("/tools/<tool_name>", methods=["GET"])
        def get_tool_info(tool_name: str):
            """获取工具详情"""
            tool = self.tool_registry.get_tool(tool_name)
            if tool:
                return jsonify(tool.to_dict())
            return jsonify({"error": f"工具 {tool_name} 不存在"}), 404
        
        @self.app.route("/execute", methods=["POST"])
        def execute_tool():
            """执行工具"""
            data = request.get_json()
            if not data:
                return jsonify({"error": "请求体为空"}), 400
            
            tool_name = data.get("tool")
            params = data.get("params", {})
            session_id = data.get("session_id")
            
            if not tool_name:
                return jsonify({"error": "未指定工具名称"}), 400
            
            try:
                result = self.tool_registry.execute(tool_name, params, session_id)
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"执行工具 {tool_name} 失败: {str(e)}")
                return jsonify({
                    "success": False,
                    "tool": tool_name,
                    "error": str(e)
                }), 500
        
        @self.app.route("/ai/analyze", methods=["POST"])
        def ai_analyze():
            """AI分析目标"""
            data = request.get_json()
            target = data.get("target")
            context = data.get("context", {})
            
            if not target:
                return jsonify({"error": "未指定目标"}), 400
            
            try:
                analysis = self.ai_engine.analyze_target(target, context)
                return jsonify({
                    "success": True,
                    "analysis": analysis
                })
            except Exception as e:
                logger.error(f"AI分析失败: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route("/ai/plan", methods=["POST"])
        def ai_plan():
            """AI生成攻击计划"""
            data = request.get_json()
            target = data.get("target")
            recon_data = data.get("recon_data", {})
            
            try:
                plan = self.ai_engine.generate_attack_plan(target, recon_data)
                return jsonify({
                    "success": True,
                    "plan": plan
                })
            except Exception as e:
                logger.error(f"生成攻击计划失败: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route("/session/create", methods=["POST"])
        def create_session():
            """创建新会话"""
            data = request.get_json() or {}
            session = self.session_manager.create_session(data.get("name"))
            return jsonify({
                "session_id": session.id,
                "created_at": session.created_at.isoformat()
            })
        
        @self.app.route("/session/<session_id>", methods=["GET"])
        def get_session(session_id: str):
            """获取会话信息"""
            session = self.session_manager.get_session(session_id)
            if session:
                return jsonify(session.to_dict())
            return jsonify({"error": "会话不存在"}), 404
        
        @self.app.route("/session/<session_id>/results", methods=["GET"])
        def get_session_results(session_id: str):
            """获取会话结果"""
            results = self.session_manager.get_results(session_id)
            return jsonify({"results": results})
        
        @self.app.route("/workflow/auto", methods=["POST"])
        def auto_workflow():
            """自动化工作流"""
            data = request.get_json()
            target = data.get("target")
            options = data.get("options", {})
            
            if not target:
                return jsonify({"error": "未指定目标"}), 400
            
            try:
                # 创建会话
                session = self.session_manager.create_session(f"auto_{target}")
                
                # 执行自动化流程
                from modules.workflow import AutoWorkflow
                workflow = AutoWorkflow(
                    self.tool_registry, 
                    self.ai_engine,
                    session
                )
                result = workflow.execute(target, options)
                
                return jsonify({
                    "success": True,
                    "session_id": session.id,
                    "result": result
                })
            except Exception as e:
                logger.error(f"自动化工作流失败: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route("/report/generate", methods=["POST"])
        def generate_report():
            """生成报告"""
            data = request.get_json()
            session_id = data.get("session_id")
            format_type = data.get("format", "html")
            
            try:
                from utils.report_generator import ReportGenerator
                generator = ReportGenerator()
                report_path = generator.generate(session_id, format_type)
                return jsonify({
                    "success": True,
                    "report_path": report_path
                })
            except Exception as e:
                logger.error(f"报告生成失败: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        # ===== 攻击链API =====
        
        @self.app.route("/chain/create", methods=["POST"])
        def create_attack_chain():
            """创建攻击链"""
            data = request.get_json()
            target = data.get("target")
            target_type = data.get("target_type", "ip")
            objectives = data.get("objectives", [])
            
            if not target:
                return jsonify({"error": "未指定目标"}), 400
            
            try:
                engine = self._get_attack_chain_engine()
                chain = engine.create_chain(target, target_type, objectives)
                return jsonify({
                    "success": True,
                    "chain_id": chain.id,
                    "nodes_count": len(chain.nodes),
                    "chain": engine.get_chain_status(chain.id)
                })
            except Exception as e:
                logger.error(f"创建攻击链失败: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route("/chain/<chain_id>/execute", methods=["POST"])
        def execute_attack_chain(chain_id: str):
            """执行攻击链"""
            data = request.get_json() or {}
            session_id = data.get("session_id")
            
            try:
                engine = self._get_attack_chain_engine()
                result = engine.execute_chain(chain_id, session_id)
                return jsonify({
                    "success": True,
                    "result": result
                })
            except Exception as e:
                logger.error(f"执行攻击链失败: {str(e)}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route("/chain/<chain_id>", methods=["GET"])
        def get_attack_chain(chain_id: str):
            """获取攻击链状态"""
            engine = self._get_attack_chain_engine()
            status = engine.get_chain_status(chain_id)
            if status:
                return jsonify(status)
            return jsonify({"error": "攻击链不存在"}), 404
        
        @self.app.route("/chain/<chain_id>/suggestions", methods=["GET"])
        def get_chain_suggestions(chain_id: str):
            """获取攻击建议"""
            engine = self._get_attack_chain_engine()
            suggestions = engine.suggest_next_steps(chain_id)
            return jsonify({
                "chain_id": chain_id,
                "suggestions": suggestions
            })
        
        # ===== 工具搜索API =====
        
        @self.app.route("/tools/search", methods=["GET"])
        def search_tools():
            """搜索工具"""
            keyword = request.args.get("q", "")
            if not keyword:
                return jsonify({"error": "请提供搜索关键词"}), 400
            
            results = self.tool_registry.search_tools(keyword)
            return jsonify({
                "query": keyword,
                "results": results,
                "count": len(results)
            })
        
        @self.app.route("/tools/stats", methods=["GET"])
        def tools_stats():
            """工具统计"""
            stats = self.tool_registry.get_stats()
            return jsonify(stats)
    
    def _register_error_handlers(self):
        """注册错误处理器"""
        
        @self.app.errorhandler(404)
        def not_found(e):
            return jsonify({"error": "资源不存在"}), 404
        
        @self.app.errorhandler(500)
        def server_error(e):
            return jsonify({"error": "服务器内部错误"}), 500
    
    def _get_uptime(self) -> str:
        """获取运行时间"""
        if hasattr(self, '_start_time'):
            delta = datetime.now() - self._start_time
            return str(delta)
        return "unknown"
    
    def register_tool(self, tool: 'BaseTool'):
        """注册工具"""
        self.tool_registry.register(tool)
    
    def run(self, host: str = None, port: int = None, debug: bool = False):
        """启动服务器"""
        self._start_time = datetime.now()
        host = host or self.config.get("server", {}).get("host", "127.0.0.1")
        port = port or self.config.get("server", {}).get("port", 5000)
        
        logger.info(f"MCP服务器启动: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)


def create_app(config: Dict[str, Any] = None) -> MCPServer:
    """创建MCP服务器实例"""
    server = MCPServer(config)
    
    # 注册所有模块
    from modules import register_all_modules
    register_all_modules(server)
    
    return server


if __name__ == "__main__":
    server = create_app()
    server.run(debug=True)
