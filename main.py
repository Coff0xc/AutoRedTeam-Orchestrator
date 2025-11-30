#!/usr/bin/env python3
"""
AI Red Team MCP Server - 主入口
基于Kali Linux的AI自动化红队打点工具
"""

import argparse
import os
import sys

# 确保项目目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.mcp_server import create_app
from utils.logger import setup_logger

logger = setup_logger("main")


def print_banner():
    """打印启动横幅"""
    banner = """
\033[91m
    █████╗ ██╗    ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
   ██╔══██╗██║    ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
   ███████║██║    ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
   ██╔══██║██║    ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
   ██║  ██║██║    ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
   ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
\033[0m
\033[92m   ███╗   ███╗ ██████╗██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
   ████╗ ████║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
   ██╔████╔██║██║     ██████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
   ██║╚██╔╝██║██║     ██╔═══╝     ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
   ██║ ╚═╝ ██║╚██████╗██║         ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
   ╚═╝     ╚═╝ ╚═════╝╚═╝         ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
\033[0m
\033[93m   ╔══════════════════════════════════════════════════════════════════════════╗
   ║     AI-Powered Red Team Automation MCP Server for Kali Linux            ║
   ║                    Version 1.0.0 | 仅用于授权测试                         ║
   ╚══════════════════════════════════════════════════════════════════════════╝
\033[0m
"""
    print(banner)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="AI Red Team MCP Server - AI驱动的红队自动化工具"
    )
    parser.add_argument(
        "-H", "--host",
        default="127.0.0.1",
        help="服务器监听地址 (默认: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5000,
        help="服务器监听端口 (默认: 5000)"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="启用调试模式"
    )
    parser.add_argument(
        "-c", "--config",
        default="config/config.yaml",
        help="配置文件路径"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="不显示启动横幅"
    )
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # 加载配置
    config = None
    config_path = os.path.join(os.path.dirname(__file__), args.config)
    if os.path.exists(config_path):
        import yaml
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.info(f"已加载配置: {config_path}")
    
    # 创建并启动服务器
    try:
        server = create_app(config)
        
        logger.info("=" * 60)
        logger.info(f"MCP服务器启动中...")
        logger.info(f"地址: http://{args.host}:{args.port}")
        logger.info(f"API文档: http://{args.host}:{args.port}/tools")
        logger.info("=" * 60)
        
        server.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
        
    except KeyboardInterrupt:
        logger.info("服务器已停止")
    except Exception as e:
        logger.error(f"服务器启动失败: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
