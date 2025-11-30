#!/bin/bash
#
# Windsurf MCP 快速配置脚本
# 自动配置 AI Red Team MCP Server 到 Windsurf
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Windsurf MCP 配置工具${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 配置路径
CONFIG_DIR="$HOME/.codeium/windsurf"
CONFIG_FILE="$CONFIG_DIR/mcp_config.json"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${YELLOW}项目路径:${NC} $PROJECT_DIR"
echo -e "${YELLOW}配置路径:${NC} $CONFIG_FILE"
echo ""

# 创建配置目录
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${BLUE}[1/4] 创建配置目录...${NC}"
    mkdir -p "$CONFIG_DIR"
    echo -e "${GREEN}  ✓ 配置目录已创建${NC}"
else
    echo -e "${GREEN}[1/4] 配置目录已存在${NC}"
fi

# 备份现有配置
if [ -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}[2/4] 备份现有配置...${NC}"
    BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$CONFIG_FILE" "$BACKUP_FILE"
    echo -e "${GREEN}  ✓ 已备份到: $BACKUP_FILE${NC}"
else
    echo -e "${BLUE}[2/4] 无需备份（配置文件不存在）${NC}"
fi

# 生成配置文件
echo -e "${BLUE}[3/4] 生成MCP配置...${NC}"

cat > "$CONFIG_FILE" << EOF
{
  "mcpServers": {
    "ai-redteam": {
      "command": "python3",
      "args": [
        "$PROJECT_DIR/mcp_server_full.py"
      ],
      "env": {
        "PYTHONPATH": "$PROJECT_DIR"
      }
    }
  }
}
EOF

echo -e "${GREEN}  ✓ 配置文件已生成${NC}"

# 验证配置
echo -e "${BLUE}[4/4] 验证配置...${NC}"

if python3 -m json.tool "$CONFIG_FILE" > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ JSON格式正确${NC}"
else
    echo -e "${RED}  ✗ JSON格式错误${NC}"
    exit 1
fi

if [ -f "$PROJECT_DIR/mcp_server_full.py" ]; then
    echo -e "${GREEN}  ✓ MCP服务器文件存在${NC}"
else
    echo -e "${RED}  ✗ MCP服务器文件不存在${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  配置完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}下一步:${NC}"
echo -e "  1. 重启 Windsurf"
echo -e "  2. 在对话中测试: ${BLUE}列出可用的工具${NC}"
echo -e "  3. 或者测试扫描: ${BLUE}扫描 192.168.1.1${NC}"
echo ""
echo -e "${YELLOW}查看配置:${NC}"
echo -e "  cat $CONFIG_FILE"
echo ""
echo -e "${YELLOW}测试MCP服务器:${NC}"
echo -e "  cd $PROJECT_DIR"
echo -e "  python3 mcp_server_full.py"
echo ""
echo -e "${YELLOW}查看完整文档:${NC}"
echo -e "  cat $PROJECT_DIR/MCP_CONFIG_GUIDE.md"
echo ""
