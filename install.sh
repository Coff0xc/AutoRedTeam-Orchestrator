#!/bin/bash
# AutoRedTeam-Orchestrator 一键安装脚本

set -e

echo "=========================================="
echo "  AutoRedTeam-Orchestrator 安装程序"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查是否为root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] 请使用 sudo 运行此脚本${NC}"
    exit 1
fi

# 获取实际用户
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(eval echo ~$REAL_USER)

echo -e "${GREEN}[*] 安装用户: $REAL_USER${NC}"
echo -e "${GREEN}[*] 用户目录: $REAL_HOME${NC}"
echo ""

# 1. 更新系统
echo -e "${YELLOW}[1/6] 更新系统包...${NC}"
apt update -qq

# 2. 安装Python依赖
echo -e "${YELLOW}[2/6] 安装Python依赖...${NC}"
apt install -y python3 python3-pip python3-venv nmap >/dev/null 2>&1
pip3 install -q aiohttp pyyaml jinja2 asyncio

# 3. 检查Go环境
echo -e "${YELLOW}[3/6] 检查Go环境...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${RED}[!] Go未安装，正在安装...${NC}"
    apt install -y golang-go >/dev/null 2>&1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo -e "${GREEN}    ✓ Go版本: $GO_VERSION${NC}"

# 4. 安装ProjectDiscovery工具
echo -e "${YELLOW}[4/6] 安装ProjectDiscovery工具套件...${NC}"

# 切换到实际用户执行go install
sudo -u $REAL_USER bash << EOF
export PATH=\$PATH:\$HOME/go/bin
export GOPATH=\$HOME/go

echo "    - 安装 subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null

echo "    - 安装 nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null

echo "    - 安装 httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null

echo "    - 安装 dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null

echo "    - 更新 nuclei 模板..."
\$HOME/go/bin/nuclei -update-templates -silent 2>/dev/null
EOF

# 5. 配置PATH
echo -e "${YELLOW}[5/6] 配置环境变量...${NC}"

# 检查shell类型
if [ -f "$REAL_HOME/.zshrc" ]; then
    SHELL_RC="$REAL_HOME/.zshrc"
elif [ -f "$REAL_HOME/.bashrc" ]; then
    SHELL_RC="$REAL_HOME/.bashrc"
else
    SHELL_RC="$REAL_HOME/.profile"
fi

# 添加PATH（如果不存在）
if ! grep -q "go/bin" "$SHELL_RC"; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$SHELL_RC"
    echo -e "${GREEN}    ✓ 已添加 Go bin 到 PATH${NC}"
fi

# 6. 验证安装
echo -e "${YELLOW}[6/6] 验证安装...${NC}"

TOOLS=("nmap" "subfinder" "nuclei" "httpx" "dnsx")
ALL_OK=true

for tool in "${TOOLS[@]}"; do
    if sudo -u $REAL_USER bash -c "export PATH=\$PATH:\$HOME/go/bin; command -v $tool" &> /dev/null; then
        echo -e "${GREEN}    ✓ $tool${NC}"
    else
        echo -e "${RED}    ✗ $tool${NC}"
        ALL_OK=false
    fi
done

echo ""
echo "=========================================="

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}[✓] 安装完成！${NC}"
    echo ""
    echo "使用方法："
    echo "  1. 重新加载shell配置: source $SHELL_RC"
    echo "  2. 检查工具状态: python main.py check-tools"
    echo "  3. 运行扫描: python main.py scan example.com"
    echo ""
    echo "MCP服务器配置："
    echo "  配置文件: mcp_config.json"
    echo "  启动命令: python mcp_server.py"
else
    echo -e "${RED}[!] 部分工具安装失败${NC}"
    echo "请手动检查并重新安装失败的工具"
fi

echo "=========================================="
