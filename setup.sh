#!/bin/bash
#
# AI Red Team MCP Server - 安装脚本
# 基于Kali Linux的AI自动化红队打点工具
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_banner() {
    echo -e "${RED}"
    cat << "EOF"
    █████╗ ██╗    ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
   ██╔══██╗██║    ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
   ███████║██║    ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
   ██╔══██║██║    ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
   ██║  ██║██║    ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
   ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}   MCP Server Installation Script${NC}"
    echo -e "${YELLOW}   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

info() {
    echo -e "${BLUE}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

# 检查是否以root运行
check_root() {
    if [ "$EUID" -ne 0 ]; then
        warning "建议使用root权限运行以安装系统依赖"
        warning "某些工具可能需要root权限才能正常工作"
        echo ""
        read -p "是否继续? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
        VERSION=$(uname -r)
    fi
    
    info "检测到操作系统: $OS $VERSION"
    
    if [[ "$OS" != *"Kali"* ]] && [[ "$OS" != *"Debian"* ]] && [[ "$OS" != *"Ubuntu"* ]]; then
        warning "此脚本针对Kali Linux优化，其他系统可能需要手动安装部分依赖"
    fi
}

# 更新系统
update_system() {
    info "更新系统包列表..."
    apt-get update -qq || true
    success "系统更新完成"
}

# 安装Python依赖
install_python_deps() {
    info "安装Python依赖..."
    
    # 检查pip
    if ! command -v pip3 &> /dev/null; then
        info "安装pip3..."
        apt-get install -y python3-pip -qq || true
    fi
    
    # 创建虚拟环境(可选)
    if [ "$USE_VENV" = "true" ]; then
        info "创建Python虚拟环境..."
        python3 -m venv venv
        source venv/bin/activate
    fi
    
    # 安装依赖
    pip3 install -r requirements.txt -q || {
        warning "部分Python包安装失败，尝试逐个安装..."
        pip3 install flask flask-cors pyyaml requests jinja2 -q
    }
    
    success "Python依赖安装完成"
}

# 安装Kali工具
install_kali_tools() {
    info "安装Kali Linux安全工具..."
    
    # 核心工具列表
    TOOLS=(
        # 信息收集
        "nmap"
        "masscan"
        "dnsutils"
        "dnsrecon"
        "whois"
        "theharvester"
        "enum4linux"
        
        # Web工具
        "nikto"
        "dirb"
        "gobuster"
        "whatweb"
        "wafw00f"
        "sqlmap"
        "wfuzz"
        
        # 漏洞扫描
        "sslscan"
        
        # 网络工具
        "hydra"
        "medusa"
        "smbclient"
        "snmp"
        "ldap-utils"
        
        # 漏洞利用
        "metasploit-framework"
        "exploitdb"
        
        # 其他
        "jq"
        "curl"
        "wget"
    )
    
    for tool in "${TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null && ! dpkg -l | grep -q "^ii  $tool"; then
            info "安装 $tool..."
            apt-get install -y "$tool" -qq 2>/dev/null || warning "无法安装 $tool"
        else
            echo -e "  ${GREEN}✓${NC} $tool 已安装"
        fi
    done
    
    success "Kali工具安装完成"
}

# 安装Go工具
install_go_tools() {
    info "安装Go语言工具..."
    
    # 检查Go
    if ! command -v go &> /dev/null; then
        info "安装Go..."
        apt-get install -y golang -qq || {
            warning "无法安装Go，跳过Go工具"
            return
        }
    fi
    
    # 设置Go环境
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # Go工具列表
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/OJ/gobuster/v3@latest"
    )
    
    for tool in "${GO_TOOLS[@]}"; do
        tool_name=$(basename "$tool" | cut -d'@' -f1)
        if ! command -v "$tool_name" &> /dev/null; then
            info "安装 $tool_name..."
            go install "$tool" 2>/dev/null || warning "无法安装 $tool_name"
        else
            echo -e "  ${GREEN}✓${NC} $tool_name 已安装"
        fi
    done
    
    # 更新nuclei模板
    if command -v nuclei &> /dev/null; then
        info "更新Nuclei模板..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi
    
    success "Go工具安装完成"
}

# 安装额外工具
install_extra_tools() {
    info "安装额外工具..."
    
    # feroxbuster
    if ! command -v feroxbuster &> /dev/null; then
        info "安装 feroxbuster..."
        apt-get install -y feroxbuster -qq 2>/dev/null || {
            curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null || true
        }
    fi
    
    # ssh-audit
    if ! command -v ssh-audit &> /dev/null; then
        info "安装 ssh-audit..."
        apt-get install -y ssh-audit -qq 2>/dev/null || pip3 install ssh-audit -q
    fi
    
    # crackmapexec
    if ! command -v crackmapexec &> /dev/null; then
        info "安装 crackmapexec..."
        apt-get install -y crackmapexec -qq 2>/dev/null || pip3 install crackmapexec -q
    fi
    
    success "额外工具安装完成"
}

# 下载字典
download_wordlists() {
    info "检查字典文件..."
    
    WORDLIST_DIR="/usr/share/wordlists"
    SECLISTS_DIR="/usr/share/seclists"
    
    # 检查rockyou
    if [ ! -f "$WORDLIST_DIR/rockyou.txt" ]; then
        if [ -f "$WORDLIST_DIR/rockyou.txt.gz" ]; then
            info "解压 rockyou.txt..."
            gunzip -k "$WORDLIST_DIR/rockyou.txt.gz" 2>/dev/null || true
        fi
    fi
    
    # 检查seclists
    if [ ! -d "$SECLISTS_DIR" ]; then
        info "安装 SecLists..."
        apt-get install -y seclists -qq 2>/dev/null || {
            warning "无法安装SecLists，请手动下载"
        }
    fi
    
    success "字典检查完成"
}

# 创建必要目录
create_directories() {
    info "创建必要目录..."
    
    mkdir -p logs
    mkdir -p reports
    mkdir -p data/sessions
    
    success "目录创建完成"
}

# 设置权限
setup_permissions() {
    info "设置文件权限..."
    
    chmod +x main.py
    chmod +x setup.sh
    
    success "权限设置完成"
}

# 创建快捷命令
create_shortcuts() {
    info "创建快捷命令..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # 创建启动脚本
    cat > /usr/local/bin/ai-recon-mcp << EOF
#!/bin/bash
cd "$SCRIPT_DIR"
python3 main.py "\$@"
EOF
    chmod +x /usr/local/bin/ai-recon-mcp 2>/dev/null || true
    
    success "快捷命令创建完成 (ai-recon-mcp)"
}

# 显示完成信息
show_completion() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}                    安装完成!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}启动服务器:${NC}"
    echo -e "  ${YELLOW}python3 main.py${NC}"
    echo -e "  或"
    echo -e "  ${YELLOW}ai-recon-mcp${NC}"
    echo ""
    echo -e "${CYAN}可用参数:${NC}"
    echo -e "  ${YELLOW}-H, --host${NC}     监听地址 (默认: 127.0.0.1)"
    echo -e "  ${YELLOW}-p, --port${NC}     监听端口 (默认: 5000)"
    echo -e "  ${YELLOW}-d, --debug${NC}    调试模式"
    echo ""
    echo -e "${CYAN}API端点:${NC}"
    echo -e "  ${YELLOW}GET  /${NC}              服务器状态"
    echo -e "  ${YELLOW}GET  /tools${NC}         工具列表"
    echo -e "  ${YELLOW}POST /execute${NC}       执行工具"
    echo -e "  ${YELLOW}POST /ai/analyze${NC}    AI分析"
    echo -e "  ${YELLOW}POST /workflow/auto${NC} 自动化工作流"
    echo ""
    echo -e "${PURPLE}⚠️  仅用于授权的渗透测试!${NC}"
    echo ""
}

# 主函数
main() {
    print_banner
    
    # 进入脚本目录
    cd "$(dirname "${BASH_SOURCE[0]}")"
    
    check_root
    detect_os
    
    echo ""
    echo -e "${CYAN}选择安装类型:${NC}"
    echo "  1) 完整安装 (推荐)"
    echo "  2) 最小安装 (仅Python依赖)"
    echo "  3) 仅更新Python依赖"
    echo ""
    read -p "请选择 [1-3]: " choice
    
    case $choice in
        1)
            update_system
            install_python_deps
            install_kali_tools
            install_go_tools
            install_extra_tools
            download_wordlists
            create_directories
            setup_permissions
            create_shortcuts
            ;;
        2)
            install_python_deps
            create_directories
            setup_permissions
            ;;
        3)
            install_python_deps
            ;;
        *)
            error "无效选择"
            exit 1
            ;;
    esac
    
    show_completion
}

# 运行主函数
main "$@"
