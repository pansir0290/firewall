#!/bin/bash

# ====================================================================
# 脚本名称: 智能防火墙交互管理工具 (兼容 iptables/nftables)
# 功能描述: 严格白名单机制，支持端口范围、多协议选择、自动探测及一键放通
# ====================================================================

# 4. 自动加权：尝试给脚本自身赋予最高执行权限
SCRIPT_PATH=$(realpath "$0" 2>/dev/null || echo "$0")
if [ -f "$SCRIPT_PATH" ] && [ ! -x "$SCRIPT_PATH" ]; then
    chmod +x "$SCRIPT_PATH" 2>/dev/null
fi

# 检查是否为 root 用户
if [ "$EUID" -ne 0 ]; then
  echo "错误：请使用 root 权限运行此脚本！(例如: sudo ./fw.sh)"
  exit 1
fi

FIREWALL_MODE=""

# 检测系统支持哪种防火墙
detect_firewall() {
    if command -v nft &> /dev/null; then
        FIREWALL_MODE="nftables"
    elif command -v iptables &> /dev/null; then
        FIREWALL_MODE="iptables"
    else
        echo "提示：未检测到防火墙组件，正在尝试自动安装 iptables..."
        if command -v apt &> /dev/null; then
            apt update && apt install -y iptables iproute2
            FIREWALL_MODE="iptables"
        elif command -v yum &> /dev/null; then
            yum install -y iptables iproute2
            FIREWALL_MODE="iptables"
        else
            echo "错误：无法自动安装，请手动安装 iptables 或 nftables 后再运行！"
            exit 1
        fi
    fi
}

# 5. 自动探测本机已占用的端口并自动放通
auto_allow_current_ports() {
    echo "正在自动探测检测本机已占用的服务端口..."
    if ! command -v ss &> /dev/null; then
        echo "未找到 ss 命令，跳过自动探测。"
        return
    fi

    # 提取当前处于 LISTEN 状态的 TCP 和 UDP 端口
    local ports=$(ss -tuln | awk 'NR>1 {print $5}' | awk -F: '{print $nf}' | sort -nu)
    
    if [ -z "$ports" ]; then
        echo "未探测到活动的监听端口。"
        return
    fi

    echo "探测到以下端口正在运行服务: $(echo $ports | tr '\n' ' ')"
    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            if [ "$FIREWALL_MODE" = "nftables" ]; then
                # nftables 允许 tcp/udp 复合规则
                nft add rule inet filter input tcp dport $port accept 2>/dev/null
                nft add rule inet filter input udp dport $port accept 2>/dev/null
            else
                iptables -A INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                iptables -A INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
            fi
            echo "-> 已自动放行本地服务端口: $port (TCP/UDP)"
        fi
    done
}

# 初始化防火墙（严格白名单模式）
init_firewall() {
    echo "正在初始化严格防火墙策略 ($FIREWALL_MODE)..."
    
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        nft flush ruleset
        nft add table inet filter
        nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
        nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
        nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
        nft add rule inet filter input iif "lo" accept
        nft add rule inet filter input ct state established,related accept
    else
        iptables -F && iptables -X && iptables -Z
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    fi

    # 初始化时触发自动探测放通，防止断连
    auto_allow_current_ports
    
    echo "防火墙严格模式初始化完成！"
    save_rules
    show_rules
}

# 3. 一键放通所有端口
allow_all_ports() {
    echo "正在切换至【一键放通所有端口】模式..."
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        nft flush ruleset
        nft add table inet filter
        nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }
        nft add chain inet filter forward { type filter hook forward priority 0 \; policy accept \; }
        nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
    else
        iptables -F
        iptables -X
        iptables -Z
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
    fi
    echo "警告：当前已放通所有入站流量！系统处于全开放状态。"
    save_rules
}

# 显示规则
show_rules() {
    echo -e "\n================ 当前入站放行规则列表 ================"
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        if nft list tables | grep -q "inet filter"; then
            # 打印当前默认策略
            local policy=$(nft list chain inet filter input | grep "policy")
            echo "当前默认策略: $policy"
            echo "----------------------------------------------------"
            nft -a list chain inet filter input
        else
            echo "防火墙尚未初始化，当前为系统默认状态。"
        fi
    else
        echo "当前默认策略: $(iptables -L INPUT -n | head -n 1)"
        echo "----------------------------------------------------"
        iptables -L INPUT -n --line-numbers | grep -E "ACCEPT|num|DROP"
    fi
    echo "===================================================="
}

# 1 & 2. 放行端口（支持范围、支持协议自由选择）
allow_port() {
    echo -e "\n请输入要放行的端口或端口范围："
    echo "  - 单个端口示例: 80"
    echo "  - 端口范围示例: 8000-9000"
    read -p "请输入: " port_input

    # 验证输入格式 (数字 或 数字-数字)
    if ! [[ "$port_input" =~ ^[0-9]+(-[0-9]+)?$ ]]; then
        echo "输入错误：请输入有效的端口或端口范围(如: 80 或 8000-9000)！"
        return
    fi

    # 协议选择
    echo "请选择要放行的协议类型："
    echo "1) TCP"
    echo "2) UDP"
    echo "3) ALL (同时放行 TCP 和 UDP)"
    read -p "请选择 [1-3, 默认 1]: " proto_choice
    
    local proto=""
    case $proto_choice in
        2) proto="udp" ;;
        3) proto="all" ;;
        *) proto="tcp" ;;
    esac

    # 转换端口范围符号 (nftables 使用 8000-9000, iptables 使用 8000:9000)
    local nft_port="$port_input"
    local ipt_port="${port_input//-/:}"

    if [ "$FIREWALL_MODE" = "nftables" ]; then
        # 检查 inet filter 是否存在，不存在先初始化
        if ! nft list tables | grep -q "inet filter"; then
            echo "正在为您建立基础防火墙表结构..."
            init_firewall
        fi

        if [ "$proto" = "all" ]; then
            nft add rule inet filter input tcp dport $nft_port accept
            nft add rule inet filter input udp dport $nft_port accept
            echo "成功：已放行端口 $port_input (TCP & UDP)。"
        else
            nft add rule inet filter input $proto dport $nft_port accept
            echo "成功：已放行端口 $port_input ($proto)。"
        fi
    else
        if [ "$proto" = "all" ]; then
            iptables -A INPUT -p tcp --dport $ipt_port -j ACCEPT
            iptables -A INPUT -p udp --dport $ipt_port -j ACCEPT
            echo "成功：已放行端口 $port_input (TCP & UDP)。"
        else
            iptables -A INPUT -p $proto --dport $ipt_port -j ACCEPT
            echo "成功：已放行端口 $port_input ($proto)。"
        fi
    fi
    save_rules
}

# 封锁/删除端口规则
block_port() {
    show_rules
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        read -p "请输入你要删除规则的 handle 编号 (每行最右侧的数字): " handle_num
        if ! [[ "$handle_num" =~ ^[0-9]+$ ]]; then echo "输入错误！"; return; fi
        nft delete rule inet filter input handle $handle_num 2>/dev/null
    else
        read -p "请输入你要删除的规则编号 (num): " line_num
        if ! [[ "$line_num" =~ ^[0-9]+$ ]]; then echo "输入错误！"; return; fi
        iptables -D INPUT $line_num 2>/dev/null
    fi

    if [ $? -eq 0 ]; then
        echo "成功：该防火墙规则已移除。"
        save_rules
    fi
}

# 持久化规则
save_rules() {
    echo "正在自动将规则持久化存储..."
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        if [ -f "/etc/nftables.conf" ]; then
            nft list ruleset > /etc/nftables.conf
            echo "nftables 规则已保存至 /etc/nftables.conf"
        fi
    else
        if [ -d "/etc/iptables" ]; then
            iptables-save > /etc/iptables/rules.v4
        elif [ -f "/etc/sysconfig/iptables" ]; then
            iptables-save > /etc/sysconfig/iptables
        fi
        echo "iptables 规则已保存。"
    fi
}

# 执行初始化环境检测
detect_firewall

# 首次运行或表不存在时，主动探测当前端口提示
if [ "$FIREWALL_MODE" = "nftables" ] && ! nft list tables | grep -q "inet filter"; then
    echo -e "\n[提示] 检测到这是脚本在当前系统首次运行。"
    auto_allow_current_ports
fi

# 主菜单循环
while true; do
    echo -e "\n=== 智能防火墙高级管理菜单 ($FIREWALL_MODE) ==="
    echo "1. 开启白名单模式 (默认拒绝一切 + 自动放行当前服务端口)"
    echo "2. 查看当前放行规则"
    echo "3. 手动放行端口/端口范围 (支持 TCP/UDP/ALL)"
    echo "4. 封锁/删除指定规则"
    echo "5. 一键放通所有端口 (切换为全开模式)"
    echo "6. 手动保存当前规则"
    echo "7. 退出脚本"
    echo "=================================================="
    read -p "请选择操作 [1-7]: " choice

    case $choice in
        1) init_firewall ;;
        2) show_rules ;;
        3) allow_port ;;
        4) block_port ;;
        5) allow_all_ports ;;
        6) save_rules ;;
        7) echo "感谢使用，脚本已安全退出。"; exit 0 ;;
        *) echo "无效选项，请重新选择！" ;;
    esac
done
