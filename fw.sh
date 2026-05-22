#!/bin/bash

# ====================================================================
# 智能防火墙交互管理工具 (IPv4/IPv6 同步增强版)
# ====================================================================

# 自动加权
SCRIPT_PATH=$(realpath "$0" 2>/dev/null || echo "$0")
[ -f "$SCRIPT_PATH" ] && [ ! -x "$SCRIPT_PATH" ] && chmod +x "$SCRIPT_PATH" 2>/dev/null

if [ "$EUID" -ne 0 ]; then
  echo "错误：请使用 root 权限运行此脚本！"
  exit 1
fi

FIREWALL_MODE=""

# 统一规则应用接口 (核心逻辑：实现 IPv4/IPv6 同步)
apply_rule() {
    local proto=$1
    local port=$2
    local action=$3 # "accept" 或其他
    
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        nft add rule inet filter input $proto dport $port $action 2>/dev/null
    else
        # iptables 模式下同时处理 IPv4 和 IPv6
        iptables -A INPUT -p $proto --dport ${port//-/:} -j ACCEPT 2>/dev/null
        ip6tables -A INPUT -p $proto --dport ${port//-/:} -j ACCEPT 2>/dev/null
    fi
}

detect_firewall() {
    if command -v nft &> /dev/null; then
        FIREWALL_MODE="nftables"
    elif command -v iptables &> /dev/null; then
        FIREWALL_MODE="iptables"
    else
        echo "正在安装防火墙组件..."
        command -v apt &> /dev/null && apt update && apt install -y iptables iproute2
        command -v yum &> /dev/null && yum install -y iptables iproute2
        FIREWALL_MODE="iptables"
    fi
}

register_shortcut() {
    if [ "$SCRIPT_PATH" != "/usr/local/bin/fw" ]; then
        cp "$SCRIPT_PATH" /usr/local/bin/fw 2>/dev/null
        chmod +x /usr/local/bin/fw 2>/dev/null
    fi
    local alias_cmd="alias fw='/usr/local/bin/fw'"
    for rc_file in "/etc/bash.bashrc" "/etc/bashrc" "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc_file" ] && ! grep -q "alias fw=" "$rc_file"; then
            echo -e "\n# 智能防火墙快捷键\n$alias_cmd" >> "$rc_file"
        fi
    done
}

auto_allow_current_ports() {
    echo "正在探测并同步放行 IPv4/IPv6 已用端口..."
    local ports=$(ss -tuln | awk 'NR>1 {print $5}' | tr ' ' '\n' | grep -oE '[0-9]+$' | sort -nu)
    for port in $ports; do
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            apply_rule tcp $port accept
            apply_rule udp $port accept
            echo "-> 已放行: $port (TCP/UDP)"
        fi
    done
}

init_firewall() {
    echo "正在初始化严格防火墙策略..."
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        nft flush ruleset
        nft add table inet filter
        nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
        nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
        nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
        nft add rule inet filter input iif "lo" accept
        nft add rule inet filter input ct state established,related accept
    else
        for cmd in iptables ip6tables; do
            $cmd -F && $cmd -X && $cmd -Z
            $cmd -P INPUT DROP
            $cmd -P FORWARD DROP
            $cmd -P OUTPUT ACCEPT
            $cmd -A INPUT -i lo -j ACCEPT
            $cmd -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        done
        ip6tables -A INPUT -p icmpv6 -j ACCEPT
    fi
    
    # 强制放行 22 和 443
    apply_rule tcp 22 accept
    apply_rule tcp 443 accept
    
    auto_allow_current_ports
    save_rules
    echo "防火墙初始化完成 (22/443 已开启)。"
}

allow_all_ports() {
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        nft flush ruleset
        nft add table inet filter
        nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }
    else
        for cmd in iptables ip6tables; do
            $cmd -F && $cmd -X && $cmd -Z
            $cmd -P INPUT ACCEPT
        done
    fi
    save_rules
}

show_rules() {
    echo -e "\n--- IPv4 规则 ---"
    [ "$FIREWALL_MODE" = "nftables" ] && nft -a list chain inet filter input || iptables -L INPUT -n --line-numbers
    echo -e "\n--- IPv6 规则 ---"
    [ "$FIREWALL_MODE" = "nftables" ] && echo "nftables 统一管理" || ip6tables -L INPUT -n --line-numbers
}

allow_port() {
    read -p "端口/范围 (80或8000-9000): " port_input
    read -p "协议: 1)TCP 2)UDP 3)ALL [默认1]: " choice
    local proto="tcp"; [ "$choice" = "2" ] && proto="udp"; [ "$choice" = "3" ] && proto="all"
    
    if [ "$proto" = "all" ]; then
        apply_rule tcp $port_input accept
        apply_rule udp $port_input accept
    else
        apply_rule $proto $port_input accept
    fi
    save_rules
}

block_port() {
    show_rules
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        read -p "Handle 编号: " h; nft delete rule inet filter input handle $h
    else
        read -p "IPv4 规则号: " n; iptables -D INPUT $n
        read -p "IPv6 规则号: " n; ip6tables -D INPUT $n
    fi
    save_rules
}

change_ssh_port() {
    read -p "新端口: " new_port
    apply_rule tcp $new_port accept
    sed -i '/^Port /d' /etc/ssh/sshd_config; echo "Port $new_port" >> /etc/ssh/sshd_config
    systemctl restart sshd || service ssh restart
    save_rules
}

save_rules() {
    if [ "$FIREWALL_MODE" = "nftables" ]; then
        nft list ruleset > /etc/nftables.conf
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    fi
}

detect_firewall
register_shortcut
while true; do
    echo -e "\n=== 智能防火墙管理 ($FIREWALL_MODE) ==="
    echo "1.白名单初始化(含22/443) 2.查看 3.放行 4.封锁 5.换SSH端口 6.全开放 7.保存 8.退出"
    read -p "操作: " choice
    case $choice in
        1) init_firewall ;; 2) show_rules ;; 3) allow_port ;;
        4) block_port ;; 5) change_ssh_port ;; 6) allow_all_ports ;;
        7) save_rules ;; 8) exit 0 ;;
    esac
done
