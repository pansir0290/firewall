 #!/bin/bash


# ====================================================================

# 脚本名称: 智能防火墙交互管理工具 (兼容 iptables/nftables)

# 功能描述: 严格白名单机制，支持端口范围、多协议选择、自动探测及一键放通

# 升级功能: 支持一键安全修改 SSH 端口，并自动生成免刷新全局 fw 命令

# ====================================================================


# 自动加权：尝试给脚本自身赋予最高执行权限

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

            apt update && apt install -y iptables iproute2 openssh-server

            FIREWALL_MODE="iptables"

        elif command -v yum &> /dev/null; then

            yum install -y iptables iproute2 openssh-server

            FIREWALL_MODE="iptables"

        else

            echo "错误：无法自动安装，请手动安装 iptables 或 nftables 后再运行！"

            exit 1

        fi

    fi

}


# 自动注册 fw 快捷键功能

register_shortcut() {

    # 1. 将当前运行的脚本复制到系统全局命令目录，并命名为 fw

    if [ "$SCRIPT_PATH" != "/usr/local/bin/fw" ]; then

        cp "$SCRIPT_PATH" /usr/local/bin/fw 2>/dev/null

        chmod +x /usr/local/bin/fw 2>/dev/null

    fi


    # 2. 写入别名到配置文件，保证持久化（重启、新开终端也有效）

    local alias_cmd="alias fw='/usr/local/bin/fw'"

    

    for rc_file in "/etc/bash.bashrc" "/etc/bashrc" "$HOME/.bashrc" "$HOME/.zshrc"; do

        if [ -f "$rc_file" ]; then

            if ! grep -q "alias fw=" "$rc_file"; then

                echo "" >> "$rc_file"

                echo "# 智能防火墙快捷键" >> "$rc_file"

                echo "$alias_cmd" >> "$rc_file"

            fi

        fi

    done

}


# 自动探测本机已占用的端口并自动放通

auto_allow_current_ports() {

    echo "正在自动探测检测本机已占用的服务端口..."

    if ! command -v ss &> /dev/null; then

        echo "未找到 ss 命令，跳过自动探测。"

        return

    fi


    local ports=$(ss -tuln | awk 'NR>1 {print $5}' | tr ' ' '\n' | grep -oE '[0-9]+$' | sort -nu)

    

    if [ -z "$ports" ]; then

        echo "未探测到活动的监听端口。"

        return

    fi


    echo "探测到以下端口正在运行服务: $(echo $ports | tr '\n' ' ')"

    for port in $ports; do

        if [[ "$port" =~ ^[0-9]+$ ]]; then

            if [ "$FIREWALL_MODE" = "nftables" ]; then

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


    auto_allow_current_ports

    echo "防火墙严格模式初始化完成！"

    save_rules

    show_rules

}


# 一键放通所有端口

allow_all_ports() {

    echo "正在切换至【一键放通所有端口】模式..."

    if [ "$FIREWALL_MODE" = "nftables" ]; then

        nft flush ruleset

        nft add table inet filter

        nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }

    else

        iptables -F && iptables -X && iptables -Z

        iptables -P INPUT ACCEPT

    fi

    echo "警告：当前已放通所有入站流量！系统处于全开放状态。"

    save_rules

}


# 显示规则

show_rules() {

    echo -e "\n================ 当前入站放行规则列表 ================"

    if [ "$FIREWALL_MODE" = "nftables" ]; then

        if nft list tables | grep -q "inet filter"; then

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


# 放行端口

allow_port() {

    echo -e "\n请输入要放行的端口或端口范围："

    echo "  - 单个端口示例: 80"

    echo "  - 端口范围示例: 8000-9000"

    read -p "请输入: " port_input


    if ! [[ "$port_input" =~ ^[0-9]+(-[0-9]+)?$ ]]; then

        echo "输入错误：请输入有效的端口或端口范围！"

        return

    fi


    echo "请选择要放行的协议类型："

    echo "1) TCP"

    echo "2) UDP"

    echo "3) ALL"

    read -p "请选择 [1-3, 默认 1]: " proto_choice

    

    local proto="tcp"

    [ "$proto_choice" = "2" ] && proto="udp"

    [ "$proto_choice" = "3" ] && proto="all"


    local nft_port="$port_input"

    local ipt_port="${port_input//-/:}"


    if [ "$FIREWALL_MODE" = "nftables" ]; then

        if ! nft list tables | grep -q "inet filter"; then init_firewall; fi

        if [ "$proto" = "all" ]; then

            nft add rule inet filter input tcp dport $nft_port accept

            nft add rule inet filter input udp dport $nft_port accept

        else

            nft add rule inet filter input $proto dport $nft_port accept

        fi

    else

        if [ "$proto" = "all" ]; then

            iptables -A INPUT -p tcp --dport $ipt_port -j ACCEPT

            iptables -A INPUT -p udp --dport $ipt_port -j ACCEPT

        else

            iptables -A INPUT -p $proto --dport $ipt_port -j ACCEPT

        fi

    fi

    echo "成功：已放行端口 $port_input ($proto)。"

    save_rules

}


# 封锁/删除端口规则

block_port() {

    show_rules

    if [ "$FIREWALL_MODE" = "nftables" ]; then

        read -p "请输入你要删除规则的 handle 编号: " handle_num

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


# 安全修改 SSH 端口并自动关闭 22 端口

change_ssh_port() {

    echo -e "\n=== 安全更改 SSH 端口向导 ==="

    read -p "请输入你想使用的新 SSH 端口号 (推荐 1024-65535 之间): " new_port

    

    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -le 0 ] || [ "$new_port" -gt 65535 ]; then

        echo "错误：请输入 1 到 65535 之间的有效数字！"

        return

    fi


    if [ "$new_port" -eq 22 ]; then

        echo "提示：你输入的就是默认的 22 端口，无需修改。"

        return

    fi


    # 1. 先在防火墙中紧急放行新端口

    echo "第一步：正在防火墙中提前放行新端口 $new_port..."

    if [ "$FIREWALL_MODE" = "nftables" ]; then

        if ! nft list tables | grep -q "inet filter"; then init_firewall; fi

        nft add rule inet filter input tcp dport $new_port accept 2>/dev/null

    else

        iptables -A INPUT -p tcp --dport $new_port -j ACCEPT 2>/dev/null

    fi


    # 2. 修改 SSH 配置文件

    echo "第二步：正在修改系统 SSH 配置文件..."

    if [ ! -f "/etc/ssh/sshd_config" ]; then

        echo "错误：未找到 /etc/ssh/sshd_config 配置文件，修改终止！"

        return

    fi


    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    sed -i '/^Port /d' /etc/ssh/sshd_config

    sed -i '/^#Port 22/d' /etc/ssh/sshd_config

    echo "Port $new_port" >> /etc/ssh/sshd_config


    # 3. 重启 SSH 服务

    echo "第三步：正在重启系统 SSH 服务使新端口生效..."

    if command -v systemctl &> /dev/null; then

        systemctl restart sshd || systemctl restart ssh

    else

        service sshd restart || service ssh restart

    fi


    sleep 2

    echo "新端口 $new_port 的 SSH 服务已成功拉起！"


    # 4. 自动在防火墙中关闭旧的 22 端口

    echo "第四步：正在防火墙中自动剔除/封锁旧的 22 端口..."

    if [ "$FIREWALL_MODE" = "nftables" ]; then

        local handles=$(nft -a list chain inet filter input | grep "tcp dport 22" | awk -F'handle ' '{print $2}')

        for h in $handles; do

            nft delete rule inet filter input handle $h 2>/dev/null

        done

    else

        while iptables -L INPUT -n --line-numbers | grep -q "dpt:22"; do

            local num=$(iptables -L INPUT -n --line-numbers | grep "dpt:22" | head -n 1 | awk '{print $1}')

            iptables -D INPUT $num 2>/dev/null

        done

    fi


    save_rules

    echo -e "\n🎉 【大功告成！】"

    echo "=========================================================="

    echo "1. 你的新 SSH 端口现在是: $new_port"

    echo "2. 防火墙已自动关闭 22 端口。"

    echo "⚠️  重要提示：请【不要断开当前的终端】，立即新开一个 Windows"

    echo "   终端连接 `你的IP:$new_port` 测试是否能成功连上！验证无误后再关闭本窗口。"

    echo "=========================================================="

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


# ==================== 核心主程序流 ====================

# 先初始化探测环境与注册快捷键

detect_firewall

register_shortcut


# 首次运行提示

if [ "$FIREWALL_MODE" = "nftables" ] && ! nft list tables | grep -q "inet filter"; then

    auto_allow_current_ports

fi


# 主菜单循环

while true; do

    echo -e "\n=== 智能防火墙高级管理菜单 ($FIREWALL_MODE) ==="

    echo "1. 开启白名单模式 (默认拒绝一切 + 自动放行当前服务端口)"

    echo "2. 查看当前放行规则"

    echo "3. 手动放行端口/端口范围 (支持 TCP/UDP/ALL)"

    echo "4. 封锁/删除指定规则"

    echo "5. 一键安全修改 SSH 端口 (修改后自动关闭22端口)"

    echo "6. 一键放通所有端口 (切换为全开模式)"

    echo "7. 手动保存当前规则"

    echo "8. 退出脚本"

    echo "=================================================="

    read -p "请选择操作 [1-8]: " choice


    case $choice in

        1) init_firewall ;;

        2) show_rules ;;

        3) allow_port ;;

        4) block_port ;;

        5) change_ssh_port ;;

        6) allow_all_ports ;;

        7) save_rules ;;

        8) 

            echo "感谢使用，脚本已安全退出。"

            # 【核心自动化技巧】退出时强制清除系统命令哈希表，让新写入的 fw 立即免刷新直接生效！

            hash -r 2>/dev/null

            exit 0 

            ;;

        *) echo "无效选项，请重新选择！" ;;

    esac

done 
