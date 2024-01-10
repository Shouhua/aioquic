#!/usr/bin/env bash

# 本脚本主要是使用linux network namespace模拟docker的网络设置。
# 1. 新建一个虚拟bridge，两个veth和两个namespace，并且将两个veth分别设置到两个namespace中
# 2. 执行操作从一个namespace中ping另一个namespace中的网络
# 3. 执行操作从一个namespace中ping外部网络

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
        echo "必须使用root才能运行此脚本"
        exit 1
fi

n1="dev"
n2="prod"
br="v-net-0"
action=${1:-"create"}

function del_conf()
{
        echo "清除networkd namespace"
        # ip netns show
        ns=$(ip netns)
        if [[ $ns == *$n1* ]]; then
                ip netns del $n1
        fi
        if [[ $ns == *$n2* ]]; then
                ip netns del $n2
        fi

        echo "清除networkd bridge"
        # ip link show type bridge
        brs=$(ip link show type bridge | awk 'NR%2!=0 {print substr($2, 1, length($2)-1)}' | xargs -n 10)
        if [[ $brs == *$br* ]]; then
                ip link del $br
        fi

        echo "清除自定义的SNAT"
        set +e
        iptables -C POSTROUTING -t nat -s 192.168.20.0/24 -j MASQUERADE &> /dev/null
        if [[ $? == 0 ]]; then
                iptables -t nat -D POSTROUTING 1
        fi
        set -e
}

if [[ "$action" == "del" ]]; then
        del_conf
        exit
fi

# 清除相关配置
del_conf

# 新建两个net namespace 
ip netns add "$n1"
ip netns add "$n2"
# ip netns show

# 新建virtual network bridge
ip link add "$br" type bridge
ip link set dev "$br" up

# 新建两对veth
ip link add veth-dev type veth peer name veth-dev-br
ip link add veth-prod type veth peer name veth-prod-br
# 设置veth，一端位于net namespace，另一端位于host的bridge
ip link set veth-dev netns dev
ip link set veth-dev-br master v-net-0
ip link set veth-prod netns prod
ip link set veth-prod-br master v-net-0

# 设置两对veth的ip地址和状态
ip -n dev addr add 192.168.20.1/24 dev veth-dev
ip -n dev link set veth-dev up
ip link set veth-dev-br up

ip -n prod addr add 192.168.20.2/24 dev veth-prod
ip -n prod link set veth-prod up
ip link set veth-prod-br up

# 设置bridige的ip地址
# ping return UNREACHEABLE, need default route
ip addr add 192.168.20.20/24 dev v-net-0

# 从network namespace里面ping另一个namespace
ip netns exec dev ping -c 3 192.168.20.2
echo 

# 为两个namespace添加默认路由和iptables SNAT，不然ping外边ip地址会return 100% LOSS, need iptables rule
ip -n dev route add default via 192.168.20.20
ip -n prod route add default via 192.168.20.20
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 192.168.20.0/24 -j MASQUERADE
ip netns exec dev ping -c 3 8.8.8.8

del_conf