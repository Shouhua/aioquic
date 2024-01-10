FROM ubuntu:latest

RUN apt update -y
RUN apt install vim \
    iptables \
    iproute2 \
    iputils-ping \
    curl \
    net-tools \
    tcpdump -y

# docker build -t iptables .
# 安装包提供命令: vi, iptables, ip, ping, curl, route, tcpdump