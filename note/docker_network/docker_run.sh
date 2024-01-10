#! /usr/bin/env bash
set -euo pipefail

# --privileged 用于提供网络权限，比如新建网络命名空间等
docker run --rm -itd --name ubuntu --privileged iptables