#!/usr/bin/env bash
# 主工作区 TEE 入口；构建、源码下载和服务启动均为显式子命令。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -u "$ROOT/scripts/deploy/tee/platform_deploy.py" "$@"
