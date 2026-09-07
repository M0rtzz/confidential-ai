#!/usr/bin/env bash
# 本次深度学习测试的专属入口，所有可写路径都位于独立工作树。
set -euo pipefail
DL_BACKEND="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DL_WORKSPACE="$(dirname "$DL_BACKEND")"
[ "$(basename "$DL_WORKSPACE")" = gpu-deep-learning-20260907 ] || { echo '必须在专属测试目录执行' >&2; exit 1; }
export DATA_SANDBOX_TEE_PROFILE=deep-learning
export DATA_SANDBOX_WORKSPACE_DIR="$DL_WORKSPACE"
export DATA_SANDBOX_FRONTEND_DIR="$DL_WORKSPACE/confidential-ai-frontend"
export DATA_SANDBOX_TOOLKIT_DIR="$DL_WORKSPACE/data-sandbox-package"
export DATA_SANDBOX_TEE_RUNTIME_ROOT="$DL_WORKSPACE/.dev-runtime"
export DATA_SANDBOX_BACKEND_BRANCH=codex/deep-learning-20260907
export DATA_SANDBOX_FRONTEND_BRANCH=codex/deep-learning-20260907
export DATA_SANDBOX_MAVEN_CACHE=/data/collab/Projects/gpu/.cache/m2
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$DL_BACKEND/scripts/deploy/tee/platform_deploy.py" --tee "$@"
