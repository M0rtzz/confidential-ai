#!/usr/bin/env bash
# 中心端机密计算数据面：签发隔离 mTLS 证书，拉起模拟证明服务与 CipherGPU 代理，
# 并把访问参数写入本实例的 600 凭据文件。仅作用于 center 实例，不触碰其他工作区资源。
set -Eeuo pipefail

DEV_NAME="${DATA_SANDBOX_DEV_NAME:-center}"
WORKSPACE_DIR="${DATA_SANDBOX_WORKSPACE_DIR:-/data/collab/Projects/gpu}"
DEV_ROOT="${WORKSPACE_DIR}/.dev-runtime/${DEV_NAME}"
DEV_PREFIX="data-sandbox-dev-${DEV_NAME}"
DEV_NETWORK="${DEV_PREFIX}"
CREDENTIAL_FILE="${DEV_ROOT}/secretpad.env"

CIPHERGPU_CONTAINER="${DEV_PREFIX}-ciphergpu"
SIM_ATTESTATION_CONTAINER="${DEV_PREFIX}-sim-attestation"
# 复用工作区内已构建的 CipherGPU 运行时镜像，不重复构建 22 GiB 的训练依赖层。
CIPHERGPU_IMAGE="${DATA_SANDBOX_DEV_CIPHERGPU_IMAGE:-data-sandbox-ciphergpu:dev-confidential-hust}"

CONFIDENTIAL_ROOT="${DEV_ROOT}/confidential-compute"
CONFIDENTIAL_CA_DIR="${CONFIDENTIAL_ROOT}/ca"
CIPHERGPU_SERVER_CERT_DIR="${CONFIDENTIAL_ROOT}/ciphergpu-server"
SIM_ATTESTATION_SERVER_CERT_DIR="${CONFIDENTIAL_ROOT}/sim-attestation-server"
SECRETPAD_CIPHERGPU_CLIENT_DIR="${CONFIDENTIAL_ROOT}/secretpad-client"
CIPHERGPU_SIM_CLIENT_DIR="${CONFIDENTIAL_ROOT}/ciphergpu-client"
CIPHERGPU_MODEL_RUNTIME_DIR="${CONFIDENTIAL_ROOT}/model-runtime"
CIPHERGPU_TRAINING_RUNTIME_DIR="${CONFIDENTIAL_ROOT}/training-runtime"
SIM_ATTESTATION_SECRET_DIR="${CONFIDENTIAL_ROOT}/sim-attestation-secret"

LABEL_PREFIX='io.hustnlp.data-sandbox'
managed_label="${LABEL_PREFIX}.dev"
owner_label="${LABEL_PREFIX}.dev-owner"
workspace_label="${LABEL_PREFIX}.dev-workspace"

log() { printf '[INFO] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }

# 只允许替换本工作区自己创建的容器，标签不符一律拒绝。
verify_managed_container() {
  local name=$1 labels
  labels="$(docker inspect "$name" --format '{{json .Config.Labels}}' 2>/dev/null)" || return 1
  case "$labels" in
    *"\"${workspace_label}\":\"${WORKSPACE_DIR}\""*) return 0 ;;
    *) log_error "拒绝操作不属于本工作区的容器：${name}"; exit 1 ;;
  esac
}

credential_value() { sed -n "s/^$1=//p" "$CREDENTIAL_FILE" | head -n 1; }

set_credential() {
  local key=$1 value=$2
  if grep -q "^${key}=" "$CREDENTIAL_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$CREDENTIAL_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >>"$CREDENTIAL_FILE"
  fi
}

generate_leaf_certificate() {
  local destination=$1 common_name=$2 usage=$3 subject_alt_name=$4 key_name=$5 cert_name=$6
  local key_file="${destination}/${key_name}" cert_file="${destination}/${cert_name}"
  local request_file="${destination}/request.csr" extensions_file="${destination}/extensions.cnf"
  mkdir -p "$destination"
  if [ -s "$key_file" ] && [ -s "$cert_file" ] && [ -s "${destination}/ca.crt" ] \
      && cmp -s "${CONFIDENTIAL_CA_DIR}/ca.crt" "${destination}/ca.crt" \
      && openssl x509 -checkend 86400 -noout -in "$cert_file" >/dev/null 2>&1 \
      && openssl verify -CAfile "${CONFIDENTIAL_CA_DIR}/ca.crt" "$cert_file" >/dev/null 2>&1; then
    chmod 444 "$key_file" "$cert_file" "${destination}/ca.crt"
    return
  fi
  chmod u+w "$key_file" "$cert_file" "${destination}/ca.crt" 2>/dev/null || true
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$key_file"
  openssl req -new -key "$key_file" -out "$request_file" -subj "/CN=${common_name}"
  {
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=%s\n' "$usage"
    printf 'subjectAltName=%s\n' "$subject_alt_name"
  } >"$extensions_file"
  openssl x509 -req -in "$request_file" \
    -CA "${CONFIDENTIAL_CA_DIR}/ca.crt" -CAkey "${CONFIDENTIAL_CA_DIR}/ca.key" \
    -CAcreateserial -days 30 -sha256 -extfile "$extensions_file" -out "$cert_file"
  cp "${CONFIDENTIAL_CA_DIR}/ca.crt" "${destination}/ca.crt"
  rm -f "$request_file" "$extensions_file"
  # DEV_ROOT 为 0700 且挂载只读，此处的全局可读位只意味着容器内固定 UID 10001 能读到。
  chmod 444 "$key_file" "$cert_file" "${destination}/ca.crt"
}

ensure_credentials() {
  umask 077
  mkdir -p "$CONFIDENTIAL_CA_DIR" "$CIPHERGPU_SERVER_CERT_DIR" "$SIM_ATTESTATION_SERVER_CERT_DIR" \
    "$SECRETPAD_CIPHERGPU_CLIENT_DIR" "$CIPHERGPU_SIM_CLIENT_DIR" "$SIM_ATTESTATION_SECRET_DIR"
  # umask 077 会把这些目录建成 0700，容器内 UID 10001 连目录都进不去。
  # 上级 .dev-runtime/<实例> 仍为 0700，CA 私钥另以 0400 保护且该目录不参与挂载。
  chmod 755 "$CONFIDENTIAL_CA_DIR" "$CIPHERGPU_SERVER_CERT_DIR" "$SIM_ATTESTATION_SERVER_CERT_DIR" \
    "$SECRETPAD_CIPHERGPU_CLIENT_DIR" "$CIPHERGPU_SIM_CLIENT_DIR" "$SIM_ATTESTATION_SECRET_DIR"
  if [ ! -s "${CONFIDENTIAL_CA_DIR}/ca.key" ] || [ ! -s "${CONFIDENTIAL_CA_DIR}/ca.crt" ] \
      || ! openssl x509 -checkend 86400 -noout -in "${CONFIDENTIAL_CA_DIR}/ca.crt" >/dev/null 2>&1; then
    local ca_config="${CONFIDENTIAL_CA_DIR}/ca.cnf"
    log "生成 A100 仿真专用的隔离 mTLS 根"
    chmod u+w "${CONFIDENTIAL_CA_DIR}/ca.key" "${CONFIDENTIAL_CA_DIR}/ca.crt" 2>/dev/null || true
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${CONFIDENTIAL_CA_DIR}/ca.key"
    {
      printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n'
      printf '[dn]\nCN=%s-a100-sim-test-root\n' "$DEV_PREFIX"
      printf '[v3_ca]\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
      printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
    } >"$ca_config"
    openssl req -x509 -new -key "${CONFIDENTIAL_CA_DIR}/ca.key" -days 30 -sha256 \
      -config "$ca_config" -out "${CONFIDENTIAL_CA_DIR}/ca.crt"
    rm -f "$ca_config"
    chmod 400 "${CONFIDENTIAL_CA_DIR}/ca.key"
    chmod 444 "${CONFIDENTIAL_CA_DIR}/ca.crt"
  fi

  generate_leaf_certificate "$CIPHERGPU_SERVER_CERT_DIR" \
    "$CIPHERGPU_CONTAINER" serverAuth "DNS:${CIPHERGPU_CONTAINER}" server.key server.crt
  generate_leaf_certificate "$SIM_ATTESTATION_SERVER_CERT_DIR" \
    "$SIM_ATTESTATION_CONTAINER" serverAuth "DNS:${SIM_ATTESTATION_CONTAINER}" server.key server.crt
  generate_leaf_certificate "$SECRETPAD_CIPHERGPU_CLIENT_DIR" \
    "${DEV_PREFIX}-secretpad-control-plane" clientAuth \
    "DNS:${DEV_PREFIX}-secretpad-control-plane" client.key client.crt
  generate_leaf_certificate "$CIPHERGPU_SIM_CLIENT_DIR" \
    "${DEV_PREFIX}-ciphergpu-agent" clientAuth \
    "DNS:${DEV_PREFIX}-ciphergpu-agent" client.key client.crt

  local signing_key="${SIM_ATTESTATION_SECRET_DIR}/sak.key"
  local public_key_file="${SIM_ATTESTATION_SECRET_DIR}/sak.public"
  if [ ! -s "$signing_key" ]; then
    log "生成仅用于仿真的 Ed25519 证据签名密钥"
    openssl rand -out "$signing_key" 32
  fi
  chmod 444 "$signing_key"
  if [ ! -s "$public_key_file" ]; then
    docker run --rm -v "${SIM_ATTESTATION_SECRET_DIR}:/run/secrets:ro" \
      --entrypoint /usr/bin/python3 "$CIPHERGPU_IMAGE" -c \
      'from ciphergpu.crypto import EvidenceSigner; print(EvidenceSigner.load("/run/secrets/sak.key").public_key)' \
      >"$public_key_file"
    chmod 444 "$public_key_file"
  fi

  local tls_public_key_hash
  tls_public_key_hash="sha256:$(openssl x509 -in "${CIPHERGPU_SERVER_CERT_DIR}/server.crt" \
    -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
  set_credential CIPHERGPU_URL "https://${CIPHERGPU_CONTAINER}:9000"
  set_credential CIPHERGPU_CLIENT_CERT_DIR /app/ciphergpu-client
  set_credential CIPHERGPU_ALLOW_INSECURE_HTTP false
  set_credential CIPHERGPU_SIM_ROOT_PUBLIC_KEY "$(tr -d '\r\n' <"$public_key_file")"
  set_credential CIPHERGPU_WORKLOAD_DIGEST sha256:builtin-digest-v1
  set_credential CIPHERGPU_POLICY_DIGEST sha256:a100-sim-policy-v1
  set_credential CIPHERGPU_TLS_PUBLIC_KEY_HASH "$tls_public_key_hash"
  set_credential CONFIDENTIAL_COMPUTE_SECURITY_PROFILE a100-sim
  chmod 600 "$CREDENTIAL_FILE"
}

wait_for_service() {
  local url=$1 client_cert_dir=$2
  docker run --rm --network "$DEV_NETWORK" \
    -e "HEALTH_URL=${url}/v1/health" \
    -v "${client_cert_dir}:/run/client:ro" \
    --entrypoint /usr/bin/python3 "$CIPHERGPU_IMAGE" -c '
import os, ssl, time, httpx

tls = ssl.create_default_context(cafile="/run/client/ca.crt")
tls.load_cert_chain("/run/client/client.crt", "/run/client/client.key")
for _ in range(60):
    try:
        with httpx.Client(verify=tls, timeout=2, trust_env=False) as client:
            response = client.get(os.environ["HEALTH_URL"])
        body = response.json()
        if response.status_code == 200 and body.get("securityProfile") == "a100-sim" and body.get("simulated") is True:
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(1)
raise SystemExit(1)
' >/dev/null 2>&1
}

start_sim_attestation() {
  if verify_managed_container "$SIM_ATTESTATION_CONTAINER"; then
    docker rm -f "$SIM_ATTESTATION_CONTAINER" >/dev/null
  fi
  log "启动 A100 模拟证明服务 ${SIM_ATTESTATION_CONTAINER}"
  docker run -d --init --restart unless-stopped --read-only \
    --name "$SIM_ATTESTATION_CONTAINER" --network "$DEV_NETWORK" \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 128 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --label "${managed_label}=true" \
    --label "${owner_label}=$(id -un)" \
    --label "${workspace_label}=${WORKSPACE_DIR}" \
    -e SIM_ATTESTATION_SIGNING_KEY=/run/secrets/sak.key \
    -v "${SIM_ATTESTATION_SECRET_DIR}:/run/secrets:ro" \
    -v "${SIM_ATTESTATION_SERVER_CERT_DIR}:/run/tls:ro" \
    --entrypoint /usr/bin/python3 "$CIPHERGPU_IMAGE" -m uvicorn ciphergpu.sim_attestation:app \
      --host 0.0.0.0 --port 9100 --no-access-log \
      --ssl-keyfile /run/tls/server.key --ssl-certfile /run/tls/server.crt \
      --ssl-ca-certs /run/tls/ca.crt --ssl-cert-reqs 2 >/dev/null
  wait_for_service "https://${SIM_ATTESTATION_CONTAINER}:9100" "$CIPHERGPU_SIM_CLIENT_DIR" || {
    log_error "模拟证明服务未达健康状态。"; exit 1; }
}

# 选一张空闲显存最多的卡。同机其他用户的训练任务与本平台共用这几张 A100，
# 固定绑定某张卡会与他人负载抢显存和算力，表现为推理长时间不返回。
# 显存相同时取利用率更低的一张；nvidia-smi 不可用则不设置，交由容器自行决定。
select_gpu() {
  if [ -n "${DATA_SANDBOX_DEV_CIPHERGPU_VISIBLE_DEVICES:-}" ]; then
    printf '%s' "$DATA_SANDBOX_DEV_CIPHERGPU_VISIBLE_DEVICES"
    return
  fi
  command -v nvidia-smi >/dev/null 2>&1 || return
  nvidia-smi --query-gpu=index,memory.free,utilization.gpu \
    --format=csv,noheader,nounits 2>/dev/null \
    | tr -d ' ' | sort -t, -k2,2nr -k3,3n | head -n 1 | cut -d, -f1
}

start_ciphergpu() {
  if verify_managed_container "$CIPHERGPU_CONTAINER"; then
    docker rm -f "$CIPHERGPU_CONTAINER" >/dev/null
  fi
  mkdir -p "$CIPHERGPU_MODEL_RUNTIME_DIR" "$CIPHERGPU_TRAINING_RUNTIME_DIR"
  # 代理进程仍是镜像内的非 root 用户；这里只借容器把两个专用挂载点初始化为容器 UID，
  # 避免把宿主机 UID 注入容器（PyTorch 也要求 UID 在 passwd 中可解析）。
  local mount
  for mount in "$CIPHERGPU_MODEL_RUNTIME_DIR" "$CIPHERGPU_TRAINING_RUNTIME_DIR"; do
    docker run --rm --user 0:0 -v "${mount}:/runtime:rw" \
      --entrypoint /bin/chown "$CIPHERGPU_IMAGE" -R 10001:10001 /runtime
    docker run --rm --user 0:0 -v "${mount}:/runtime:rw" \
      --entrypoint /bin/chmod "$CIPHERGPU_IMAGE" 700 /runtime
  done
  local gpu_args=()
  if [ "${DATA_SANDBOX_DEV_CIPHERGPU_GPUS:-all}" != none ]; then
    gpu_args+=(--gpus "${DATA_SANDBOX_DEV_CIPHERGPU_GPUS:-all}")
  fi
  local visible_devices
  visible_devices="$(select_gpu)"
  if [ -n "$visible_devices" ]; then
    gpu_args+=(-e "CUDA_VISIBLE_DEVICES=${visible_devices}")
    log "选定 GPU ${visible_devices}（空闲显存最多）"
  else
    log "未能读取 GPU 状态，不限定可见设备"
  fi
  log "启动 CipherGPU A100 仿真代理 ${CIPHERGPU_CONTAINER}"
  docker run -d --init --restart unless-stopped --read-only \
    --name "$CIPHERGPU_CONTAINER" --network "$DEV_NETWORK" \
    --add-host host.docker.internal:host-gateway \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 256 --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    "${gpu_args[@]}" \
    --label "${managed_label}=true" \
    --label "${owner_label}=$(id -un)" \
    --label "${workspace_label}=${WORKSPACE_DIR}" \
    -e CIPHERGPU_TLS_KEY=/run/tls/server.key \
    -e CIPHERGPU_TLS_CERT=/run/tls/server.crt \
    -e CIPHERGPU_TLS_CA=/run/tls/ca.crt \
    -e "CIPHERGPU_TLS_PUBLIC_KEY_HASH=$(credential_value CIPHERGPU_TLS_PUBLIC_KEY_HASH)" \
    -e CIPHERGPU_WORKLOAD_DIGEST=sha256:builtin-digest-v1 \
    -e CIPHERGPU_POLICY_DIGEST=sha256:a100-sim-policy-v1 \
    -e "SIM_ATTESTATION_URL=https://${SIM_ATTESTATION_CONTAINER}:9100" \
    -e SIM_ATTESTATION_CA=/run/sim-client/ca.crt \
    -e SIM_ATTESTATION_CLIENT_CERT=/run/sim-client/client.crt \
    -e SIM_ATTESTATION_CLIENT_KEY=/run/sim-client/client.key \
    -e CIPHERGPU_MODEL_RUNTIME_DIR=/var/lib/ciphergpu/models \
    -e CIPHERGPU_TRAINING_RUNTIME_DIR=/var/lib/ciphergpu/training \
    -e "CIPHERGPU_TRAINING_IMAGE_DIGEST=sha256:$(docker image inspect --format '{{.Id}}' "$CIPHERGPU_IMAGE" | sed 's/^sha256://')" \
    -e HOME=/var/lib/ciphergpu/models/.home \
    -e XDG_CACHE_HOME=/var/lib/ciphergpu/models/.cache \
    -e "CIPHERGPU_VLLM_GPU_MEMORY_UTILIZATION=${DATA_SANDBOX_DEV_VLLM_GPU_MEMORY_UTILIZATION:-0.10}" \
    -e "CIPHERGPU_VLLM_MAX_MODEL_LEN=${DATA_SANDBOX_DEV_VLLM_MAX_MODEL_LEN:-1024}" \
    -v "${CIPHERGPU_SERVER_CERT_DIR}:/run/tls:ro" \
    -v "${CIPHERGPU_SIM_CLIENT_DIR}:/run/sim-client:ro" \
    -v "${CIPHERGPU_MODEL_RUNTIME_DIR}:/var/lib/ciphergpu/models:rw" \
    -v "${CIPHERGPU_TRAINING_RUNTIME_DIR}:/var/lib/ciphergpu/training:rw" \
    "$CIPHERGPU_IMAGE" >/dev/null
  wait_for_service "https://${CIPHERGPU_CONTAINER}:9000" "$SECRETPAD_CIPHERGPU_CLIENT_DIR" || {
    log_error "CipherGPU 代理未达健康状态。"; exit 1; }
  verify_capabilities
}

verify_capabilities() {
  docker run --rm --network "$DEV_NETWORK" \
    -e "CAPABILITIES_URL=https://${CIPHERGPU_CONTAINER}:9000/v1/crypto/capabilities" \
    -v "${SECRETPAD_CIPHERGPU_CLIENT_DIR}:/run/client:ro" \
    --entrypoint /usr/bin/python3 "$CIPHERGPU_IMAGE" -c '
import os, ssl, httpx

tls = ssl.create_default_context(cafile="/run/client/ca.crt")
tls.load_cert_chain("/run/client/client.crt", "/run/client/client.key")
with httpx.Client(verify=tls, timeout=5, trust_env=False) as client:
    response = client.get(os.environ["CAPABILITIES_URL"])
    response.raise_for_status()
    body = response.json()
names = {item.get("algorithm") for item in body.get("contentEncryptionAlgorithms", [])}
required = {"AES-256-GCM", "AES-256-GCM-SIV", "CHACHA20-POLY1305", "XCHACHA20-POLY1305", "AES-256-SIV"}
if body.get("format") != "ds-envelope/v2" or names != required:
    raise SystemExit("CipherGPU content-encryption capability mismatch")
' >/dev/null || { log_error "CipherGPU 未发布要求的五种 ds-envelope/v2 算法。"; exit 1; }
  log "CipherGPU ds-envelope/v2 五算法能力检查通过。"
}

[ -s "$CREDENTIAL_FILE" ] || { log_error "未找到实例凭据文件：${CREDENTIAL_FILE}"; exit 1; }
docker image inspect "$CIPHERGPU_IMAGE" >/dev/null || {
  log_error "CipherGPU 镜像不存在：${CIPHERGPU_IMAGE}"; exit 1; }
ensure_credentials
start_sim_attestation
start_ciphergpu
log "中心端机密计算数据面就绪。"
