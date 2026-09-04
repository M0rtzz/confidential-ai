# 机密模型托管与密态推理后端技术文档

## 1. 文档范围

本文说明 `feat/confidential-compute-mvp` 分支新增后端和数据面实现，面向后端开发、联调、测试、安全评审和运维人员。只描述本次新增的机密计算控制面、机密模型、CipherGPU、模拟证明和隔离部署，不描述平台原有业务模块。

## 2. 代码组成

本功能跨四个仓库实现：

| 仓库职责                     | 工作目录                                        | 新增代码入口                                                                                                     |
| ---------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Java 控制面                  | `gpu-confidential-mvp/confidential-ai`          | `secretpad-web/.../controller/Confidential*Controller.java`、`secretpad-web/.../service/crypto/`、Flyway V45/V46 |
| Web 前端和浏览器密码模块     | `gpu-confidential-mvp/confidential-ai-frontend` | `apps/platform/src/modules/confidential-compute/`、`apps/platform/src/security/crypto/`                          |
| 隔离开发部署和本地 vLLM 脚本 | `gpu-confidential-mvp/data-sandbox-package`     | `develop.sh`、`build.sh`、`serve-hf-model.sh`                                                                    |
| Python 数据面                | `gpu/ciphergpu`                                 | `ciphergpu/app.py`、`service.py`、`crypto.py`、`models.py`、`sim_attestation.py`                                 |

四个仓库使用分支 `feat/confidential-compute-mvp`。

## 3. 架构与数据流

```text
Browser
  |  X25519/Ed25519 session identity
  |  file/API-key/request encryption
  |  attestation validation and grant signing
  v
Java control plane
  |  identity, metadata, immutable TaskSpec
  |  model version/review/deployment state
  |  ciphertext/hash/signature/audit only
  +---------------------> MinIO
  |                        cipher chunks and manifests
  |
  | mTLS
  v
CipherGPU :9000  <------ mTLS ------  sim-attestation :9100
  |  one-time TEK                         lab SAK signature
  |  grant and envelope verification
  |  transient DEK/API key/request key
  |  encrypted execution output
  +------> pre-started vLLM OpenAI endpoint
  |
  +------> remote OpenAI-compatible HTTPS endpoint
```

Java 控制面没有 AES 或 HPKE 解密接口。它负责身份与所有者范围校验、协议编排、元数据持久化、状态机和审计；密码输入解封只发生在浏览器或 CipherGPU 中。

## 4. 安全档位和信任边界

### 4.1 固定协议常量

当前实现由 `ConfidentialContract` 和 CipherGPU Pydantic 模型共同限制：

| 常量         | 值                          |
| ------------ | --------------------------- |
| 合同版本     | `ds-confidential/v1`        |
| 安全档位     | `a100-sim`                  |
| 运行模式     | `SIMULATION`                |
| 证据类型     | `SIMULATED_LAB_V1`          |
| 硬件标识     | `NVIDIA A100`               |
| 模拟标记     | `simulated=true`            |
| 硬件证明标记 | `attestationVerified=false` |
| 证明策略     | `policy/a100-sim/v1`        |

TaskSpec、grant、模拟证据、执行回执、模型部署和推理响应均重复携带安全档位，防止调用链中某一层删除模拟标识。

### 4.2 当前能保护的范围

- 浏览器生成用户会话私钥和 DEK；
- Java、数据库、MinIO 和控制面日志只处理密文或封装；
- CipherGPU 使用一次性 TEK，并在任务或部署生命周期内短时持有解密材料；
- 控制面到 CipherGPU、CipherGPU 到模拟证明服务使用独立 mTLS 身份；
- 模拟证明绑定任务摘要、nonce、TEK、TLS 公钥 Hash、workload digest、policy digest、会话和过期时间；
- `gpu-cc` 资产在控制面和 CipherGPU 两层拒绝运行。

### 4.3 当前不能保护的范围

A100 没有本方案需要的 GPU CC 硬件隔离。宿主 root、GPU 驱动层和高权限调试人员理论上可以读取或修改任务期间的运行时明文。`SIMULATED_LAB_V1` 只能证明测试签名和协议字段未被修改，不能证明 CPU/GPU 内存对管理员保密。

## 5. Java 控制面实现

### 5.1 Controller

新增三个 REST Controller：

| 类                                | 路径                                   | 职责                                            |
| --------------------------------- | -------------------------------------- | ----------------------------------------------- |
| `ConfidentialComputeController`   | `/api/v1alpha1/crypto`                 | 身份、可信域、TaskSpec、证明、grant、执行和审计 |
| `ConfidentialModelController`     | `/api/v1alpha1/confidential-models`    | 双来源模型、上传、版本、审核、部署和下线        |
| `ConfidentialInferenceController` | `/api/v1alpha1/confidential-inference` | 外层密文 OpenAI `chat/completions` 转发         |

Controller 返回统一 `SecretPadResponse<T>`，并从 `UserContext` 取得当前 `ownerId`。模型、版本、部署、任务和 grant 查询都带所有者条件，避免仅凭资源 ID 跨所有者访问。

### 5.2 Service

| 类                           | 新增职责                                                              |
| ---------------------------- | --------------------------------------------------------------------- |
| `ConfidentialComputeService` | 创建规范化 TaskSpec；验证模拟证明、grant 和签名回执；消费一次性 grant |
| `ConfidentialModelService`   | 管理密文上传、模型版本、审核状态、部署授权、SSRF 校验和推理路由       |
| `ConfidentialMetadataStore`  | 持久化身份、任务、证明、grant、执行和 Hash 链审计                     |
| `CipherGpuClient`            | 使用 mTLS 调用 CipherGPU，只传密文、签名和元数据                      |
| `ConfidentialCanonical`      | RFC 8785 风格规范化 JSON、SHA-256、Base64URL 和 Ed25519 验证          |

### 5.3 CipherGPU HTTP 客户端

`CipherGpuClient` 默认只允许 HTTPS。开发环境也通过生成的 CA 和短期服务证书连接 `https://<ciphergpu-container>:9000`。只有显式配置 `CIPHERGPU_ALLOW_INSECURE_HTTP=true` 才允许不安全 HTTP，不应在共享或生产环境启用。

实现缓存已初始化的 `SSLContext`，但每次业务请求创建新的 Java `HttpClient`。这样可以避免复用已被 Uvicorn 关闭的空闲 HTTP 连接，修复首次推理成功、第二次请求出现 `KEY_SERVICE_UNAVAILABLE` 的问题。

调用失败统一映射为协议错误，响应正文不得写入包含 secret 的日志。

## 6. 浏览器密码协议

虽然浏览器实现位于前端仓库，但它定义了后端必须验证的数据合同。

### 6.1 会话身份

每个页面会话生成：

- X25519 UEK，用于 HPKE 接收；
- Ed25519 USK，用于 proof-of-possession、manifest 和 grant 签名。

注册请求签名覆盖：

```json
{
  "kid": "...",
  "encryptionPublicKey": "...",
  "signingPublicKey": "..."
}
```

Java 校验两个 raw public key 均为 32 bytes，并用上传的 Ed25519 公钥验证 proof-of-possession 后才保存公钥身份。数据库不包含私钥。

### 6.2 内容 DEK 和 HPKE

每个权重文件或 API Key 创建随机 32-byte DEK。DEK 的跨边界传输统一使用：

```text
HPKE-Base-X25519-HKDF-SHA256-AES-256-GCM
```

HPKE 只封装小密钥，不直接加密大文件。envelope 绑定 recipient、协议 info 和 AAD；任务授权时会重新把同一 DEK 封装给本次证明中的 TEK 公钥。

### 6.3 权重文件格式

权重文件使用 `ds-envelope/v2`，固定分块大小为 8 MiB。客户端先生成 32-byte DEK，再使用 HKDF-SHA256 按 envelope 和算法派生内容密钥。

| 算法                 | 派生内容密钥 |    nonce |      tag |
| -------------------- | -----------: | -------: | -------: |
| `AES-256-GCM`        |     32 bytes | 12 bytes | 16 bytes |
| `AES-256-GCM-SIV`    |     32 bytes | 12 bytes | 16 bytes |
| `CHACHA20-POLY1305`  |     32 bytes | 12 bytes | 16 bytes |
| `XCHACHA20-POLY1305` |     32 bytes | 24 bytes | 16 bytes |
| `AES-256-SIV`        |     64 bytes | 16 bytes | 16 bytes |

每块 AAD 至少包含：

```json
{
  "format": "ds-envelope/v2",
  "envelopeId": "env_...",
  "contentEncryptionAlgorithm": "AES-256-GCM",
  "implementationVersion": "1",
  "domainId": "a100-domain-a",
  "publicKeyId": "...",
  "publicKeyVersion": 1,
  "chunkIndex": 0,
  "plaintextLength": 8388608
}
```

每块携带独立 nonce 和密文 SHA-256。manifest 不携带块内联密文，只声明块序号、明文长度和 SHA-256；后端将声明与实际存储的对象记录逐项比较。

版本提交时后端验证：

1. format 必须为 `ds-envelope/v2`；
2. 顶层和 `contentEncryption.algorithm` 必须与上传会话算法一致；
3. manifest 块数必须等于上传会话预期块数；
4. 块序号连续且与数据库记录一致；
5. manifest 不得内联 `ciphertext`；
6. 每块 SHA-256 必须与上传时校验值一致；
7. manifest 规范化 SHA-256 必须等于 `manifestHash`；
8. owner signing public key 必须是已注册身份，并通过 Ed25519 签名验证。

### 6.4 API Key 密文

API Key 使用 `ds-envelope/v1` 和 AES-256-GCM。后端要求存在 `ciphertext`、`nonce`、`cipherHash` 和 `keyEnvelope`，同时拒绝 `apiKey`、`plaintext`、`privateKey` 等明文字段。

API Key 密文保存于 `ds_model_credential.encrypted_credential_json`。Java 不解密，只在模型授权执行时把密文作为 encrypted input 转发给 CipherGPU。

### 6.5 规范化和完整性

签名和摘要一律针对规范化 JSON，而不是普通序列化字符串。关键对象使用 SHA-256：

- TaskSpec digest；
- manifest hash；
- cipher chunk hash；
- evidence hash；
- grant claims hash；
- encrypted output hash；
- audit event hash。

GCM/SIV/Poly1305 认证失败、Hash 不一致、签名不一致或 AAD 不一致均 fail closed。

## 7. 核心后端流程

### 7.1 身份和可信域

```text
Browser -> POST /crypto/identities
        -> Java verifies Ed25519 proof-of-possession
        -> stores public keys only

Browser -> POST /crypto/trusted-domains/{id}/verify
        -> Java checks active/trusted
        -> mTLS GET CipherGPU /v1/health
        -> verifies explicit simulation identity
        -> appends audit event
```

控制面不会仅信任前端传入的域状态。上传、创建 TaskSpec 和证明时都会重新调用 `requireUsableDomain`。

### 7.2 权重导入

```text
Browser encrypts 8 MiB chunks
  -> create upload session, TTL 2 hours
  -> PUT-like POST each ciphertext chunk with X-Cipher-SHA256
  -> Java validates index, size and digest
  -> MinIO stores cipher/{owner}/models/{uploadSession}/{index}
  -> Browser submits signed manifest
  -> Java cross-checks all stored chunks and signature
  -> MinIO stores cipher-manifests/{owner}/{assetVersion}.json
  -> Java creates asset version and model version
```

单块允许的最大大小是 `16 MiB + 64 bytes`。同一上传会话同一块索引再次上传时更新对象元数据而不重复增加已接收块数。所有分块收齐前不能 commit。

### 7.3 OpenAI 兼容模型导入

```text
Browser encrypts API key with AES-256-GCM
  -> Java validates domain and remote Base URL
  -> validates ds-envelope/v1 shape and SHA-256
  -> stores encrypted credential
  -> creates immutable model version
```

Base URL 在 Java 和 CipherGPU 两层校验。两层都要求 HTTPS、公网目标且禁止重定向。双层校验用于防止绕过控制面直接构造数据面注册请求。

### 7.4 审核

审核动作和合法状态迁移：

| action    | 起始状态                 | 目标状态         |
| --------- | ------------------------ | ---------------- |
| `SUBMIT`  | `IMPORTED` 或 `REJECTED` | `PENDING_REVIEW` |
| `APPROVE` | `PENDING_REVIEW`         | `APPROVED`       |
| `REJECT`  | `PENDING_REVIEW`         | `REJECTED`       |

控制面为机密模型版本创建审批记录和历史记录，并把 `approval_id` 写回版本。当前实现以 `ownerId` 作为提交者、操作者和 reviewer，尚未加入新增的职责分离权限层。

### 7.5 发布和授权

发布拆成注册部署与一次性密钥授权两个阶段：

```text
POST /confidential-models/{modelId}/deployments
  -> require version APPROVED
  -> reuse an existing AUTHORIZATION_REQUIRED deployment if present
  -> register ephemeral deployment in CipherGPU
  -> model state PUBLISHING

Browser creates TaskSpec and attestation session
  -> verifies evidence
  -> signs grant with maxUses=1
  -> HPKE seals model DEK to session TEK

POST /confidential-models/deployments/{id}/authorize
  -> atomically consumes grant jti
  -> CipherGPU decrypts and validates model input
  -> binds deployment to attestation session
  -> ONLINE or RUNTIME_REQUIRED
```

`LOCAL_WEIGHTS` 的 CipherGPU 部署地址来自 `CIPHERGPU_VLLM_URL`。为空时，授权执行成功但状态为 `RUNTIME_REQUIRED`，错误码为 `VLLM_ENDPOINT_NOT_CONFIGURED`。

`OPENAI_COMPATIBLE` 的 Base URL 和 upstream model ID 来自不可变模型版本；解密出的 API Key 保存为 CipherGPU 进程内 `bytearray`，不返回 Java。

### 7.6 TaskSpec、证明和 grant

TaskSpec 由 Java 生成，有效期 5 分钟，至少绑定：

- `taskId` 和 `domainId`；
- `securityProfile`、`evidenceType`、`simulated`、`hardwareModel`；
- `runtimeSecurityRequirement`；
- purpose、workload ID 和 digest；
- asset version IDs；
- output recipients；
- attestation policy 和 policy digest；
- `egressPolicy=deny-all`；
- issued/expiry time。

证明请求携带客户端 nonce、TaskSpec digest、期望档位和 TTL。CipherGPU 每个会话创建一次性 X25519 TEK，模拟证明服务使用独立 SAK 对 evidence 签名。

Java 验证 evidence 必须绑定：

- 原始客户端 nonce；
- TaskSpec digest；
- TEK public key hash；
- CipherGPU TLS public key hash；
- workload digest 和 policy digest；
- session ID、issuedAt 和 expiresAt；
- A100 模拟身份字段。

grant claims 使用 Ed25519 签名，并且必须与 TaskSpec 和会话一致。`maxUses` 固定为 1，`jti` 在数据库中唯一。`consumeGrant` 使用条件更新原子写入 `consumed_at`；过期、撤销、已消费或会话不一致都失败。

### 7.7 执行和加密输出

CipherGPU 执行时再次独立验证 TaskSpec digest、用户签名、grant claims、session、TEK hash、输入版本、输出接收人、有效期和 `jti`。之后：

1. 使用 TEK 私钥打开 sealed DEK；
2. 根据输入算法和 AAD 解密、验证输入；
3. 执行受控 workload；
4. 随机生成 ODK；
5. 使用 AES-256-GCM 加密输出；
6. 为每个输出接收人分别创建 HPKE ODK envelope；
7. 生成由模拟 SAK 签名的执行回执；
8. 在 `finally` 路径清零可变密钥缓冲。

Java 验证执行回执的模拟身份、execution/task/session 绑定、output ciphertext hash、完成时间和 SAK 签名后才持久化执行结果。

### 7.8 密态推理

对外入口：

```text
POST /api/v1alpha1/confidential-inference/chat/completions
```

外层请求：

```json
{
  "deploymentId": "deploy_...",
  "sessionId": "tees_...",
  "encryptedRequest": {
    "algorithm": "AES-256-GCM",
    "nonce": "base64url",
    "aad": {
      "contractVersion": "ds-confidential/v1",
      "deploymentId": "deploy_...",
      "sessionId": "tees_..."
    },
    "ciphertext": "base64url",
    "cipherHash": "sha256-hex",
    "sealedRequestKey": {
      "enc": "base64url",
      "ciphertext": "base64url",
      "aad": "base64url"
    }
  }
}
```

浏览器每次请求生成新的 32-byte request key 和 12-byte nonce。明文体仍为标准 OpenAI `chat/completions` JSON。request key 的 HPKE AAD 为：

```text
inference|{deploymentId}|{sessionId}|{cipherHash}
```

Java 只确认当前 owner 的部署状态为 `ONLINE`，随后原样转发密文。CipherGPU 校验部署、授权 session、Hash 和 AAD，解密后强制覆盖 `model` 为注册的 upstream model ID，防止调用者绕过部署选择其他模型。

路由规则：

| source type         | 目标                                     | 鉴权                                        |
| ------------------- | ---------------------------------------- | ------------------------------------------- |
| `LOCAL_WEIGHTS`     | `${CIPHERGPU_VLLM_URL}/chat/completions` | 当前不附加鉴权头                            |
| `OPENAI_COMPATIBLE` | `${baseUrl}/chat/completions`            | `Authorization: Bearer <decrypted-api-key>` |

CipherGPU 不跟随重定向，使用版本配置的 5 至 300 秒 timeout。返回 JSON 先用同一个 request key 加密，再清零 request key。浏览器验证响应的 deployment ID、session ID 和 ciphertext SHA-256 后本地解密。

## 8. 对外 API

所有接口位于 `/api/v1alpha1/`，并使用平台认证上下文。

### 8.1 计算协议 API

| 方法和路径                                       | 关键请求字段                                                                                                    | 结果                                  |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `POST /crypto/identities`                        | `kid, encryptionPublicKey, signingPublicKey, proofOfPossession`                                                 | 注册会话公钥身份                      |
| `GET /crypto/trusted-domains`                    | 无                                                                                                              | 返回 A100 模拟域清单                  |
| `GET /crypto/trusted-domains/{domainId}`         | path ID                                                                                                         | 返回单个域                            |
| `POST /crypto/trusted-domains/{domainId}/verify` | path ID                                                                                                         | mTLS 校验 CipherGPU 模拟身份          |
| `POST /crypto/tasks`                             | `domainId, purpose, workloadId, assetVersionIds, outputRecipients, securityProfile, runtimeSecurityRequirement` | 返回不可变 TaskSpec 和 digest         |
| `POST /crypto/attestation-sessions`              | `taskId, clientNonce, expectedSecurityProfile`                                                                  | 返回 evidence、签名、TEKpub 和 expiry |
| `POST /crypto/grants`                            | `taskId, sessionId, grant, sealedDeks, encryptedInputs, outputRecipients, scenario`                             | 保存一次性 grant                      |
| `POST /crypto/tasks/{taskId}/start`              | `grantId`                                                                                                       | 执行并返回加密输出和签名回执          |
| `GET /crypto/tasks/{taskId}/outputs`             | task ID                                                                                                         | 返回该任务最近一次加密输出            |
| `GET /crypto/audit-events`                       | 无                                                                                                              | 返回当前 owner 的审计链               |

### 8.2 机密模型 API

| 方法和路径                                                                    | 关键请求字段                                                                                      | 结果                                    |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `GET /confidential-models/capabilities`                                       | 无                                                                                                | 返回 `ds-envelope/v2`、8 MiB 和五种算法 |
| `GET /confidential-models`                                                    | 无                                                                                                | 返回当前 owner 的模型列表               |
| `GET /confidential-models/{modelId}`                                          | model ID                                                                                          | 返回模型、版本和部署详情                |
| `POST /confidential-models/weight-upload-sessions`                            | `modelName, originalFileName, originalSize, domainId, contentEncryptionAlgorithm, expectedChunks` | 创建 2 小时上传会话                     |
| `POST /confidential-models/weight-upload-sessions/{sessionId}/chunks?index=N` | octet-stream；`X-Cipher-SHA256`                                                                   | 校验并保存密文块                        |
| `POST /confidential-models/weight-versions`                                   | session/model/name/description、manifest/hash/signature、runtime config、security requirement     | 提交不可变权重版本                      |
| `POST /confidential-models/openai-compatible-versions`                        | model/name/domain、Base URL、upstream model、encrypted credential、runtime config                 | 提交不可变远程模型版本                  |
| `POST /confidential-models/{modelId}/versions/{versionId}/review`             | `action, comment`                                                                                 | 推进审核状态机                          |
| `POST /confidential-models/{modelId}/deployments`                             | `versionId`                                                                                       | 注册等待授权的部署                      |
| `POST /confidential-models/deployments/{deploymentId}/authorize`              | `taskId, grantId`                                                                                 | 消费 grant 并完成上线授权               |
| `POST /confidential-models/deployments/{deploymentId}/offline`                | 无                                                                                                | 清除 secret 并下线                      |

### 8.3 推理 API

| 方法和路径                                      | 请求                         | 结果                                 |
| ----------------------------------------------- | ---------------------------- | ------------------------------------ |
| `POST /confidential-inference/chat/completions` | encrypted inference envelope | encrypted OpenAI-compatible response |

接口需要 `User-Token`。调用方不能直接向该接口提交明文 `messages`。

## 9. CipherGPU 内部 API

内部 API 只通过 mTLS 网络暴露给受信任工作负载身份：

| 方法和路径                                         | 职责                                        |
| -------------------------------------------------- | ------------------------------------------- |
| `GET /v1/health`                                   | 返回显式模拟身份和证据签名公钥              |
| `GET /v1/crypto/capabilities`                      | 返回五种内容加密能力                        |
| `POST /v1/attestation/sessions`                    | 创建一次性 TEK 和模拟证据                   |
| `POST /v1/executions`                              | 校验授权、解密输入、加密输出                |
| `GET /v1/executions/{id}/receipt`                  | 返回不含明文的签名回执                      |
| `POST /v1/executions/{id}/cancel`                  | 取消执行                                    |
| `POST /v1/model-deployments`                       | 注册内存部署，初始 `AUTHORIZATION_REQUIRED` |
| `GET /v1/model-deployments/{id}`                   | 查询临时部署状态                            |
| `POST /v1/model-deployments/{id}/offline`          | 清零凭据并下线；不存在时幂等成功            |
| `POST /v1/confidential-inference/chat/completions` | 解密、路由、重新加密推理请求                |

Pydantic 模型使用 `extra=forbid`，未知字段直接拒绝，防止调用方通过未定义字段夹带私钥或明文配置。

模拟证明服务只提供：

| 方法和路径               | 职责                             |
| ------------------------ | -------------------------------- |
| `GET /v1/health`         | 测试证明服务健康状态             |
| `POST /v1/evidence/sign` | 使用实验室 SAK 签署模拟 evidence |
| `POST /v1/receipts/sign` | 使用实验室 SAK 签署执行回执      |

SAK 与 mTLS server/client key 分离。生产 verifier 或生产 KMS 不得信任该 SAK。

## 10. 数据库设计

新增 Flyway 迁移在 `center`、`edge` 和 `p2p` 三套 schema 中同步维护。

### 10.1 V45 计算协议表

| 表                           | 用途                                                 | 明确不保存         |
| ---------------------------- | ---------------------------------------------------- | ------------------ |
| `ds_crypto_identity`         | X25519/Ed25519 公钥身份、状态和撤销时间              | 私钥、恢复口令     |
| `ds_crypto_asset_version`    | 密文资产 manifest URI/hash/signature、安全要求       | 明文资产、DEK      |
| `ds_crypto_key_envelope`     | recipient 对应的 HPKE envelope 和 AAD hash           | raw DEK            |
| `ds_crypto_task`             | TaskSpec、digest、档位、状态和 expiry                | 明文任务输入       |
| `ds_tee_attestation_session` | nonce/TEK/evidence hash、模拟标识、策略和会话状态    | TEK 私钥           |
| `ds_crypto_grant`            | claims hash、opaque payload、唯一 jti、消费/撤销时间 | 用户私钥、解封 DEK |
| `ds_confidential_execution`  | 执行状态、receipt、output manifest hash 和密文输出   | 明文输出           |
| `ds_crypto_audit_event`      | 追加式事件及 previous/event hash                     | secret、明文正文   |

### 10.2 V46 机密模型表

| 表                               | 用途                                                                      |
| -------------------------------- | ------------------------------------------------------------------------- |
| `ds_confidential_model`          | 模型主记录、来源、最新版本和聚合状态                                      |
| `ds_model_credential`            | API Key 密文 envelope、cipher hash、状态和撤销时间                        |
| `ds_confidential_model_version`  | 不可变来源配置、密文算法、manifest、credential、runtime config 和审核状态 |
| `ds_model_deployment`            | 版本部署、security profile、授权 session、endpoint 和错误码               |
| `ds_confidential_upload_session` | 分块上传元数据、计数、状态和 2 小时 expiry                                |
| `ds_confidential_upload_chunk`   | 块序号、MinIO URI、cipher hash 和大小                                     |

时间字段当前使用 ISO-8601 字符串。所有 ID 由带类型前缀的 UUID 生成，例如 `cmodel_`、`modelv_`、`deploy_`、`task_`、`tees_` 和 `grant_`。

## 11. 对象存储布局

新增密文对象前缀：

```text
cipher/{ownerId}/models/{uploadSessionId}/{zero-padded-chunk-index}
cipher-manifests/{ownerId}/{assetVersionId}.json
```

对象内容为客户端产生的密文或签名 manifest。原始文件名仅作为受控元数据存在，不作为对象路径。上传块写入时同时传递并校验 SHA-256。

## 12. 状态、一致性和幂等性

### 12.1 模型和部署状态

```text
version/model: IMPORTED -> PENDING_REVIEW -> APPROVED -> PUBLISHING
                         -> REJECTED          |-> ONLINE
                                              |-> RUNTIME_REQUIRED
ONLINE -> OFFLINE
```

CipherGPU 内部部署初始状态固定为 `AUTHORIZATION_REQUIRED`。Java 对外模型使用 `PUBLISHING` 表示该阶段。

### 12.2 幂等和恢复规则

- 同一 upload session 和 chunk index 可重新上传，计数只增加一次；
- 同一批准版本已有 `AUTHORIZATION_REQUIRED` 记录时，`deploy` 复用最新记录；
- grant `jti` 有唯一约束，并通过原子消费防止重放；
- CipherGPU 下线不存在的内存部署返回 `OFFLINE` 和 `alreadyAbsent=true`；
- CipherGPU 重启后不从 Java 数据库恢复 secret，必须重新授权；
- 等待授权取消后，模型恢复 `APPROVED`，已授权部署下线后模型为 `OFFLINE`。

当前 Web 控制台没有为 `OFFLINE` 或 `RUNTIME_REQUIRED` 模型提供一键重新部署操作。后端仍允许对状态为 `APPROVED` 的原版本调用部署 API；前端补齐该恢复入口前，也可以通过导入、审核新版本重新进入发布流程。

当前 `deploy` 方法在单 Java 实例内使用 `synchronized` 减少重复创建。多实例部署前应增加数据库唯一约束或分布式锁，不能只依赖 JVM 锁。

## 13. SSRF 和上游调用防护

OpenAI 兼容 Base URL 在 Java `ConfidentialModelService` 中执行：

- scheme 必须为 HTTPS；
- host 必须存在；
- userinfo 和 fragment 必须为空；
- 对全部 DNS 结果执行地址分类；
- 拒绝 any-local、loopback、link-local、site-local、multicast、IPv4 `0/8`、CGNAT `100.64/10` 和 IPv6 ULA；
- 去掉末尾 `/` 后保存规范化 URL。

CipherGPU 使用 `httpx.Client(..., follow_redirects=False)` 并再次校验 URL。现有实现仍存在 DNS rebinding/解析与连接之间地址变化的残余风险；生产版本应把已校验 IP 固定到连接层，并结合 egress firewall、DNS policy 和上游域名 allowlist。

## 14. CipherGPU 内存和生命周期

CipherGPU 在进程内维护：

- `_sessions`: 一次性 TEK private key 和 expiry；
- `_consumed_jti`: 已消费 grant ID；
- `_receipts`: 签名回执；
- `_model_deployments`: 临时部署、授权 session 和解密 API Key。

这些状态不写数据库或持久卷。过期清理会删除 session，并把凭据 `bytearray` 覆盖为零。任务 request key、DEK、ODK 和解密明文缓冲在 `finally` 路径尽量清零。

Python、不可变 `bytes`、解释器复制、HTTP 库和 GPU runtime 不能提供可验证的完全内存零化保证。当前清零属于明文生命周期缩短措施，不等于 A100 硬件隔离。

## 15. 本地权重 runtime

### 15.1 启动脚本

`serve-hf-model.sh` 启动本地 Hugging Face 权重的 vLLM OpenAI server。默认值：

| 配置       | 默认值                                                      |
| ---------- | ----------------------------------------------------------- |
| 权重路径   | `/nas/Models/deepseek-llm-7b-chat`                          |
| 监听端口   | `39089`                                                     |
| 服务模型名 | 由 `--served-model-name` 指定，当前联调使用 `deepseek-chat` |

脚本支持：

- `--cuda-visible-devices`；
- `--tensor-parallel-size`；
- `--dtype`；
- `--max-model-len`；
- `--gpu-memory-utilization`；
- `--quantization`；
- `--chat-template`；
- `--api-key-file`；
- `--host` 和 `--port`。

`--api-key-file` 可保护直接访问 vLLM 的请求和脚本自身的健康检查，但当前 CipherGPU 本地 runtime connector 不会向 vLLM 附加 Authorization header。因此，本次系统联调不要启用该参数；需要启用时，必须先为 CipherGPU 增加对应的密文凭据配置和请求头注入。

示例：

```bash
cd /data/collab/Projects/gpu-confidential-mvp/data-sandbox-package

./serve-hf-model.sh start \
  --model /nas/Models/deepseek-llm-7b-chat \
  --served-model-name deepseek-chat \
  --cuda-visible-devices 0 \
  --tensor-parallel-size 1 \
  --dtype bfloat16 \
  --max-model-len 4096 \
  --gpu-memory-utilization 0.90 \
  --host 0.0.0.0 \
  --port 39089
```

### 15.2 当前运行模型绑定

模型版本中的 `runtimeConfig.servedModelName` 决定调用 vLLM 时发送的模型名。它必须和 vLLM 的 `--served-model-name` 一致。

上传的密文权重在授权执行中会被 CipherGPU 解密并验证，但当前 CipherGPU 不会把这些 bytes 组装为 Hugging Face 目录，也不会自动启动新的 vLLM worker。所有 `LOCAL_WEIGHTS` 部署共享外部预启动、由 `CIPHERGPU_VLLM_URL` 指定的 runtime。这是当前 MVP 的主要实现边界。

## 16. 隔离开发部署

`data-sandbox-package/develop.sh` 新增一个开发者独占栈，包含：

- Kuscia；
- MinIO；
- sim-attestation；
- CipherGPU；
- SecretPad 前后端镜像。

默认端口：

| 服务          | 默认端口 |
| ------------- | -------: |
| Web 控制台    |    39088 |
| 网关          |    39080 |
| API HTTP      |    39082 |
| API gRPC      |    39083 |
| internal      |    39081 |
| metrics       |    39084 |
| 外部本地 vLLM |    39089 |

建议启动：

```bash
cd /data/collab/Projects/gpu-confidential-mvp/data-sandbox-package

export DATA_SANDBOX_DEV_VLLM_URL=http://host.docker.internal:39089/v1
./develop.sh up --name confidential-mvp --api-grpc-port 39093
```

如栈已经创建，可使用对应 `restart` 操作，但必须在同一个 shell 中保留 `DATA_SANDBOX_DEV_VLLM_URL`，使重新创建的 CipherGPU 容器得到配置。

### 16.1 自动生成的安全材料

脚本在该 checkout 下的私有 `.dev-runtime/<name>/` 中生成：

- 模拟 CA；
- CipherGPU server certificate；
- sim-attestation server certificate；
- SecretPad 到 CipherGPU client certificate；
- CipherGPU 到 sim-attestation client certificate；
- 独立实验室 SAK 及公钥；
- CipherGPU TLS public key hash。

运行时把 CA、证书和私钥以只读 volume 挂载，不写入镜像。

### 16.2 容器加固

CipherGPU 和模拟证明容器采用：

- 非 root UID 10001；
- `--cap-drop ALL`；
- `no-new-privileges`；
- 进程数限制；
- `/tmp` tmpfs 且 `noexec,nosuid`；
- mTLS；
- secret 目录只读挂载；
- 不在业务日志输出密钥、请求明文或解密结果。

这些设置减少开发环境暴露面，但不改变 A100 缺少 GPU CC 的事实。

## 17. 配置项

### 17.1 Java 控制面

| 配置                            | 用途                            | 建议值                      |
| ------------------------------- | ------------------------------- | --------------------------- |
| `CIPHERGPU_URL`                 | CipherGPU 内部地址              | `https://<container>:9000`  |
| `CIPHERGPU_CLIENT_CERT_DIR`     | mTLS CA/client cert/key 目录    | 只读 secret mount           |
| `CIPHERGPU_ALLOW_INSECURE_HTTP` | 是否允许 HTTP                   | `false`                     |
| `CIPHERGPU_SIM_ROOT_PUBLIC_KEY` | 实验室 SAK 公钥                 | 由部署脚本生成              |
| `CIPHERGPU_WORKLOAD_DIGEST`     | 允许的 workload digest          | `sha256:builtin-digest-v1`  |
| `CIPHERGPU_POLICY_DIGEST`       | A100 模拟策略 digest            | `sha256:a100-sim-policy-v1` |
| `CIPHERGPU_TLS_PUBLIC_KEY_HASH` | 绑定进 evidence 的服务公钥 Hash | 从 server cert 计算         |

### 17.2 CipherGPU

| 配置                                                          | 用途                               |
| ------------------------------------------------------------- | ---------------------------------- |
| `CIPHERGPU_TLS_KEY`、`CIPHERGPU_TLS_CERT`、`CIPHERGPU_TLS_CA` | mTLS server 配置                   |
| `CIPHERGPU_TLS_PUBLIC_KEY_HASH`                               | evidence 中绑定当前 TLS identity   |
| `CIPHERGPU_WORKLOAD_DIGEST`                                   | 数据面允许的 workload              |
| `CIPHERGPU_POLICY_DIGEST`                                     | 数据面允许的模拟策略               |
| `SIM_ATTESTATION_URL`                                         | 模拟证明服务地址                   |
| `SIM_ATTESTATION_CA`                                          | 模拟证明 CA                        |
| `SIM_ATTESTATION_CLIENT_CERT`、`SIM_ATTESTATION_CLIENT_KEY`   | CipherGPU 客户端身份               |
| `CIPHERGPU_VLLM_URL`                                          | 本地权重部署使用的 OpenAI endpoint |

### 17.3 部署脚本

| 配置                              | 用途                                |
| --------------------------------- | ----------------------------------- |
| `DATA_SANDBOX_DEV_PORT`           | 控制台端口，默认 39088              |
| `DATA_SANDBOX_DEV_VLLM_URL`       | 注入 CipherGPU 的本地 vLLM endpoint |
| `DATA_SANDBOX_DEV_CIPHERGPU_GPUS` | CipherGPU 容器可见 GPU，默认 all    |
| `DATA_SANDBOX_CIPHERGPU_DIR`      | CipherGPU checkout 路径             |
| `DATA_SANDBOX_DEV_ROOT`           | 当前 checkout 下的私有运行目录      |

## 18. 错误和失败关闭

Java 业务校验使用 `TeeContract.Error`；CipherGPU 返回自己的结构化错误。当前 `CipherGpuClient` 会把 CipherGPU 非 2xx 响应映射为 Java `POLICY_DENIED`，并把上游错误码放入异常消息。因此，调用方需要同时检查 Java 错误枚举和消息中的 CipherGPU 原因码。重点错误如下：

| 错误码                      | 触发条件                                 |
| --------------------------- | ---------------------------------------- |
| `CONTRACT_INVALID`          | 缺字段、未知动作、格式或状态不合法       |
| `POLICY_DENIED`             | 域、profile、信任根或资产安全要求不允许  |
| `DATA_INTEGRITY_FAILED`     | cipher/manifest/output Hash 不一致       |
| `TASK_EXPIRED`              | TaskSpec、evidence 或 grant 过期         |
| `KEY_SERVICE_UNAVAILABLE`   | mTLS、CipherGPU 或模拟证明信任配置不可用 |
| `AUTHORIZATION_REQUIRED`    | CipherGPU 会话或部署凭据不可用           |
| `MODEL_RUNTIME_UNAVAILABLE` | 本地 vLLM endpoint 未配置或不可用        |
| `SECURITY_DOWNGRADE_DENIED` | `gpu-cc` 资产尝试进入 A100 模拟环境      |

以下情况禁止自动降级或绕过：

- 模拟证明服务不可用；
- SAK 公钥不匹配；
- nonce、TEK、TLS key hash、task digest 或 expiry 不匹配；
- grant 已消费、撤销或过期；
- manifest/密文认证失败；
- 本地 runtime 不存在；
- 资产要求 `gpu-cc`。

## 19. 测试

### 19.1 已新增测试

Java：

- `ConfidentialCanonicalTest`；
- `ConfidentialComputeServiceTest`；
- `ConfidentialModelServiceTest`。

CipherGPU：

- `tests/test_content_encryption.py`；
- `tests/test_service.py`；
- `tests/test_sim_attestation.py`。

前端的关键密码逻辑位于 `apps/platform/src/security/crypto/`，应通过 TypeScript 类型检查、lint 和端到端联调共同验证。

### 19.2 建议验证命令

Java 定向测试：

```bash
cd /data/collab/Projects/gpu-confidential-mvp/confidential-ai
./mvnw -pl secretpad-web \
  -Dtest=ConfidentialCanonicalTest,ConfidentialComputeServiceTest,ConfidentialModelServiceTest \
  test
```

CipherGPU：

```bash
cd /data/collab/Projects/gpu/ciphergpu
uv run --extra test pytest
uv run --extra test ruff check ciphergpu tests
```

前端：

```bash
cd /data/collab/Projects/gpu-confidential-mvp/confidential-ai-frontend
pnpm --filter secretpad lint:typing
pnpm --filter secretpad lint:js
```

### 19.3 必测安全分支

1. 五种算法正常解密和认证失败路径；
2. 块替换、乱序、Hash 修改和 manifest 签名修改；
3. 证据 nonce、TEKpub、task digest、policy/workload digest 修改；
4. 错误 SAK、错误 mTLS identity 和过期 evidence；
5. grant `jti` 重放和跨 session 使用；
6. `gpu-cc` 资产降级到 `a100-sim`；
7. API Key 明文字段夹带；
8. Base URL 指向 localhost、内网、云元数据、混合 DNS 结果和重定向；
9. CipherGPU 重启后的重新授权和幂等下线；
10. 连续两次及多次密态推理，确认没有复用失效连接或 request key；
11. Java/MinIO/数据库/日志扫描，确认没有 private key、raw DEK、API Key、权重或 prompt 明文。

## 20. 当前实现限制和后续工程项

### 20.1 已知限制

- 当前只有 A100 模拟证明，没有真实 CPU TEE + GPU CC 联合证明；
- 可信域清单当前由 `ConfidentialComputeService.domains()` 静态提供，尚未接入持久化域注册和动态健康管理；
- 浏览器身份和 DEK 为内存态，刷新后不可恢复；
- CipherGPU 部署、TEK 和 secret 为进程内存态，重启后必须重新授权；
- 本地权重没有按上传版本动态创建 vLLM runtime；
- 所有本地权重部署共享预配置 `CIPHERGPU_VLLM_URL`；
- 审核没有独立 reviewer 权限隔离；
- Java `synchronized` 只解决单实例重复部署；
- 远程 URL 仍需在生产网络层补充 DNS pinning 和 egress allowlist；
- 当前没有无人值守 KMS、密钥轮换后台任务和硬件客户端密钥库；
- 当前推理入口是应用层加密 envelope，不是官方 OpenAI SDK 可直接提交的明文 wire format。

### 20.2 生产化前置条件

生产档位必须新增独立 `gpu-cc-prod` 实现，而不是把当前 `simulated` 开关改为 false。至少需要：

- 支持的 GPU CC 硬件和 CPU TEE；
- 厂商 CPU/GPU 联合证明和生产信任根；
- 独立 production policy、队列、namespace 和 KMS；
- 生产 KMS 硬编码拒绝实验室 SAK；
- 上传权重到隔离 runtime 的完整加载器和生命周期管理；
- 数据面 egress allowlist、DNS pinning、镜像 digest/SBOM 校验；
- 正式审批权限、密钥恢复/轮换和事故响应方案；
- 宿主 root、GPU 工具、驱动/固件篡改和降级攻击验收。

完成上述工作并通过安全评审前，所有接口、日志、页面和报告都必须保持 `A100_SIMULATED` 语义。
