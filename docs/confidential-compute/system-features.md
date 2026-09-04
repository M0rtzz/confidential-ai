# 机密模型托管与密态推理系统功能文档

## 1. 文档范围

本文说明本次 `feat/confidential-compute-mvp` 分支新增的功能，面向产品、实施、测试和使用人员。

本文仅覆盖以下新增能力：

- A100 模拟可信计算控制台；
- 浏览器会话密钥身份；
- 本地权重加密导入和 OpenAI 兼容 API 凭据加密导入；
- 模型注册、不可变版本、审核、发布、授权、上线和下线；
- 一次性 TEK 授权和模拟证明；
- OpenAI `chat/completions` 外层密文调用；
- 加密执行产物、本地解密及审计链。

平台已有的数据、项目、画布、普通沙箱和普通模型管理等功能不在本文范围内。

## 2. 当前运行档位

当前版本固定运行在 `A100_SIMULATED` 档位，对应协议字段如下：

| 字段                  | 当前值                        |
| --------------------- | ----------------------------- |
| `securityProfile`     | `a100-sim`                    |
| `runtimeMode`         | `SIMULATION`                  |
| `evidenceType`        | `SIMULATED_LAB_V1`            |
| `simulated`           | `true`                        |
| `attestationVerified` | `false`                       |
| `hardwareModel`       | `NVIDIA A100`                 |
| 允许的资产要求        | `controlled-sim-ok`、`public` |

`A100_SIMULATED` 表示客户端加密、HPKE 密钥封装、Ed25519 签名、一次性 TEK、任务绑定和审计流程均为真实实现，但证明证据是实验室模拟证据。A100 不具备 GPU Confidential Computing 硬件隔离，宿主机 root、驱动层或高权限调试人员理论上可以读取任务执行期间的进程内存、CPU 到 GPU 数据路径或 GPU 显存中的明文。

因此，本版本不得对外描述为生产硬件机密计算，也不得承接要求 `gpu-cc` 的资产。系统会拒绝把 `gpu-cc` 资产降级到 A100 模拟环境。

## 3. 功能入口

开发环境默认访问地址：

```text
http://222.20.99.38:39088/confidential-compute
```

页面新增五个功能标签：

| 标签     | 功能                                         |
| -------- | -------------------------------------------- |
| 机密模型 | 导入、审核、发布和测试两类模型               |
| 可信域   | 查看运行域状态、安全档位和校验结果           |
| 协议验证 | 发起一次完整的任务、证明、授权和加密执行验证 |
| 解密事件 | 查看协议演示过程中产生的受控事件             |
| 审计链   | 查看追加写入且前后哈希关联的审计记录         |

页面支持“后端 API”和“统一 Mock”两种数据源。正式联调及验收必须选择“后端 API”；Mock 仅用于界面演示，不代表真实密码协议或数据面已经执行。

## 4. 浏览器会话密钥身份

首次进入功能页面时，浏览器在当前页面会话中生成两套密钥：

- X25519 加密密钥，用于接收 DEK/ODK 的 HPKE 封装；
- Ed25519 签名密钥，用于身份持有证明、manifest 和授权签名。

只有公钥、`kid` 和签名证明提交给后端。用户私钥和原始 DEK 不上传到 Java 控制面、数据库、MinIO 或 CipherGPU 配置。

当前 MVP 的私钥及待授权 DEK 仅保存在页面 JavaScript 内存中，具有以下使用约束：

- 刷新或关闭页面后，待授权材料可能丢失；
- CipherGPU 重启后，一次性 TEK、已解封凭据和部署内存状态会丢失；
- 当前没有浏览器持久密钥库、TPM/硬件令牌或无人值守 KMS；
- 丢失某版本的 DEK 后不能由平台恢复，只能取消当前发布并导入不可变新版本。

## 5. 可信域

可信域页面展示域名称、可用状态和信任状态。只有同时满足以下条件的域才能用于密文上传、证明和执行：

```text
status = active
trustStatus = trusted
```

点击“校验可信域”后，控制面会通过 mTLS 调用 CipherGPU 健康接口，并检查返回值必须明确包含 `a100-sim`、`SIMULATED_LAB_V1`、`simulated=true` 和 `attestationVerified=false`。离线或阻断域不能获取会话公钥、创建上传会话或发起执行。

可信域校验的通过只表示当前模拟服务身份和协议字段符合预期，不表示 A100 获得了硬件机密隔离。

## 6. 机密模型中心

### 6.1 统一模型来源

系统使用同一套模型列表、版本、审核和发布流程管理两类来源：

| 来源            | 系统值              | 导入内容                                 | 运行方式                                          |
| --------------- | ------------------- | ---------------------------------------- | ------------------------------------------------- |
| 本地权重        | `LOCAL_WEIGHTS`     | `safetensors` 或模型目录压缩包等权重文件 | 发布后路由到预先启动的 OpenAI 兼容 vLLM runtime   |
| OpenAI 兼容 API | `OPENAI_COMPATIBLE` | HTTPS Base URL、上游 Model ID、API Key   | CipherGPU 在内存解密 API Key 后调用上游 HTTPS API |

同一个模型的来源类型不可变更。权重、API Key、Base URL、上游 Model ID 或运行参数变更时，应创建不可变新版本。

### 6.2 模型列表

模型列表展示：

- 模型名称和模型 ID；
- 来源类型；
- 最新版本号；
- 权重内容加密算法；
- `A100_SIMULATED` 安全档位；
- 当前模型状态；
- 当前状态允许的审核、部署、恢复和推理操作。

点击模型行可查看版本历史、manifest Hash、凭据掩码、审核记录、部署状态、授权会话和错误码。页面不会显示 API Key、DEK、明文权重或明文请求内容的服务端副本。

## 7. 本地权重加密导入

### 7.1 导入字段

选择“上传权重”时填写或选择：

- 模型名称；
- 模型描述；
- 可信域；
- 权重文件；
- 内容加密算法；
- vLLM 服务模型名。

### 7.2 支持的内容加密算法

权重文件支持五种算法，默认使用 AES-256-GCM：

| 算法               | 内容密钥长度 | nonce 长度 | 说明                                 |
| ------------------ | -----------: | ---------: | ------------------------------------ |
| AES-256-GCM        |     32 bytes |   12 bytes | 默认和推荐选项                       |
| AES-256-GCM-SIV    |     32 bytes |   12 bytes | 具备 nonce 误用抗性                  |
| ChaCha20-Poly1305  |     32 bytes |   12 bytes | ChaCha20 流加密与 Poly1305 认证      |
| XChaCha20-Poly1305 |     32 bytes |   24 bytes | 使用扩展 nonce                       |
| AES-256-SIV        |     64 bytes |   16 bytes | 由 32-byte DEK 派生 64-byte 内容密钥 |

五种算法只用于权重文件内容加密。API Key 文本和密态推理请求当前固定使用 AES-256-GCM。

### 7.3 浏览器处理流程

点击“加密并导入”后，浏览器执行：

1. 使用密码学安全随机数生成 32-byte DEK；
2. 通过 HKDF-SHA256 为所选算法派生内容密钥；
3. 按 8 MiB 对文件分块；
4. 为每块生成独立 nonce，并使用 AAD 绑定 envelope、算法版本、可信域、公钥、块序号和明文长度；
5. 计算每个密文块的 SHA-256；
6. 生成 `ds-envelope/v2` manifest；
7. 对规范化 manifest 计算 SHA-256 并使用 Ed25519 签名；
8. 逐块上传密文，最后提交模型版本。

Java 后端只接收和校验密文块、Hash、manifest、签名和元数据，不执行权重解密。分块被替换、缺失、乱序，或者 manifest/签名不匹配时，版本提交失败。

### 7.4 当前本地权重运行限制

本次 MVP 已完成“权重加密导入、密文存储、不可变版本、审核、一次性授权、CipherGPU 解密校验和审计”的闭环，但尚未实现根据每个上传权重自动创建独立 vLLM 进程。

本地权重模型上线后，实际请求路由到部署前由 `serve-hf-model.sh` 启动、并通过 `CIPHERGPU_VLLM_URL` 配置的固定 OpenAI 兼容 vLLM 服务。上传的权重文件不会在当前版本中被自动落到 tmpfs 并动态加载为新的 vLLM 实例。

## 8. OpenAI 兼容 API 模型导入

### 8.1 导入字段

选择“OpenAI 兼容 API”时填写：

- 模型名称；
- 模型描述；
- 可信域；
- HTTPS Base URL；
- 上游 Model ID；
- API Key；
- 超时时间，范围为 5 至 300 秒。

### 8.2 凭据保护

API Key 在浏览器中使用随机 DEK 和 AES-256-GCM 加密，后端收到的是 `ds-envelope/v1` 密文和密钥 envelope。页面只显示类似 `sk-****encrypted` 的掩码，不提供查看或下载原始 API Key 的功能。

模型发布授权时，浏览器把该凭据 DEK 使用 HPKE 封装给本次 CipherGPU 会话的 TEK。CipherGPU 只在内存中解密并使用 API Key，通过以下请求头调用上游服务：

```http
Authorization: Bearer <api-key>
```

API Key 更新会创建新凭据版本；旧版本不会被原地覆盖。

### 8.3 Base URL 安全限制

为降低 SSRF 风险，Base URL 必须满足：

- 使用 HTTPS；
- 包含合法主机名；
- 不包含 URL userinfo；
- 不包含 fragment；
- DNS 解析得到的所有地址都是公网地址；
- 禁止本机、回环、链路本地、站点内网、组播、云元数据及其他保留地址；
- 调用上游时不跟随 HTTP 重定向。

因此，`http://127.0.0.1`、`http://host.docker.internal` 和局域网 HTTP 地址不能作为 OpenAI 兼容 API 的 Base URL。开发机上的本地 vLLM 应作为 `LOCAL_WEIGHTS` runtime 通过部署配置接入，或者使用符合上述限制的 HTTPS 公网入口进行 API 来源测试。

### 8.4 远程模型明文边界

远程模型场景中，浏览器到平台控制面的请求为密文，Java 控制面看不到提示词；CipherGPU 必须解密请求后才能调用上游模型，因此上游模型供应商会看到请求和响应明文。页面会在导入和推理测试时显示该提示。

## 9. 模型版本、审核和状态

### 9.1 状态流转

```text
IMPORTED
   -> PENDING_REVIEW
       -> APPROVED
           -> PUBLISHING
               -> ONLINE
               -> RUNTIME_REQUIRED
       -> REJECTED

ONLINE -> OFFLINE
PUBLISHING -> APPROVED  （取消等待授权的发布）
```

| 状态               | 页面含义                                      | 可执行操作                                       |
| ------------------ | --------------------------------------------- | ------------------------------------------------ |
| `IMPORTED`         | 密文版本已导入                                | 提交审核                                         |
| `PENDING_REVIEW`   | 等待审核                                      | 批准、驳回                                       |
| `APPROVED`         | 当前版本允许部署                              | 部署；丢失 DEK 时导入新版本                      |
| `PUBLISHING`       | 部署记录已创建，等待浏览器完成一次性 TEK 授权 | 继续授权、取消发布、取消并重新导入               |
| `ONLINE`           | 授权有效且 runtime 可用                       | 推理测试、下线                                   |
| `RUNTIME_REQUIRED` | 授权完成，但本地 vLLM endpoint 未配置         | 配置 runtime 后下线，再通过部署 API 重新发布授权 |
| `REJECTED`         | 审核未通过                                    | 查看审核结果或导入新版本                         |
| `OFFLINE`          | 部署已下线，临时凭据已清除                    | 通过部署 API 对仍为 `APPROVED` 的版本重新部署    |

当前 MVP 的审核接口复用当前登录主体，不实现独立的组织审批角色隔离。生产使用前仍需接入正式的审核权限和职责分离策略。

## 10. 发布与一次性授权

批准版本点击“部署”后，系统不会立即把 DEK 或 API Key 发给后端，而是进入如下流程：

1. Java 创建或复用 `AUTHORIZATION_REQUIRED` 部署；
2. 浏览器创建绑定版本、输出接收人和安全档位的不可变 TaskSpec；
3. CipherGPU 生成一次性 X25519 TEK，并返回模拟证明；
4. 浏览器校验证据中的 nonce、任务摘要、TEK、公钥 Hash、镜像/策略摘要、会话和有效期；
5. 用户使用 Ed25519 会话身份签署仅可使用一次的 grant；
6. 浏览器将该模型版本的 DEK 使用 HPKE 封装给 TEK；
7. CipherGPU 校验 grant 后解封 DEK、验证密文输入并建立部署内存状态；
8. 本地 runtime 已配置时进入 `ONLINE`，未配置时进入 `RUNTIME_REQUIRED`。

TaskSpec 最长有效 5 分钟。TEK、grant `jti` 和证明会话均不可跨任务复用，grant 的 `maxUses` 固定为 1。

## 11. 发布恢复和下线

### 11.1 等待授权恢复

模型停留在 `PUBLISHING` 时：

- 当前页面内存仍持有该版本 DEK，可点击“继续授权”；
- 页面已丢失 DEK，可点击“取消并重新导入凭据”或“取消并重新导入权重”；
- 不希望继续发布，可点击“取消发布”，模型恢复为 `APPROVED`。

Java 再次部署同一批准版本时会复用已存在的 `AUTHORIZATION_REQUIRED` 部署，避免重复创建等待授权记录。

### 11.2 CipherGPU 重启

CipherGPU 有意只在内存保存一次性会话、已解密 API Key 和临时部署状态。进程重启后这些内容消失，现有部署需要重新注册并授权，不会从数据库恢复明文凭据。当前控制台尚未给 `OFFLINE` 和 `RUNTIME_REQUIRED` 模型提供一键重新部署按钮；可以调用部署 API 重新发布仍为 `APPROVED` 的版本，或者导入并审核新版本。

### 11.3 下线

下线会清除 CipherGPU 内存中的部署 secret 和会话关联。若 CipherGPU 已重启且临时部署不存在，下线按“目标已经处于安全下线状态”幂等成功处理。

## 12. 密态推理测试

只有 `ONLINE` 部署显示“推理测试”。点击后输入消息并选择“加密发送”，浏览器执行：

1. 生成新的随机 32-byte request key；
2. 将标准 OpenAI `chat/completions` JSON 整体使用 AES-256-GCM 加密；
3. 将 request key 使用 HPKE 封装给当前授权会话的 TEK；
4. 使用 AAD 绑定 deployment ID、session ID 和密文 Hash；
5. 调用统一密态推理接口；
6. CipherGPU 解密请求，并把 `model` 强制替换为该部署注册的上游模型 ID；
7. CipherGPU 路由到本地 vLLM 或远程 OpenAI 兼容 API；
8. 响应使用同一个 request key 加密返回；
9. 浏览器校验 deployment、session 和 Hash 后本地解密展示。

统一外部接口为：

```text
POST /api/v1alpha1/confidential-inference/chat/completions
```

接口请求仍需要平台 `User-Token`。外层请求不是明文 OpenAI JSON，而是 `deploymentId`、`sessionId` 和 `encryptedRequest`。每次发送都会生成新的 request key，不复用上一轮密钥。

当前测试对话框按单轮请求工作。多轮上下文需要调用方在浏览器或 SDK 中重新组合 `messages` 后，再作为新的密文请求发送。

## 13. 协议验证与加密输出

“协议验证”标签可运行 `ds-confidential/v1` 的完整链路：

```text
浏览器注册会话公钥
  -> 创建不可变 TaskSpec
  -> 请求模拟证据和一次性 TEK
  -> 校验模拟证据
  -> 签署一次性 grant
  -> HPKE 封装输入 DEK
  -> CipherGPU 解密并执行
  -> 使用新 ODK 加密输出
  -> 将 ODK 封装给输出接收人
  -> 浏览器本地解密和下载 JSON
```

输出明文不由 Java 下载接口直接返回。CipherGPU 使用新的 ODK 加密产物，并为每个输出接收人创建独立 HPKE envelope；接收人浏览器使用自己的 X25519 私钥解开 ODK 后，再在本地验证和解密。

## 14. 解密事件与审计链

### 14.1 解密事件

页面展示协议运行产生的状态事件，用于确认可信域、密钥封装、执行结果和错误分支。事件不得记录私钥、原始 DEK、API Key、明文权重、提示词或完整模型响应。

### 14.2 审计链

后端对以下新增操作写入审计事件：

- 会话身份注册；
- 可信域校验；
- 密文上传开始和模型版本提交；
- 模型审核和发布；
- 模拟证明签发；
- grant 保存和消费；
- A100 模拟执行完成；
- 模型上线、推理和下线。

每条事件包含上一事件 Hash 和本事件规范化内容 Hash，可检查顺序篡改或中间事件缺失。所有 A100 相关事件显式记录 `securityProfile=a100-sim` 和 `simulated=true`。

## 15. 常见异常与处理

| 现象或错误                   | 含义                                              | 处理方式                                                              |
| ---------------------------- | ------------------------------------------------- | --------------------------------------------------------------------- |
| 可信域为 Blocked/Offline     | 域不可用于密文操作                                | 选择 active/trusted 域并重新校验                                      |
| `PUBLISHING` 长时间不变      | 部署正在等待浏览器一次性授权                      | 有 DEK 时继续授权；否则取消并导入新版本                               |
| 浏览器已丢失凭据 DEK         | 页面刷新、关闭或内存材料被清除                    | 取消发布，输入新 API Key 或重新上传权重形成新版本                     |
| `RUNTIME_REQUIRED`           | 本地权重已授权，但没有配置 vLLM endpoint          | 启动 vLLM，配置 `DATA_SANDBOX_DEV_VLLM_URL`，重启开发栈并重新授权     |
| 模型部署未上线或需要重新授权 | CipherGPU 重启、会话过期或部署未完成              | 重新部署并完成一次性授权                                              |
| `KEY_SERVICE_UNAVAILABLE`    | CipherGPU/mTLS/模拟证明根不可用，或数据面连接失败 | 检查 CipherGPU、sim-attestation、证书和后端配置                       |
| `DATA_INTEGRITY_FAILED`      | 密文块、manifest、请求或响应 Hash 不一致          | 不重试解密，重新上传或重新发送新密文                                  |
| `POLICY_DENIED`              | 安全档位、可信域、证据根或资产要求不允许          | 修正配置，禁止绕过或自动降级                                          |
| OpenAI Base URL 被拒绝       | 地址不是 HTTPS 或解析为非公网地址                 | 使用合法公网 HTTPS 地址                                               |
| 上游 HTTP 错误               | 上游鉴权、模型 ID、限流或服务状态异常             | 检查 Base URL、Model ID、API Key 和上游日志，不在平台日志输出 API Key |

## 16. 当前 MVP 不包含的能力

本次新增功能不包含：

- H100 或更新 GPU 的真实 GPU CC 联合远程证明；
- 宿主 root 不可见运行时明文的硬件保证；
- 上传权重自动创建、隔离和销毁独立 vLLM 进程；
- 任意训练脚本或机密训练调度；
- 无人值守 KMS/HSM 密钥释放；
- TPM、Secure Enclave 或硬件令牌中的客户端私钥持久化；
- 多方资产所有者联合审批；
- 独立审核员角色和正式审批权限隔离；
- 面向生产的配额、计费、自动扩缩容和 SLA。

上述能力未完成前，页面、验收记录和对外材料都必须保留 `A100_SIMULATED` 标识。

## 17. 功能验收清单

1. 页面固定显示 `A100_SIMULATED`，且说明不具备 GPU CC 硬件隔离。
2. 五种权重加密算法均可完成分块上传和版本提交，篡改任一块必须失败。
3. Java 请求、数据库、MinIO、容器环境变量和日志中不出现用户私钥、原始 DEK、API Key 或明文权重。
4. `gpu-cc` 资产、错误可信域、错误证据根和 profile 降级必须被拒绝。
5. 同一 grant `jti` 第二次使用必须失败。
6. 修改 TaskSpec、nonce、TEK、输入版本、输出接收人或密文 Hash 后必须失败。
7. OpenAI 兼容 Base URL 的本机、内网、元数据和重定向访问必须被拒绝。
8. 模型能经过导入、审核、等待授权、上线、推理和下线完整流转。
9. 页面丢失 DEK 后能取消发布并创建不可变新版本，不存在服务端恢复明文的入口。
10. CipherGPU 重启后旧临时授权不可继续使用，下线不存在的临时部署幂等成功。
11. 推理请求和响应在 Java 控制面只以密文形式经过，浏览器能够校验并本地解密。
12. 审计事件按前一事件 Hash 串联，并明确记录模拟安全档位。
