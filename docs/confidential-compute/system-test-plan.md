# Confidential Compute MVP 系统测试计划（Codex 可执行协议）

## 1. 目的、范围与判定原则

本文不是功能或技术设计的替代品，而是后续 Codex 可以逐单元执行、诊断、修复、复测和记录的系统测试协议。测试基线由以下三者共同组成：

1. `docs/confidential-compute/system-features.md`：业务功能预期；
2. `docs/confidential-compute/backend-technical-design.md`：架构、协议与安全预期；
3. 当前三个 worktree 和 CipherGPU checkout 的实际代码。

发现文档、前端、Java、数据库、部署脚本或 CipherGPU 行为不一致时，不擅自选定某一方为正确；该 TEST 记为 `FAIL`，问题分类为 `DESIGN_MISMATCH`，保存双方证据。当前范围是新增 Confidential Compute MVP，不扩展到平台已有普通数据、项目、画布和普通沙箱功能。

结果只允许 `PASS`、`FAIL`、`BLOCKED`、`SKIPPED`。`BLOCKED` 仅用于外部依赖、权限或环境不可得；已观察到错误行为不得写成 `BLOCKED`。测试资源统一以前缀 `codex-cc-<UTC时间>-` 命名。

## 2. 固定安全边界

- 唯一允许操作的实例：`confidential-mvp`；容器前缀只能是 `data-sandbox-dev-confidential-mvp-`。
- 后端、前端和部署 checkout 分别为当前工作目录下的 `confidential-ai`、`confidential-ai-frontend`、`data-sandbox-package`。部署脚本固定从 `/data/collab/Projects/gpu-confidential-mvp/data-sandbox-package` 执行；先核对该目录属于预期实例配置。
- 禁止 `git push`、Publish Branch、PR、`git reset --hard`、`git clean -fd`、删除他人 worktree/分支、停止非本实例容器、删除真实业务/用户数据。
- 不把 API Key、token、密码、私钥、DEK、明文权重或 prompt 写入本文、testlog、命令历史、截图或 Git。变量值只放当前 shell/浏览器内存，日志引用必须脱敏。
- 破坏性/故障注入只使用本计划创建的测试数据；停止/重启容器前必须用名称和 Docker labels 双重确认实例归属。
- 只需要进程重启时执行：

```bash
cd /data/collab/Projects/gpu-confidential-mvp/data-sandbox-package
export DATA_SANDBOX_DEV_VLLM_URL=http://host.docker.internal:39089/v1
./develop.sh restart --name confidential-mvp --port 39088
```

- 代码、镜像或依赖改变才执行重建：

```bash
cd /data/collab/Projects/gpu-confidential-mvp/data-sandbox-package
export DATA_SANDBOX_DEV_VLLM_URL=http://host.docker.internal:39089/v1
./develop.sh up --name confidential-mvp --port 39088
```

## 3. 统一执行环境与证据

每个 UNIT 开始前执行并记录（不得输出 token 值）：

```bash
export CC_INSTANCE=confidential-mvp
export CC_BASE=http://127.0.0.1:39088
export CC_API="$CC_BASE/api/v1alpha1"
export CC_DEPLOY_ROOT=/data/collab/Projects/gpu-confidential-mvp/data-sandbox-package
export CC_PREFIX=data-sandbox-dev-confidential-mvp
git -C confidential-ai status --short --branch
git -C confidential-ai rev-parse HEAD
git -C confidential-ai-frontend status --short --branch
git -C data-sandbox-package status --short --branch
```

认证 API 测试从已登录 `confidential-mvp` 页面取得临时 `User-Token`，只设置为当前 shell 的 `CC_USER_TOKEN`；不得 `echo`、保存到文件或写入 testlog。通用调用：

```bash
curl -sS --fail-with-body -H "User-Token: $CC_USER_TOKEN" \
  -H 'Content-Type: application/json' "$CC_API/<path>"
```

对统一 `SecretPadResponse` 同时验证 HTTP 状态、`status.code/status.msg` 和 `data`，不能只看 HTTP 200。JSON 建议用 `jq -e` 断言；密文二进制和临时请求 JSON 放 `mktemp -d` 创建的目录，UNIT 完成后仅删除该目录。日志使用非跟随模式，避免阻塞：

```bash
docker logs --since 10m "${CC_PREFIX}-secretpad" 2>&1
docker logs --since 10m "${CC_PREFIX}-ciphergpu" 2>&1
docker logs --since 10m "${CC_PREFIX}-sim-attestation" 2>&1
docker logs --since 10m "${CC_PREFIX}-minio" 2>&1
```

数据库只读核验必须先通过 `docker inspect` 找到 `${CC_PREFIX}-secretpad` 的实际 DB 配置，再在该实例容器/数据库中执行 `SELECT`；禁止猜测数据库文件、凭据或连接其他实例。对象存储同理只检查该实例 MinIO。每项保留：命令、脱敏请求、完整响应、相关时间窗日志、前后状态和 ID。

### 自动化分级

- `AUTO`：命令/API/数据库断言可由 Codex独立完成。
- `BROWSER`：需浏览器 WebCrypto 私钥、页面交互或视觉检查，可由浏览器自动化执行；没有浏览器工具时由人工辅助，结果不得臆测。
- `EXTERNAL`：需要 SSH、GPU/vLLM 或公网 OpenAI 兼容服务；不可用时记 `BLOCKED`。

## 4. 真实实现索引

- Java：`ConfidentialComputeController`（`/crypto` 10 个入口）、`ConfidentialModelController`（模型 10 个入口）、`ConfidentialInferenceController`（密文推理），以及 `service/crypto/`。
- 前端：`apps/platform/src/modules/confidential-compute/`、`apps/platform/src/security/crypto/`、`services/confidential-{compute,models}.ts`。
- 数据：Flyway V45/V46；核心表为 `ds_crypto_*`、`ds_tee_attestation_session`、`ds_confidential_execution`、`ds_confidential_model*`、`ds_model_*`、`ds_confidential_upload_*`。
- MinIO：`cipher/{ownerId}/models/{uploadSessionId}/{index}` 与 `cipher-manifests/{ownerId}/{assetVersionId}.json`。
- 数据面：`${CC_PREFIX}-ciphergpu:9000`、`${CC_PREFIX}-sim-attestation:9100`；本地模型是 `host.docker.internal:39089/v1`。
- 固定合同：`ds-confidential/v1`、`a100-sim`、`SIMULATION`、`SIMULATED_LAB_V1`、`simulated=true`、`attestationVerified=false`、`NVIDIA A100`。

## 5. 执行顺序与依赖

严格顺序：`001→002→003→004→005→006→007→008→009→010→011→012→013→014→015→016→017→018→019→020→021→022`。P0 阻塞后续依赖时停止并记录；P1/P2 不得掩盖 P0。UNIT-007 产生浏览器身份，UNIT-009/010 产生两类模型版本，UNIT-011 审核，UNIT-012/013 授权上线，UNIT-014/015 推理，UNIT-016 协议执行。最后执行恢复、并发、安全、E2E 和一致性回归。

## UNIT-001：工作区、实例隔离与部署命令

### 测试目标
确认三仓库版本、部署入口和所有操作严格限定到 `confidential-mvp`。

### 对应系统功能
功能文档第 3、17 节的开发入口与验收前提。

### 对应技术实现
`develop.sh` 的 `status/up/restart/logs/manifest`，五个容器及私有 `.dev-runtime/confidential-mvp`。

### 前置条件
Docker 可读；三个 checkout 存在。

### 测试准备
执行统一 Git 检查；记录三仓库 branch/HEAD/upstream/diff，不改环境。

### 正常测试
`TEST-001-01 [P0][AUTO]`：运行 `./develop.sh status --name confidential-mvp --port 39088`，预期只列出 `${CC_PREFIX}-{kuscia,minio,sim-attestation,ciphergpu,secretpad}`、控制台端口 39088、其他端口 39080/39082/39083/39081/39084 和 `a100-sim`；名称或端口越界即 FAIL。

### 边界测试
`TEST-001-02 [P1][AUTO]`：运行 `./develop.sh manifest --name confidential-mvp`（若命令会写文件，仅读取已有 manifest），核对 workspace、实例、镜像和端口；任何指向其他开发者目录记 FAIL。

### 异常测试
`TEST-001-03 [P0][AUTO]`：静态检查脚本的实例名正则、managed/owner/workspace label 校验和端口占用保护；构造非法名称只运行参数校验，不启动容器，预期非零退出。

### 技术风险测试
检查 `help/status` 是否意外生成凭据或修改实例；若发生记录 bug 并只清理由本次创建的文件。

### 设计一致性验证
文档固定命令与 `develop.sh` 实际选项、默认端口逐项对比，差异记 `DESIGN_MISMATCH`。

### 需要检查的日志
本 UNIT 不产生服务日志；保存 status/manifest 输出且脱敏。

### 清理方式
删除本 UNIT 自己创建的临时目录；不执行 `down`。

### 回归测试范围
脚本修改后重跑 UNIT-001、002、018。

### UNIT 通过标准
三项全 PASS，且没有触碰其他实例。

## UNIT-002：部署、重启与 Docker 健康

### 测试目标
验证现有栈可识别、按需部署/重启且容器健康。

### 对应系统功能
可信域、模型和协议页面可用的运行基础。

### 对应技术实现
五容器、Docker network/labels、`develop.sh up/restart` 和健康等待。

### 前置条件
UNIT-001 PASS；变更前先判断是否需要重建。

### 测试准备
`docker inspect` 五个精确容器名，断言 managed label、owner、workspace；禁止通配 stop/rm。

### 正常测试
`TEST-002-01 [P0][AUTO]`：现有栈运行时执行 status 和 inspect，预期五容器 `running`，CipherGPU/attestation 为 UID 10001、cap-drop/no-new-privileges、secret mount 只读。

### 边界测试
`TEST-002-02 [P1][EXTERNAL]`：仅在需要重启时按固定命令 restart；记录前后 container ID/startedAt，等待 UI 与 API 恢复，预期不影响任何非前缀容器。

### 异常测试
`TEST-002-03 [P1][AUTO]`：静态/隔离参数验证端口冲突、缺容器时 restart 必须 fail closed，不准自动接管无正确 label 的同名资源。

### 技术风险测试
检查 restart 是否重建 CipherGPU/attestation并保留 `DATA_SANDBOX_DEV_VLLM_URL`，避免静默丢失 runtime 配置。

### 设计一致性验证
容器集合、端口和加固项与技术文档第 16 节一致；否则 `DESIGN_MISMATCH`。

### 需要检查的日志
五容器启动窗口；无 crash loop、stack trace、certificate/port 错误。

### 清理方式
无；禁止 down。

### 回归测试范围
部署改动后重跑 UNIT-002～006、018。

### UNIT 通过标准
所有被执行项 PASS，外部重启不可用时 002-02 可 BLOCKED 但 P0 必须 PASS。

## UNIT-003：Web、认证与前端入口

### 测试目标
验证 UI 可访问、认证生效、五标签和 API/Mock 切换真实存在。

### 对应系统功能
功能文档第 3、4 节。

### 对应技术实现
前端 `index.tsx`、路由、`User-Token` 请求头和 Java 登录拦截器。

### 前置条件
UNIT-002 PASS；有独立测试管理员账号。

### 测试准备
访问 `$CC_BASE/confidential-compute`，登录后 token 只存内存。

### 正常测试
`TEST-003-01 [P0][BROWSER]`：页面应显示“机密模型/可信域/协议验证/解密事件/审计链”、`A100_SIMULATED` 警告和后端 API 数据源。

### 边界测试
`TEST-003-02 [P1][BROWSER]`：API 与统一 Mock 往返切换；验收测试保持 API，Mock 数据不得混入 API 结果或被记为协议 PASS。

### 异常测试
`TEST-003-03 [P0][AUTO]`：不带、空、伪造 `User-Token` 调用 `/confidential-models` 与 `/crypto/audit-events`，预期认证失败且不返回数据；有效 token 成功。

### 技术风险测试
刷新页面验证私钥/DEK 内存态丢失提示，不检查或导出 localStorage 中的 token 值。

### 设计一致性验证
五标签、警告和正式验收数据源与功能文档一致。

### 需要检查的日志
SecretPad 认证拒绝日志不得包含 token。

### 清理方式
退出测试账号；不删除真实用户。

### 回归测试范围
前端/认证改动重跑 UNIT-003、007、019、022。

### UNIT 通过标准
三项 PASS。

## UNIT-004：基础 API、能力与错误合同

### 测试目标
验证 API 可达、能力声明准确、错误可判定。

### 对应系统功能
五种内容算法、统一模型中心和明确错误信息。

### 对应技术实现
`GET /confidential-models/capabilities`、`SecretPadResponse`、异常映射。

### 前置条件
有效 token。

### 测试准备
创建临时响应目录并记录 HTTP header/body。

### 正常测试
`TEST-004-01 [P0][AUTO]`：GET capabilities，断言 format=`ds-envelope/v2`、chunkSize=8388608、默认 AES-256-GCM，五算法 key/nonce/tag/HKDF 参数精确匹配。

### 边界测试
`TEST-004-02 [P1][AUTO]`：GET 模型列表、域列表、审计列表在无数据时也返回正确数组而非 null/解析错误。

### 异常测试
`TEST-004-03 [P1][AUTO]`：错误方法、非法 JSON、未知字段和错误 Content-Type；预期 4xx 或业务错误而非 500/stack trace。记录 Java record 未使用 Bean Validation 的实际行为。

### 技术风险测试
确认 HTTP 状态与业务 `status.code` 不互相掩盖；客户端 `responseData` 能显示错误。

### 设计一致性验证
能力 API 与前端类型、Java常量、CipherGPU capabilities 四方比较，差异记 mismatch。

### 需要检查的日志
SecretPad；不得出现完整请求 secret 或未处理异常。

### 清理方式
删除临时响应。

### 回归测试范围
UNIT-003～006、009、015。

### UNIT 通过标准
三项 PASS。

## UNIT-005：可信域与模拟身份

### 测试目标
验证域查询、可用性门禁及 mTLS 模拟身份校验。

### 对应系统功能
功能文档第 2、5 节。

### 对应技术实现
`GET/POST /crypto/trusted-domains*`、静态 domains、`CipherGpuClient.health()`。

### 前置条件
UNIT-002、004 PASS。

### 测试准备
记录 `a100-domain-a/b/c` 当前返回。

### 正常测试
`TEST-005-01 [P0][AUTO]`：列表/详情/verify active+trusted 域；runtime 必须包含所有固定模拟字段和警告，产生 `A100_SIMULATION_DOMAIN_VERIFIED` 审计。

### 边界测试
`TEST-005-02 [P1][AUTO]`：不存在、空、URL 编码异常 domainId，预期 `CONTRACT_INVALID`，无审计成功事件。

### 异常测试
`TEST-005-03 [P0][AUTO]`：verify `a100-domain-c`，并用它创建上传/TaskSpec，均应 `POLICY_DENIED`；不得调用/绕过数据面。

### 技术风险测试
mTLS/错误 SAK/TLS hash 故障注入留在 UNIT-018；本 UNIT 检查健康响应不得缺少 `attestationVerified=false`。

### 设计一致性验证
页面信任状态与后端实际门禁一致；静态域限制作为已知实现边界记录。

### 需要检查的日志
SecretPad、CipherGPU；无 TLS 私钥或证书 secret。

### 清理方式
无业务资源。

### 回归测试范围
UNIT-005、008～018。

### UNIT 通过标准
三项 PASS。

## UNIT-006：数据库迁移、隔离与密文存储

### 测试目标
验证 V45/V46 schema、owner 隔离、敏感信息不落库/MinIO。

### 对应系统功能
不可变版本、密文存储、审计链和无服务端明文恢复。

### 对应技术实现
center/edge/p2p 三套迁移、18 类核心表、MinIO 两个前缀。

### 前置条件
只读数据库访问限于实例；准备两个独立测试 owner（可用时）。

### 测试准备
检查 Flyway history 和表/索引/唯一约束；所有 SELECT 限定测试 ID/owner。

### 正常测试
`TEST-006-01 [P0][AUTO]`：确认 V45/V46 已应用、表列和 grant jti/ID约束存在，时间可解析为 ISO-8601。

### 边界测试
`TEST-006-02 [P1][AUTO]`：用户 A 创建资源，用户 B 按 ID 查询/操作应不可见或拒绝；数据库行 owner 正确。

### 异常测试
`TEST-006-03 [P0][AUTO]`：对测试行、对象 metadata、容器 env 和日志扫描唯一 canary（禁止真实 secret），确认不出现私钥/raw DEK/API Key/明文 prompt/权重；只应出现密文、hash、masked credential。

### 技术风险测试
检查三套 schema 迁移文件语义一致，索引是否支持条件查询和原子 grant 消费。

### 设计一致性验证
技术文档表清单/“明确不保存”字段与真实 DDL、写入代码比较。

### 需要检查的日志
SecretPad、MinIO；查询输出必须脱敏。

### 清理方式
只清理由测试 API 创建的数据；不得直接 DELETE 绕过业务状态机。

### 回归测试范围
所有数据相关 UNIT，尤其 008～017、020。

### UNIT 通过标准
三项 PASS；无法获得第二测试 owner 时 006-02 BLOCKED，但不得宣称 owner 隔离 PASS。

## UNIT-007：浏览器会话身份

### 测试目标
验证 X25519/Ed25519 生成、持有证明、注册和会话生命周期。

### 对应系统功能
功能文档第 4 节。

### 对应技术实现
`sessionIdentity.ts`、`POST /crypto/identities`、`ds_crypto_identity`。

### 前置条件
支持 WebCrypto 的浏览器和有效 token。

### 测试准备
以页面生成 32-byte raw 公钥及规范化 proof，不导出私钥。

### 正常测试
`TEST-007-01 [P0][BROWSER]`：首次进入注册身份，返回 ACTIVE/X25519+Ed25519；DB 仅有公钥，审计新增注册事件。

### 边界测试
`TEST-007-02 [P1][BROWSER]`：同 kid 重复注册、刷新后新身份、并行标签页；结果应确定且不会错误绑定旧私钥，实际唯一约束行为记录。

### 异常测试
`TEST-007-03 [P0][AUTO]`：错误长度/非法 Base64URL/空 kid/篡改 proof/签名公钥不匹配，均拒绝且不写成功身份。

### 技术风险测试
检查规范化 JSON 和 Ed25519 验证；未知明文字段不可被静默持久化。

### 设计一致性验证
页面刷新确实丢失会话密钥，且 UI 不承诺恢复。

### 需要检查的日志
SecretPad；不得打印 proof 之外的私密材料，尤其私钥不存在于请求。

### 清理方式
关闭测试标签页；身份记录作为审计证据保留或按专用测试清理 API（若存在）处理。

### 回归测试范围
UNIT-007、012、016、017、022。

### UNIT 通过标准
三项 PASS。

## UNIT-008：本地权重上传会话与分块

### 测试目标
验证上传会话、分块大小/索引/hash、重复上传和 MinIO 对象。

### 对应系统功能
功能文档第 7.1～7.3 节。

### 对应技术实现
`POST weight-upload-sessions`、chunk endpoint、2h TTL、16MiB+64上限、上传表与 MinIO。

### 前置条件
UNIT-005～007 PASS；使用小型无敏感测试文件。

### 测试准备
浏览器或测试 helper 按 8MiB、随机 DEK/AAD 生成 `ds-envelope/v2` 分块。

### 正常测试
`TEST-008-01 [P0][BROWSER]`：创建会话并上传所有块；校验 response index/hash/status、DB received_chunks、MinIO owner隔离路径和密文不等于明文。

### 边界测试
`TEST-008-02 [P1][AUTO]`：同 index 同/不同密文重复上传，received_chunks 只计一次且对象/hash一致更新；0、最后索引、8MiB边界均正确。

### 异常测试
`TEST-008-03 [P0][AUTO]`：负/越界 index、空块、超过上限、错误/非法 hash、过期/他人 session、blocked domain、size/chunks非正，全部拒绝且计数不变。

### 技术风险测试
并发重复块留在 UNIT-020；验证失败上传不遗留可提交的对象状态。

### 设计一致性验证
浏览器实际块大小、五算法 nonce/AAD 与 capability/文档一致。

### 需要检查的日志
SecretPad、MinIO；无明文文件内容或 DEK。

### 清理方式
使用唯一 session；无清理 API时保留 ID 并标记 TTL 清理需求，不直接删 bucket。

### 回归测试范围
UNIT-006、008、009、017、020。

### UNIT 通过标准
三项 PASS。

## UNIT-009：权重 manifest、五算法与不可变版本

### 测试目标
验证五种加密导入、manifest 完整性、签名及不可变新版本。

### 对应系统功能
功能文档第 6、7、9 节及验收 2。

### 对应技术实现
`POST /weight-versions`、`contentEncryption.ts`、`ConfidentialCanonical`、资产/模型版本表。

### 前置条件
每种算法各有完整上传会话；有效身份私钥仅在浏览器内存。

### 测试准备
为每算法建立独立、可识别但非敏感的小文件和 signed manifest。

### 正常测试
`TEST-009-01 [P0][BROWSER]`：AES-GCM、GCM-SIV、ChaCha20、XChaCha20、AES-SIV 分别 commit；返回 IMPORTED、算法/manifestHash/assetVersion准确，列表/详情显示五版本。

### 边界测试
`TEST-009-02 [P1][BROWSER]`：同 modelId 创建新版本，确认来源不可变、旧版本/manifest/对象不改变、latestVersion单调增加，文件名不进入对象路径。

### 异常测试
`TEST-009-03 [P0][AUTO]`：缺块、乱序/重复 index、内联 ciphertext、块 hash/manifest hash/签名/公钥/domain/算法任一篡改，以及跨 owner session，均 fail closed，不创建版本。

### 技术风险测试
核对 manifest 声明与数据库对象元数据的逐项比较，认证失败不能重试为成功。

### 设计一致性验证
“五算法可完成导入”必须是实际全链路，不以单元加解密代替。

### 需要检查的日志
SecretPad/MinIO；搜索 `DATA_INTEGRITY_FAILED`，不得出现明文。

### 清理方式
测试模型后续通过业务下线；不可变版本不直接删除。

### 回归测试范围
UNIT-006、008、009、011～017。

### UNIT 通过标准
五算法全部成功且所有篡改全部拒绝。

## UNIT-010：OpenAI 兼容模型导入与 SSRF

### 测试目标
验证凭据密文、URL/timeout 安全校验与不可变凭据版本。

### 对应系统功能
功能文档第 8 节。

### 对应技术实现
`POST /openai-compatible-versions`、Java/CipherGPU双层 URL 校验、`ds_model_credential`。

### 前置条件
有效公网 HTTPS 测试 upstream（不写真实 key）；否则正常链路 EXTERNAL BLOCKED。

### 测试准备
浏览器用 AES-256-GCM `ds-envelope/v1` 加密测试 key，canary 与真实 secret 分离。

### 正常测试
`TEST-010-01 [P0][BROWSER][EXTERNAL]`：合法 HTTPS/baseUrl/modelId/timeout 5、60、300 导入，返回 IMPORTED 和 masked credential，DB仅密文。

### 边界测试
`TEST-010-02 [P1][AUTO]`：URL尾斜线规范化；同 modelId 更新 key/base/model形成新版本，旧 credential不覆盖；timeout 4/301、空 model、超长文本拒绝。

### 异常测试
`TEST-010-03 [P0][AUTO]`：HTTP、localhost、127/8、0/8、RFC1918、link-local、100.64/10、IPv6 ULA、metadata、userinfo、fragment、混合 DNS、重定向，以及 apiKey/plaintext/privateKey 夹带，全部拒绝或不跟随。

### 技术风险测试
记录 DNS rebinding 残余风险；验证 CipherGPU Pydantic `extra=forbid`。

### 设计一致性验证
页面显示远程供应商可见明文边界；不能用本地 HTTP vLLM 冒充 API 来源。

### 需要检查的日志
SecretPad/CipherGPU/upstream测试服务；Authorization 值必须脱敏。

### 清理方式
下线测试部署；测试 upstream 自行销毁。

### 回归测试范围
UNIT-006、010～015、017、021。

### UNIT 通过标准
所有可执行安全拒绝 PASS；无公网 upstream 时 010-01 BLOCKED，UNIT 不得标总 PASS。

## UNIT-011：模型列表、详情、审核与状态机

### 测试目标
验证模型可见信息、版本历史和全部合法/非法审核迁移。

### 对应系统功能
功能文档第 6、9 节。

### 对应技术实现
GET list/detail、review API、审批/历史与 model/version 聚合状态。

### 前置条件
有独立 LOCAL_WEIGHTS 与 OPENAI_COMPATIBLE IMPORTED 测试版本。

### 测试准备
记录 model/version/status/approval 数量。

### 正常测试
`TEST-011-01 [P0][AUTO]`：逐步 `SUBMIT→PENDING_REVIEW→APPROVE→APPROVED`；另一版本 `SUBMIT→REJECT→REJECTED→SUBMIT`，历史、comment、approval_id正确。

### 边界测试
`TEST-011-02 [P1][AUTO]`：重复查询、空列表、版本历史排序、masked credential和部署详情；不得显示 key/DEK/明文。

### 异常测试
`TEST-011-03 [P0][AUTO]`：未知 action、APPROVE from IMPORTED、重复 APPROVE、REJECT from APPROVED、跨 model/version/owner，均拒绝且状态/历史不变。

### 技术风险测试
并发审核见 UNIT-020；核对 model 与 latest version 状态原子一致。

### 设计一致性验证
当前 reviewer=owner 与文档“无职责分离”一致并作为限制，不误判已有独立角色。

### 需要检查的日志
SecretPad；记录错误码/消息，无敏感数据。

### 清理方式
不删除审批历史；使用测试前缀隔离。

### 回归测试范围
UNIT-011～015、020、022。

### UNIT 通过标准
三项 PASS。

## UNIT-012：部署创建、复用、取消和恢复入口

### 测试目标
验证 APPROVED 到 PUBLISHING、等待授权复用与取消发布。

### 对应系统功能
功能文档第 10、11.1 节。

### 对应技术实现
deploy/offline API、CipherGPU临时 deployment、前端继续授权/取消按钮。

### 前置条件
APPROVED测试版本和浏览器仍持有 DEK。

### 测试准备
记录版本、CipherGPU内部部署和Java部署表。

### 正常测试
`TEST-012-01 [P0][BROWSER]`：点击部署，预期 Java model=PUBLISHING、deployment=AUTHORIZATION_REQUIRED/等待授权，页面显示继续授权与取消。

### 边界测试
`TEST-012-02 [P1][AUTO]`：对同批准版本重复 deploy，预期复用同一等待授权 deployment ID，不新增记录；多次查询稳定。

### 异常测试
`TEST-012-03 [P0][AUTO]`：从 IMPORTED/PENDING/REJECTED/ONLINE/OFFLINE 或错误版本 deploy 均按真实状态机拒绝；对等待授权 deployment offline 后模型恢复 APPROVED且可重新 deploy。

### 技术风险测试
验证单 JVM `synchronized` 的局限在 UNIT-020；刷新丢 DEK 后只能取消并导入新版本，服务端无恢复入口。

### 设计一致性验证
特别执行 `OFFLINE/RUNTIME_REQUIRED` 重新部署声明与 `deploy` 代码“仅APPROVED”条件的对照；冲突记 `DESIGN_MISMATCH`。

### 需要检查的日志
SecretPad/CipherGPU；部署注册错误不得泄露输入。

### 清理方式
等待授权部署用 offline API 取消，确认 APPROVED。

### 回归测试范围
UNIT-011～014、018、020。

### UNIT 通过标准
三项 PASS且一致性无未解释差异。

## UNIT-013：证明、一次性授权与模型上线

### 测试目标
验证 TaskSpec→evidence→grant→HPKE DEK→authorize 全链路和一次性语义。

### 对应系统功能
功能文档第 10 节。

### 对应技术实现
tasks/attestation/grants/authorize API、SAK、TEK、grant原子消费和CipherGPU内存部署。

### 前置条件
PUBLISHING部署、有效身份、DEK、可用域。

### 测试准备
浏览器保存 TaskSpec/evidence/grant摘要和ID，不保存私钥/DEK。

### 正常测试
`TEST-013-01 [P0][BROWSER]`：创建5分钟 TaskSpec，验证 evidence所有绑定字段，签 maxUses=1 grant、HPKE sealed DEK并authorize；有vLLM时 ONLINE，无配置仅 LOCAL_WEIGHTS允许RUNTIME_REQUIRED。

### 边界测试
`TEST-013-02 [P1][AUTO]`：同等待部署授权重试、临近expiry、不同输出接收人；成功只消费一次，失败不产生伪ONLINE，状态/consumed_at一致。

### 异常测试
`TEST-013-03 [P0][BROWSER]`：逐一篡改 task digest、nonce、TEKpub/hash、TLS hash、workload/policy digest、session、expiry、version/input/output recipient/profile/maxUses/jti/signature；跨session/过期/撤销/第二次jti全部拒绝。

### 技术风险测试
并发jti见 UNIT-020；检查 failure 后可否安全取消/重新开始，密钥生命周期日志无泄露。

### 设计一致性验证
ONLINE/RUNTIME_REQUIRED页面操作和功能文档状态含义一致。

### 需要检查的日志
三服务；搜索 POLICY_DENIED/TASK_EXPIRED/AUTHORIZATION_REQUIRED，禁止记录 sealed前的 key。

### 清理方式
成功部署由 UNIT-017 下线；失败会话等待过期，不直接删数据库。

### 回归测试范围
UNIT-005、007、012～018、020。

### UNIT 通过标准
正常链路 PASS，所有绑定篡改均 fail closed。

## UNIT-014：本地权重 runtime 与正常密态推理

### 测试目标
验证固定 vLLM runtime绑定、连续密文请求/响应和浏览器解密。

### 对应系统功能
功能文档第 7.4、12 节。

### 对应技术实现
`CIPHERGPU_VLLM_URL`、servedModelName、密文 inference API、request key/AAD。

### 前置条件
39089 vLLM健康、LOCAL_WEIGHTS ONLINE部署；GPU/模型属于 EXTERNAL。

### 测试准备
`curl http://127.0.0.1:39089/v1/models`仅检查健康和served name；不写prompt日志。

### 正常测试
`TEST-014-01 [P0][BROWSER][EXTERNAL]`：页面单轮加密发送，Java只见envelope，CipherGPU强制model为servedModelName，浏览器验证hash/session并解密出有效OpenAI JSON。

### 边界测试
`TEST-014-02 [P1][BROWSER][EXTERNAL]`：连续至少3次请求、空/Unicode/接近允许长度消息及客户端组合多轮messages；每次nonce/request key/cipherHash不同，均无失效连接问题。

### 异常测试
`TEST-014-03 [P0][BROWSER]`：错误deployment/session/AAD/hash/sealed key/nonce/ciphertext、OFFLINE/RUNTIME_REQUIRED部署、明文messages直传，全部拒绝且无明文响应。

### 技术风险测试
确认 Java 不改写/解密请求，CipherGPU不复用request key，新HttpClient策略避免第二次失败。

### 设计一致性验证
上传权重不会自动启动独立vLLM；页面/结果不能暗示实际运行了上传文件。

### 需要检查的日志
SecretPad/CipherGPU/vLLM；用canary扫描 prompt 不得出现在前两者，vLLM属于明文边界需脱敏。

### 清理方式
结束测试对话，不停止共享vLLM；下线只操作测试deployment。

### 回归测试范围
UNIT-013～015、017～019、021、022。

### UNIT 通过标准
正常与连续请求 PASS，所有密文篡改拒绝。

## UNIT-015：远程模型推理、上游错误、超时与流式输入

### 测试目标
验证远程路由鉴权、错误映射、timeout、redirect和JSON/streaming边界。

### 对应系统功能
功能文档第 8、12、15 节。

### 对应技术实现
httpx `follow_redirects=false`、5～300秒timeout、Bearer注入、加密响应。

### 前置条件
可控公网HTTPS测试server和ONLINE远程部署；否则 EXTERNAL BLOCKED。

### 测试准备
测试server只记录“存在Authorization”与请求结构，不记录key/prompt。

### 正常测试
`TEST-015-01 [P0][BROWSER][EXTERNAL]`：正常密文chat完成，upstream收到配置model与Bearer，浏览器解密标准JSON，Java日志无prompt/key。

### 边界测试
`TEST-015-02 [P2][BROWSER][EXTERNAL]`：请求 `stream=false`、缺省stream及 `stream=true`；按当前接口能力验证，若文档/页面暗示stream但实现不支持，记 mismatch而非强行通过。

### 异常测试
`TEST-015-03 [P1][EXTERNAL]`：上游401/403/404/429/500、非法/空/超大JSON、断连、慢响应超时、TLS失败、30x；预期结构化失败、不跟随redirect、不泄露响应secret、状态仍一致且可重试新请求。

### 技术风险测试
确认错误不能全部模糊成无法诊断的HTTP 200；Java `POLICY_DENIED`映射中保留脱敏数据面原因码。

### 设计一致性验证
远程供应商看到明文的警告、timeout范围和非官方明文OpenAI wire格式均与UI一致。

### 需要检查的日志
SecretPad/CipherGPU/测试upstream；Authorization必须完全脱敏。

### 清理方式
下线部署、销毁测试server和测试key。

### 回归测试范围
UNIT-010、013、015、017、021、022。

### UNIT 通过标准
三项 PASS；无外部server则 UNIT BLOCKED。

## UNIT-016：协议验证、执行、取消与加密输出

### 测试目标
验证独立协议演示的完整一次性执行和本地输出解密。

### 对应系统功能
功能文档第 13 节。

### 对应技术实现
TaskSpec/attestation/grant/start/output API，CipherGPU executions/receipt/cancel，ODK envelopes。

### 前置条件
有效身份、可用域和独立测试asset version。

### 测试准备
页面输入固定非敏感canary，至少一个输出接收人。

### 正常测试
`TEST-016-01 [P0][BROWSER]`：运行协议验证，浏览器验签/解密并下载JSON；Java仅返回密文output，receipt绑定task/session/hash/time/模拟字段。

### 边界测试
`TEST-016-02 [P1][BROWSER]`：多个接收人各有独立ODK envelope；正确私钥可解，其他会话私钥不可解；outputs返回最近一次且owner受限。

### 异常测试
`TEST-016-03 [P0][AUTO]`：缺grant、重复start、执行中cancel/完成后cancel、不存在execution、篡改output hash/receipt/SAK/time；必须确定性拒绝或幂等，不能返回明文/错误所有者结果。

### 技术风险测试
检查 cancellation race、finally清零路径和执行失败后的数据库状态。

### 设计一致性验证
页面“协议验证”从前端操作到下载闭环，解密事件与审计均产生。

### 需要检查的日志
三服务；无输入/输出明文，receipt签名失败可诊断。

### 清理方式
取消尚在运行的测试执行；保留审计，不删除他人输出。

### 回归测试范围
UNIT-007、013、016、017、020、022。

### UNIT 通过标准
三项 PASS。

## UNIT-017：下线、重复操作与资源清理

### 测试目标
验证安全清除临时凭据、幂等下线与测试资源可追踪。

### 对应系统功能
功能文档第 11.3、15 节。

### 对应技术实现
deployment offline API、CipherGPU内存bytearray/会话清理、状态表。

### 前置条件
至少一个ONLINE、一个等待授权测试部署。

### 测试准备
记录deployment/model/version与CipherGPU内存可见状态（不取secret）。

### 正常测试
`TEST-017-01 [P0][AUTO]`：ONLINE下线后 Java/CipherGPU均OFFLINE、authorization_session_id清空、推理拒绝、审计追加。

### 边界测试
`TEST-017-02 [P1][AUTO]`：相同deployment重复下线；CipherGPU已无内存项时应 `alreadyAbsent=true` 幂等成功，Java状态稳定。

### 异常测试
`TEST-017-03 [P1][AUTO]`：不存在/他人deployment下线拒绝；等待授权取消恢复APPROVED；不得清理其他模型/version/object。

### 技术风险测试
检查进程内credentials引用/session关联移除；无法证明完全内存零化时按文档限制记录，不虚假PASS硬件清零。

### 设计一致性验证
OFFLINE后的“重新部署”UI/API能力按实际验证，差异记 mismatch。

### 需要检查的日志
SecretPad/CipherGPU；无credential值。

### 清理方式
只下线 `codex-cc-*` 部署；不可变版本/审计按保留策略处理。

### 回归测试范围
UNIT-012～017、018。

### UNIT 通过标准
三项 PASS。

## UNIT-018：容器/服务重启、网络故障与异常恢复

### 测试目标
验证mTLS/data plane/runtime异常、重启后的失忆语义和恢复。

### 对应系统功能
功能文档第 11.2、15 节。

### 对应技术实现
CipherGPU内存 `_sessions/_consumed_jti/_model_deployments`、restart脚本、mTLS。

### 前置条件
独立测试deployment；确认所有目标容器label属于实例。故障注入需明确授权。

### 测试准备
记录容器ID、测试部署/会话和基线健康；绝不操作非精确名称。

### 正常测试
`TEST-018-01 [P0][EXTERNAL]`：按固定restart命令重启整栈，健康恢复、数据库/密文对象保留、页面可登录，已有CipherGPU临时授权不可继续使用且需重新授权。

### 边界测试
`TEST-018-02 [P1][EXTERNAL]`：依次短停测试实例的sim-attestation、CipherGPU、vLLM网络；期望 KEY_SERVICE_UNAVAILABLE/MODEL_RUNTIME_UNAVAILABLE，恢复后新会话/新请求成功，不自动降级HTTP/profile。

### 异常测试
`TEST-018-03 [P0][EXTERNAL]`：错误CA/client identity/SAK/workload/policy/TLS hash使用隔离配置注入；证明/执行拒绝，恢复原配置并回归，不覆盖真实证书。

### 技术风险测试
检查restart重新注入VLLM URL；半完成PUBLISHING、消费中的grant与超时请求恢复一致性。

### 设计一致性验证
页面恢复提示、后端状态和内存失忆语义一致；不存在服务端秘密恢复。

### 需要检查的日志
五服务对应故障窗口；收集TLS/timeout原因但脱敏路径和密钥。

### 清理方式
恢复原容器/网络/只读证书配置，验证五容器healthy；不使用down。

### 回归测试范围
UNIT-002、005、012～018、021、022。

### UNIT 通过标准
故障均fail closed，恢复后规定回归全PASS；无授权则 BLOCKED。

## UNIT-019：前端错误呈现、会话丢失与接口一致性

### 测试目标
验证前端字段/按钮/错误信息和后端状态真实一致。

### 对应系统功能
模型详情、恢复、推理、解密事件和审计的用户可见功能。

### 对应技术实现
`model-panel.tsx`、API adapters/types、`responseData`。

### 前置条件
覆盖各状态的测试模型；浏览器工具。

### 测试准备
建立状态→允许按钮矩阵：IMPORTED提交；PENDING批准/驳回；APPROVED部署；PUBLISHING继续/取消；ONLINE推理/下线；RUNTIME_REQUIRED/OFFLINE按真实能力。

### 正常测试
`TEST-019-01 [P0][BROWSER]`：逐状态检查按钮，执行后列表/detail立即反映API/DB状态，loading防重复点击。

### 边界测试
`TEST-019-02 [P2][BROWSER]`：刷新/关闭导致DEK丢失后继续授权被阻止并提示取消重导；空列表、长名称、Unicode、慢API和多版本展示不崩溃。

### 异常测试
`TEST-019-03 [P1][BROWSER]`：注入400/401/403/409/500/timeout/非JSON响应，页面显示可行动且脱敏错误，不误报成功、不回退Mock。

### 技术风险测试
比较前端TS类型与真实JSON字段/大小写/可空性；发现字段漂移记 mismatch。

### 设计一致性验证
逐条验证用户看到的功能可完成，而不只验证按钮存在。

### 需要检查的日志
浏览器console/network及SecretPad；token/request plaintext截图需裁剪或脱敏。

### 清理方式
关闭测试标签页，清除测试会话；不删除用户。

### 回归测试范围
UNIT-003、007、011～019、022。

### UNIT 通过标准
三项 PASS。

## UNIT-020：并发、幂等、重试与数据一致性

### 测试目标
验证重复/并发请求不会产生双消费、重复计数或非法状态。

### 对应系统功能
不可变版本、一次授权、部署复用和可靠恢复。

### 对应技术实现
事务、条件UPDATE、jti唯一约束、单JVM synchronized、上传upsert。

### 前置条件
独立测试资源；并发脚本限制为10并发且不压测共享系统。

### 测试准备
记录前置行数/status/version/received_chunks；请求体放临时目录。

### 正常测试
`TEST-020-01 [P0][AUTO]`：同grant jti并发10次start/authorize，恰好一次成功，其余明确拒绝；consumed_at一次、execution/deployment无重复成功。

### 边界测试
`TEST-020-02 [P1][AUTO]`：同chunk index并发上传、同APPROVED版本并发deploy、相同offline重试；计数一次/等待部署一个/最终OFFLINE。

### 异常测试
`TEST-020-03 [P1][AUTO]`：并发APPROVE/REJECT、authorize/offline、timeout后客户端重试；最终状态必须属于合法状态机，model/version/deployment/approval/audit互相一致。

### 技术风险测试
若只有一个Java实例，只能证明单实例；多实例竞态明确记为未覆盖风险，不能以synchronized宣称生产安全。

### 设计一致性验证
技术文档列出的幂等规则逐条获得数据库与API证据。

### 需要检查的日志
SecretPad/CipherGPU；检查deadlock、unique violation stack trace、重复成功审计。

### 清理方式
下线本UNIT测试部署；删除临时请求文件。

### 回归测试范围
UNIT-008、011～013、016、017、020。

### UNIT 通过标准
三项 PASS且无非法中间/最终状态。

## UNIT-021：审计链、日志完整性与敏感信息扫描

### 测试目标
验证审计覆盖、hash链和所有日志/存储的保密边界。

### 对应系统功能
功能文档第 14、17 节验收3/12。

### 对应技术实现
`ds_crypto_audit_event`、`GET /crypto/audit-events`、previous/event hash规范化。

### 前置条件
前序业务UNIT至少完成一轮；使用唯一canary而非真实secret。

### 测试准备
记录事件总数/首尾hash，定义预期事件：身份、域、上传、导入、审核、发布、证明、grant保存/消费、执行、上线、推理、下线。

### 正常测试
`TEST-021-01 [P0][AUTO]`：API/DB事件顺序一致；逐条重新规范化计算eventHash并验证previousHash链接，A100事件均有profile/simulated。

### 边界测试
`TEST-021-02 [P2][AUTO]`：空链、分页/大量事件（若无分页则记录扩展风险）、并发事件稳定排序；owner只能看自己的链。

### 异常测试
`TEST-021-03 [P0][AUTO]`：用只读副本模拟改/删/插事件，校验器必须发现链断裂；扫描Java/DB/MinIO/env/日志，不得出现canary私钥、DEK、key、权重、prompt、完整响应。

### 技术风险测试
确认“追加写”是否由数据库权限/触发器强制，若只是应用约定则记录风险；错误日志也在扫描范围。

### 设计一致性验证
解密事件页面当前是否真实来自后端：若仍使用 `mockDecryptEvents`，与“展示协议产生事件”的文档差异记 `DESIGN_MISMATCH`。

### 需要检查的日志
所有五容器、浏览器console；只保存脱敏命中上下文。

### 清理方式
删除只读副本和canary临时文件；不改真实审计链。

### 回归测试范围
所有产生审计/日志的 UNIT，尤其 005、007～018、020～022。

### UNIT 通过标准
链完整、事件覆盖完整、零敏感命中。

## UNIT-022：完整 E2E、设计适配性与最终回归

### 测试目标
从用户入口验证两类模型和协议演示闭环，并完成设计—实现一致性总审计。

### 对应系统功能
system-features.md 全部实际功能点及12项验收清单。

### 对应技术实现
浏览器→Java→DB/MinIO→mTLS CipherGPU→sim-attestation→本地/远程模型→密文响应→浏览器展示全链路。

### 前置条件
前序所有P0 PASS；P1/P2失败已记录且不破坏E2E；API数据源。

### 测试准备
新建两套 `codex-cc-e2e-*` 数据，不复用可能污染的旧资源；截取脱敏前后状态。

### 正常测试
`TEST-022-01 [P0][BROWSER][EXTERNAL]`：LOCAL_WEIGHTS 从五算法之一导入→详情→提交→批准→部署→证明授权→ONLINE→连续推理→下线，结果/状态/审计闭环。

### 边界测试
`TEST-022-02 [P1][BROWSER][EXTERNAL]`：OPENAI_COMPATIBLE 导入→不可变新版本→审核→授权→推理→上游异常恢复→下线；凭据始终masked且供应商明文边界有提示。

### 异常测试
`TEST-022-03 [P0][BROWSER]`：协议验证完整执行/下载后，集中核对12项验收：模拟标识、五算法、无secret、gpu-cc拒绝、jti重放、绑定篡改、SSRF、模型全状态、DEK丢失、重启失忆/幂等下线、密文传输/本地解密、审计hash链。

### 技术风险测试
将所有文档功能映射到至少一个 TEST；任何缺口、不可操作UI、字段漂移或链路中断均不是“部分通过”。

### 设计一致性验证
形成“文档声明｜前端入口｜API｜业务/DB｜Sandbox/CipherGPU｜模型｜结果/UI｜结论”矩阵；差异逐条登记 `DESIGN_MISMATCH`。

### 需要检查的日志
全链路时间窗；无stack trace、未处理错误和敏感信息。

### 清理方式
仅下线E2E测试部署并销毁外部测试server/key；保留不可变版本和审计作为证据，除非存在经确认的专用清理API。

### 回归测试范围
任何代码修复均先重跑所属UNIT，再跑直接依赖；最终至少 UNIT-002、003、005、006、013～018、021、022。

### UNIT 通过标准
三个TEST PASS、全部P0 PASS、无未记录功能缺口或 DESIGN_MISMATCH。

## 6. 优先级与数量

本计划共 22 个 UNIT、66 个 TEST：P0 38 个、P1 25 个、P2 3 个。执行顺序为环境/基础服务（001～006）→身份与导入（007～010）→核心状态和执行（011～017）→恢复与健壮性（018～021）→完整E2E（022）。完全自动化测试以 `[AUTO]` 标识；浏览器密钥/视觉交互为 `[BROWSER]`；SSH/GPU/vLLM/公网服务依赖为 `[EXTERNAL]`。

## 7. 已识别、必须实测的设计一致性候选

这些是代码审阅发现的候选差异，不在方案阶段直接判定为最终缺陷；执行对应 TEST 后决定是否写 `DESIGN_MISMATCH`：

1. 技术文档一处建议 `up --api-grpc-port 39093`，用户给定固定部署命令未指定该参数，脚本默认39083；以实例manifest/实际端口验证。
2. 文档称后端可对仍为 APPROVED 的版本重新部署，同时描述 OFFLINE/RUNTIME_REQUIRED恢复；实际 `deploy` 明确仅接受版本status=APPROVED，而下线已授权部署把模型/版本聚合状态置为OFFLINE，需验证是否存在可达恢复路径。
3. “解密事件”应展示协议运行事件，但前端 `index.tsx` 当前直接使用 `mockDecryptEvents`；需验证后端API模式是否仍展示固定Mock。
4. 文档列出内部 execution cancel/receipt API，Java公共控制面仅暴露start/output；验证页面是否承诺用户可取消，以及取消是否仅为内部能力。
5. 审核设计明确当前owner同时充当reviewer；若UI或验收材料暗示职责分离，记 mismatch。
6. 本地上传权重仅被解密校验，实际推理共享预启动vLLM，不是按上传版本运行；UI必须准确披露。
7. API Controller request records无Bean Validation注解，主要依赖service手工校验；TEST-004/007～013验证未知字段、null和类型错误是否得到稳定业务错误而非500。

## 8. testlog.md 追加规则

日志固定为 `confidential-ai/docs/testlog.md`。每完成一个 UNIT（包括 FAIL/BLOCKED/SKIPPED）立即在文件末尾追加一次记录；严禁覆盖、改写或整理历史记录。复制文件中的模板，填写所有 Test ID。BUG编号取现有最大值+1；设计差异在问题描述首行写 `分类：DESIGN_MISMATCH`。证据过大时保存到不含secret的测试产物路径并记录hash，不把二进制或完整容器日志塞入Git。

## 9. 失败、修复与部署决策

1. FAIL后先冻结该测试资源，收集脱敏API response、时间窗日志、stack trace、相关代码、DB前后行和复现步骤。
2. 判断根因归属：TEST/ENV、前端、Java、迁移/存储、部署、CipherGPU、vLLM/upstream或 `DESIGN_MISMATCH`。
3. 属于当前项目代码才修改；CipherGPU不在三个当前worktree时，先确认其分支/权限，不得修改他人分支。
4. 仅配置/进程问题用restart；代码/镜像变化用up。两者均限定 `--name confidential-mvp`。
5. 先重跑失败TEST，再跑UNIT全部TEST，再跑该UNIT“回归测试范围”。有失败不得commit。
6. commit前执行三个相关仓库的 `git status`/`git diff`，扫描 API key、token、password、secret、private key、临时数据、测试日志敏感信息、大文件和无关文件。一次完整UNIT全部通过且回归通过后，允许相关仓库各一次本地commit；绝不push。

# Codex 自动测试执行协议

以后收到“按照 system-test-plan.md 继续测试”时，必须严格执行：

1. 完整阅读 `system-features.md`、`backend-technical-design.md`、本文件和 `../testlog.md`。
2. 解析 testlog 历史：同一 UNIT 最新一条最终结果为 PASS 才算完成；FAIL/BLOCKED/SKIPPED 均视为待处理。选编号最小的未完成 UNIT。
3. 检查三个仓库的 Git branch、HEAD、status、diff和现有用户修改；不得覆盖无关修改。
4. 执行 UNIT-001 的实例保护检查，明确唯一实例为 `confidential-mvp`；任何目标名称不匹配立即停止。
5. 检查环境和当前 UNIT 前置条件。外部能力缺失时穷尽安全只读检查后记 BLOCKED，不伪造PASS。
6. 只执行当前 UNIT，使用其指定输入、API、命令、DB/状态断言和日志检查；不要无故跑全套。
7. PASS、FAIL、BLOCKED或SKIPPED后立即按模板追加testlog，记录测试前HEAD。
8. FAIL时收集脱敏API response、logs、stack trace、相关代码和状态，登记 BUG 或 DESIGN_MISMATCH并定位根因。
9. 当前项目代码问题可以修改；保持最小变更，不修改其他人的实例、分支、worktree或业务数据。
10. 按“失败、修复与部署决策”选择restart或up，命令必须含 `--name confidential-mvp` 和指定VLLM URL。
11. 重新执行失败TEST、当前UNIT全部TEST及其回归范围；把修复后结果作为新的、追加的testlog记录，旧FAIL保留。
12. 有效代码修改仅在当前UNIT和回归全PASS、无敏感/临时/无关文件后允许本地commit。commit前必须 `git status`、`git diff` 和secret检查。
13. 最高权限是 LOCAL COMMIT ONLY：禁止push/force push、Publish Branch、PR或任何remote写操作；无upstream也不publish。
14. UNIT最终PASS后进入下一个编号；一轮只在用户要求的范围内持续执行。
