# 全链路 TEE 开发契约 v1

**状态：已冻结，A 发布，B 按本契约实现。** 版本标识：`tee-contract/1.0`。生效日期：2026-08-31。

本文件是 A/B 接口与分工的唯一规范，`examples.json` 是唯一示例文件。契约冻结不表示功能已经实现；当前仅完成隔离工作树与协议准备。B 无需审批本契约，遇到实现障碍应报告具体阻塞，不得自行改变接口、安全边界或回退到明文链路。破坏性修改由 A 发布新主版本。

## 一、工作位置与责任

A 使用服务器 `222.20.99.38` 的 `collab` 身份，唯一新工作树为 `/data/collab/Projects/gpu-tee-dev-a`，分支 `codex/tee-dev-a`，后端基线 `343eca6420640fb1f4e1cd1ad33993a4d43a9dc4`。

| 唯一维护人 | 文件与交付责任 |
| --- | --- |
| A | Java 接口/DTO/会话守卫、密钥与规则适配、资产同步、任务下发、结果导出、审计只读 API、三份 Flyway 迁移、部署适配及所有 TEE AppImage 注册/YAML、本契约 |
| B | Python 可信运行时、原运行容器脚本与构建来源回收、运行时 Dockerfile、原算子调用适配、React 登录/权限菜单/链路/回执/导出界面 |

B 在自己的工作树开发，不写 A 工作树；A 不写 B 工作树。P8 的 Java 只读接口归 A，React 展示归 B。共享 AppImage 的入口、资源和镜像信息由 B 提供，文件只由 A 修改。原前端、原工具链不为 A 另建工作树，复用工具链版本时必须隔离其写入位置。

现有代码可复用入口：`AuthServiceImpl.login`、`LoginRequest`、`UserContextDTO`、`LoginInterceptor`、`DevJobExecutor`、`SandboxDataControlService`、`ModelApiApprovalService`。RSA 使用 `secretpad-common/.../util/EncryptUtils.java` 的 `signSHA256withRSA/verifySHA256withRSA`，不可将 SHA-256 摘要当成签名。现有任务包含明文语义的 `input_csv_b64/sandbox_db_b64`，现有 CSV 结果落盘也需要改造；这些行为不能保留在 TEE 执行路径中。

## 二、通用 API 规则

新增接口前缀固定为 `/api/v1alpha1/tee`。JSON 使用 UTF-8、camelCase；新增请求及响应 data 携带 `contractVersion="tee-contract/1.0"`，既有登录结构仅增加端角色。版本不匹配拒绝。ID 为非空字符串，版本号为正整数，时间为 UTC RFC3339；JWS 的 Base64URL 无填充，其余二进制字段采用标准 Base64。

沿用实际响应格式：`{"status":{"code":0,"msg":"success"},"data":{...}}`。业务拒绝 HTTP 200 且 `status.code` 非零；未认证 HTTP 401、越权 HTTP 403；版本/格式错误 HTTP 400、大小超限 HTTP 413、服务不可用 HTTP 503，均返回同一包装。错误 data 固定包含 `contractVersion,errorCode,requestId,retryable`，不得包含密钥、数据行或内部堆栈。

POST 请求带 `requestId`。中心端按调用主体、操作、requestId 保存幂等记录至少 24 小时；相同内容重试返回原结果，相同 ID 不同内容拒绝。指纹按已校验 DTO 的确定性字段序列计算，不使用原始 JSON 属性顺序。任务 nonce 按签发方和 nonce 全局去重，记录至少保留至 expiresAt 后 24 小时；同一 requestId 的已接受重试先返回原任务，新的 requestId 复用旧 nonce 才判重放。

浏览器用原 `User-Token` 机制；跨机构和运行时接口必须 mTLS，最低 TLS 1.2，并验证证书链、有效期和吊销状态。身份由服务端证书/会话取得，不能信任请求自报的机构或角色。中心密钥服务独立于普通平台进程；原模板的 `--enable_capsule_tls=false` 必须移除。不得创建无需认证的仿真放行接口。

## 三、登录与端权限

`POST /api/login` 保留 `name/passwordHash`，增加 `endRole: CLIENT|CENTER`；原上下文响应及 token 持久化内容增加同名字段。实例配置 `allowedEndRoles`，默认仅 CLIENT；账户可用端角色与实例可用端角色取交集。

单端实例允许旧登录请求省略 endRole，推导唯一端；双端实例必须显式选择。旧 token 缺角色时返回 `RELOGIN_REQUIRED`。切换角色须重新登录。前端菜单过滤与后端权限使用相同矩阵：CLIENT 处理本机构数据接入、挂载、抽样脱敏、加密、审批和目录；CENTER 处理沙箱开发、SQL/Python/JAR、建模、计算及可信审计；共享管理仍受原资源权限控制。端角色不能授予额外机构/项目/数据权限。

A 的守卫覆盖普通会话、开发 token、模型 API 凭证和内部 RPC，不允许绕过端限制。B 只负责选择控件、错误提示及菜单，不在前端生成授权结论。

## 四、密钥、资产与规则

以下是 A 提供的统一适配接口，B 不直接依赖 Capsule 原生 SDK 或错误码。A 负责选定可实现本接口的底座版本；底座不满足时保持阻塞，不降低契约。

| 方法与相对路径 | 请求关键字段 | 成功 data |
| --- | --- | --- |
| POST `/keys/issue` | requestId, assetId, assetVersion | keyId, keyVersion, state；仅登记资产所有者可调用 |
| POST `/keys/claim` | requestId, assetId, assetVersion, keyId, keyVersion | keyEnvelope；仅所有者申领加密密钥 |
| POST `/keys/revoke` | requestId, keyId, keyVersion, reason | keyId, keyVersion, state=REVOKED；所有者或密钥管理员可调用 |
| POST `/policies/register` | requestId, policy | policyId, policyVersion, state=ACTIVE；由有效审批生成 |
| POST `/assets/register` | requestId, ownerId, schema, encryptedObject, policyId, policyVersion | assetId, assetVersion, objectId |
| POST `/runtime/release` | requestId, taskJws, attestationEvidence | taskId, runtimeMode, attestationVerified, keyEnvelopes |
| POST `/runtime/output-key` | requestId, taskJws, resultId, resultKind | keyEnvelope；结果 ID 首次申领时原子绑定任务，已绑定其他任务即拒绝 |
| GET `/objects/{objectId}` | 会话或证书身份 | encryptedObject；按任务或资产权属鉴权，只返回密文 |
| GET `/programs/{objectId}` | 绑定任务的运行时证书身份 | kind,sha256,contentB64；仅程序字节，不含数据行或密钥 |
| POST `/objects` | requestId, taskId, resultId, encryptedObject | objectId；只允许任务对应的运行时写结果 |

`keyEnvelope` 固定字段：`keyId,keyVersion,algorithm="RSA-OAEP-256",recipientCertSha256,wrappedKeyB64`。密钥服务用已认证接收者证书内的 RSA 公钥密封 32 字节数据密钥；RSA 至少 2048 位，OAEP hash 和 MGF1 均 SHA-256，label 为空。证书指纹是 DER 证书 SHA-256，服务端计算并绑定会话；不得由调用方传任意公钥。平台只转发密封结果，不持有解封私钥。见 [RSA-OAEP 参数依据](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption)。

每个资产版本有独立的数据密钥版本；同一版本重试复用已有密文对象。中心端签发并托管密钥，客户端不自产、不落盘。客户端在加密后清除应用可控的密钥缓冲；不承诺清除所有 GC/库副本。吊销拒绝后续申领与运行时放行，不能追回已释放密钥、原始数据或既有明文导出。

`encryptedObject` 字段：`contractVersion,assetId,assetVersion,keyId,keyVersion,algorithm,nonceB64,aadB64,ciphertextB64,tagB64,ciphertextSha256`。算法固定 AES-256-GCM，nonce 为 12 字节，tag 为 16 字节；同一 keyVersion 下 nonce 不得复用。AAD 的解码 JSON 绑定 assetId/assetVersion/keyId/keyVersion，传输保留原始字节，接收者核对值后以原字节认证解密。摘要为 `SHA256(nonce || aad || ciphertext || tag)`。

v1 每对象最多 64 MiB 明文，任务全部输入明文总量最多 256 MiB，超限明确拒绝；不支持分块拼装。Kuscia 仅接收密文对象 ID、元数据和签名任务，不内联数据块；任务 JSON 上限 1 MiB。对象存储与传输均为密文，大小、版本、摘要须在密钥放行和运行时解密前校验；不能为绕过限制退回明文 Base64。

`policy` 字段：`contractVersion,policyId,policyVersion,assetId,assetVersion,ownerId,sandboxId,columns,operators,expiresAt,reportKinds`。列名和算子精确匹配，不支持通配符；空授权集合即禁止。任务发起人与沙箱须具备已有业务权限。密钥服务放行同时校验规则版本、列、算子、有效期、任务签名、运行时身份和环境。

SIMULATION 只允许预注册仿真工作负载证书、指定运行镜像摘要及签名任务；HARDWARE 必须验证绑定接收者证书公钥摘要、任务 nonce 与镜像度量的证明。证据为空仅能进入显式配置的 SIMULATION，绝不作为 HARDWARE 失败后的回退。中心端和运行时都保留真实模式标记。

## 五、任务与运行时

下发入口固定为 Kuscia `task_input_config` 中的 `tee_task_jws`；B 运行时从 AppImage 挂载的配置读取，不再读取明文 `input_csv_b64/sandbox_db_b64`。A 负责 AppImage YAML，B 提供可执行镜像和启动入口；单次 Job 只处理一个任务。

`TaskSpec` 字段：`contractVersion,taskId,requestId,issuer,audience,sandboxId,operatorId,columns,inputs,program,issuedAt,expiresAt,nonce,outputPolicy,runtimeImageDigest`。inputs 每项为 `assetId,assetVersion,keyId,keyVersion,policyId,policyVersion,objectId,ciphertextSha256,plaintextBytes`。program 为 `kind: BUILTIN|SQL|PYTHON|JAR,objectId,sha256,parameters`；BUILTIN 的 objectId=null，其 sha256 为镜像内算子资源摘要；其余模式必须通过 `/programs/{objectId}` 取得程序字节并校验摘要。程序对象不含数据行或数据密钥。parameters 全部在签名载荷中，禁止未签名覆盖。

签名采用 JWS Compact，protected header 为 `alg=RS256,typ=JWS,kid`；签名输入是原始两段 Base64URL 字节拼接，验证时不得重序列化 payload。中心端使用受信 RSA 公钥映射，未知 kid 或非 RS256 一律拒绝。现有 Java 工具返回标准 Base64，需转换为无填充 Base64URL。[规范依据：RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html)。

任务有效期最长 5 分钟，时钟容差 30 秒；运行时校验 issuer、audience、镜像摘要及所有对象绑定。顺序固定：验签/时效/去重 → 对象元数据与策略检查 → 环境和密钥放行 → GCM 认证解密 → 列筛选并组装运行库 → 原算子执行 → 分类与加密输出。任一环节失败即终止，不运行用户代码。

B 在运行时受信框架内取得数据密钥、解密和筛列；只把授权列交给用户脚本。Python/JAR/SQL 子进程不得访问密钥缓冲、未筛选输入或其他任务目录。临时数据仅存内存或受限 tmpfs，不写宿主机持久卷；禁止 core dump，约束 swap，成功/失败/取消均清理任务临时空间。运行时退出码非零视为失败，最长运行时间默认 30 分钟。SIMULATION 对宿主机管理员没有内存保密保证，不得夸大隔离能力。

## 六、输出、回执和投票

`outputPolicy` 固定包含 `reportKinds,encryptData=true,encryptModel=true,exportRequiresAllContributors=true`。REPORT 仅允许 `EVALUATION_METRICS/FEATURE_IMPORTANCE/TREE_STRUCTURE`，且必须在全部输入策略的共同白名单内。DATA 和 MODEL 一律加密，使用中心签发的独立结果密钥；明文结果不能先交给普通平台再补加密。

B 通过 `POST /tasks/{taskId}/receipt` 发送 `requestId,receiptJws`，采用工作负载证书对应私钥签名的 RS256 JWS；A 根据已登记且绑定该任务的证书验签，不能接受任务自带任意公钥。平台保存原始回执及验证状态，界面只展示已核实状态。

回执载荷为 `contractVersion,taskId,requestId,status,runtimeMode,attestationVerified,policyVersion,keyReleaseCount,outputs,startedAt,finishedAt,errorCode`。status 取 SUCCEEDED/FAILED/CANCELLED；policyVersion 为各输入均使用同一版本时的摘要字段，否则为 null，准确规则版本以任务 inputs 为准。keyReleaseCount 为本次任务成功放行的输入密钥数，不包含结果密钥。

REPORT 输出含 `kind,reportKind,encrypted=false,content`。单份报告上限 1 MiB；运行时按三类结构白名单过滤，禁止数据行、任意 CSV、stdout、原始错误堆栈及数据密钥。DATA/MODEL 输出含 `kind,resultId,objectId,encrypted=true,keyId,keyVersion,ciphertextSha256,contributors,exportState=PENDING_APPROVAL`。贡献方为全部输入资产所属机构的去重集合，不接受运行时自行减少。

`POST /results/{resultId}/export` 接收 requestId，复用已有审批流；全部贡献方对同一不可变结果版本同意、授权未过期且密钥未吊销才返回 `objectId,keyEnvelope,expiresAt`，有效期 5 分钟。缺票、拒绝、结果版本变化或过期一律拒绝。解封密钥的接收者须为审批允许的数据方；普通中心平台不解密导出结果。审批记录绑定结果摘要与接收者身份。v1 不提供免投票数据预览。

## 七、环境与只读展示

| GET 接口 | data 字段 |
| --- | --- |
| `/environment` | contractVersion,runtimeMode,checkedAt,hardwareDetected,deviceChecks,attestationVerified,keyServiceReachable,realModeReady,blockers |
| `/keys` | contractVersion,items；每项为 keyId,keyVersion,assetId,ownerId,state,issuedAt,claimCount,releaseCount |
| `/tasks/{taskId}/chain` | contractVersion,taskId,events；事件为 stage,status,occurredAt,errorCode；stage 固定 KEY_ISSUE/ENCRYPT/POLICY/ATTESTATION/EXECUTION/EGRESS |
| `/tasks/{taskId}/receipt` | contractVersion,taskId,receiptJws,signatureVerified |

审计接口按机构与沙箱权限过滤；台账不得返回密钥材料。deviceChecks 的 sgx/tdx/csv 表示宿主机受控检测结果，检测时间必须显示；设备存在不等同证明通过。默认 SIMULATION，真实切换入口保持禁用直到 realModeReady=true；v1 不提供在线切换写接口，模式变化走明确授权的部署。

链路状态只能来自实际审计事件，缺数据显示 UNKNOWN；stage 状态为 PENDING/RUNNING/SUCCEEDED/FAILED/UNKNOWN。仿真 attestationVerified=false 必须显式显示，不允许绿色“硬件认证通过”。字段计数是事件统计，不可硬编码演示数据。

## 八、错误与验收

| code | errorCode | 含义 |
| --- | --- | --- |
| 49001 | END_ROLE_DENIED | 端或账户越权 |
| 49002 | END_ROLE_REQUIRED | 双端登录未选择 |
| 49003 | RELOGIN_REQUIRED | 旧会话缺端角色 |
| 49004 | ASSET_OWNER_MISMATCH | 证书机构与资产不符 |
| 49005 | KEY_REVOKED | 密钥吊销 |
| 49006 | POLICY_DENIED | 列、算子或有效期未授权 |
| 49007 | REQUEST_ID_CONFLICT | 相同请求 ID 对应不同内容 |
| 49008 | TASK_SIGNATURE_INVALID | 任务/回执签名或信任校验失败 |
| 49009 | TASK_REPLAYED | 新请求复用已消费 nonce |
| 49010 | EXPORT_NOT_APPROVED | 导出条件未满足 |
| 49011 | REAL_MODE_UNAVAILABLE | 真实模式缺少证明条件 |
| 49012 | AUDIT_ACCESS_DENIED | 审计越权 |
| 49013 | CONTRACT_INVALID | 版本、格式或必填字段错误 |
| 49014 | PAYLOAD_TOO_LARGE | 对象/任务/报告超限 |
| 49015 | KEY_SERVICE_UNAVAILABLE | 密钥服务不可用，可重试 |
| 49016 | TASK_EXPIRED | 签名任务过期 |
| 49017 | DATA_INTEGRITY_FAILED | 摘要、AAD 或 GCM 认证失败 |

B 先使用合成示例验证 AES-GCM 输入/输出解密、RSA 签名验签和篡改拒绝，再提交运行时镜像摘要、源码位置与接口测试结果给 A。A 按契约检查登录越权、机构越权、规则、吊销、重试/重放、未批准导出与报告分类。接口/运行时不符合契约时修实现，不靠页面文案掩盖。

示例文件包含公开合成 AES 测试密钥、公钥、自签名测试证书与固定测试时间，不含真实凭据，不允许用于真实数据。测试证书仅用于本向量验证，生产信任库禁止导入；时效检查以 testMaterial.verificationTime 为准。签名私钥只在生成向量时驻留内存，未交付。加密向量通过仅证明样例自洽；硬件可信保证、密钥服务和业务流程必须分别实测。

本阶段无业务实现、迁移、构建、部署、提交或推送。后续仅规划三个新测试实例，两客户端一中心端；实例、端口与工具链写入隔离记录在本地《工作交接手册》，该手册不上传服务器。
