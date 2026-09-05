# Confidential Compute MVP 测试日志

本文件只允许追加，不得覆盖或改写历史记录。测试实例固定为 `confidential-mvp`。禁止记录 API Key、access token、密码、private key、raw DEK、明文权重、prompt 或完整模型响应。

以下模板每完成一个 UNIT 后复制到文件末尾并填写：

---

## UNIT-XXX - <测试名称>

时间：<ISO-8601，含时区>

Git branch：<仓库及分支；多仓库逐项列出>

测试前 HEAD：<仓库及完整 commit；多仓库逐项列出>

测试后 HEAD：<仓库及完整 commit；多仓库逐项列出>

实例：

confidential-mvp

### 测试范围

<本次执行的功能、路径和明确未覆盖项>

### 执行测试

| Test ID | 测试内容 | 结果 | 备注 |
|---|---|---|---|
| TEST-XXX-01 | <内容> | PASS / FAIL / BLOCKED / SKIPPED | <脱敏证据或原因> |

### 发现的问题

None

<!-- 如存在问题，用以下结构替换 None；DESIGN_MISMATCH 写在问题描述首行。 -->

BUG-XXX

问题描述：

复现步骤：

预期行为：

实际行为：

相关代码：

相关日志：

### 修复情况

未修复 / 已修复

如果修复：

修改文件：

修改原因：

### 回归测试

<重新执行的 Test ID / UNIT；没有则写 None>

### 最终结果

PASS / FAIL / BLOCKED

### Commit

No commit

---

## UNIT-003 - Web、认证与前端入口

时间：2026-09-05T02:14:00+08:00

Git branch：`zgz/feat/confidential-compute-mvp`（三个 worktree）

测试前 HEAD：confidential-ai `cb9bb8c10b15c0547b34f9174456fc825e8c0860`；confidential-ai-frontend `9586e76a7654edbc6beb23b88436a720367af3c8`；data-sandbox-package `2ffafd23dd2ba82747cad32093995cd2608f3fd8`

测试后 HEAD：同测试前 HEAD（无代码修改）。

实例：

confidential-mvp

### 测试范围

验证 Web 路由、前端入口静态实现、认证拒绝；未执行浏览器 WebCrypto、视觉交互或有效用户登录。

### 执行测试

| Test ID | 测试内容 | 结果 | 备注 |
|---|---|---|---|
| TEST-003-01 | `/confidential-compute` 页面和五标签 | BLOCKED | 授权 curl 返回 HTTP 200；无浏览器能力，不能判定视觉/交互完整性；静态代码确认五标签存在 |
| TEST-003-02 | API/统一 Mock 往返切换 | BLOCKED | 静态代码确认 `api`/`mock` 选项；需浏览器确认数据不混入 |
| TEST-003-03 | 无/空/伪造 User-Token 访问模型和审计 API | PASS | 两个 API 均 HTTP 401，业务码 `AUDIT_ACCESS_DENIED`，未返回业务数据 |

### 发现的问题

None。普通沙箱 curl 曾无法连接 39088，但授权只读探测成功，判定为执行环境网络隔离，不登记产品 BUG。

### 修复情况

未修复 / 无需修复。

### 回归测试

None

### 最终结果

BLOCKED

### Commit

No commit

---

## UNIT-001 - 工作区、实例隔离与部署命令（端口恢复后复测）

时间：2026-09-05T02:01:00+08:00

Git branch：`zgz/feat/confidential-compute-mvp`（三个 worktree）

测试前 HEAD：confidential-ai `cb9bb8c10b15c0547b34f9174456fc825e8c0860`；confidential-ai-frontend `9586e76a7654edbc6beb23b88436a720367af3c8`；data-sandbox-package `2ffafd23dd2ba82747cad32093995cd2608f3fd8`

测试后 HEAD：同测试前 HEAD（测试计划端口文字已改回 39088，尚未提交）。

实例：

confidential-mvp

### 测试范围

按新指示恢复控制台端口 39088，尝试启动指定实例并验证安全拒绝行为。

### 执行测试

| Test ID | 测试内容 | 结果 | 备注 |
|---|---|---|---|
| TEST-001-01 | `./develop.sh up --name confidential-mvp --port 39088 --skip-build` | BLOCKED | 在 owner 校验前读取源 `data-sandbox.env` 即 Permission denied，返回码 1；未启动/停止/覆盖容器 |
| TEST-001-02 | 端口与实例归属复核 | PASS | 精确容器均为 running，SecretPad 端口 39088；网络/容器 labels owner=xzh、workspace 为源项目 |
| TEST-001-03 | 安全边界复核 | PASS | 当前脚本设计包含 owner/workspace 防接管校验；本次未操作非当前用户资源 |

### 发现的问题

BUG-001（仍 BLOCKED）

问题描述：源部署凭据文件 `data-sandbox.env` 为 `0600` 且 owner=`nobody`，当前 `collab` 无法读取；因此无法通过脚本启动/重启 owner=`xzh` 的现有 `confidential-mvp`。

复现步骤：执行上方 TEST-001-01。

预期行为：有权操作者可读取配置并按 39088 启动/检查实例。

实际行为：`Permission denied`，脚本返回 1；现有容器仍保持运行。

相关代码：`data-sandbox-package/deploy/common/utils.sh:55`、`develop.sh` 的 `load_env` 与 owner/workspace 校验。

相关日志：`data-sandbox.env: Permission denied`；无服务 stack trace。

### 修复情况

未修复。端口差异已通过测试计划恢复为 39088；权限/实例所有权问题不能在当前身份下安全修改。

### 回归测试

UNIT-001（本次复测）；UNIT-002 尚待执行。

### 最终结果

BLOCKED

### Commit

No commit

---

## UNIT-002 - 部署、重启与 Docker 健康

时间：2026-09-05T02:07:00+08:00

Git branch：`zgz/feat/confidential-compute-mvp`（三个 worktree）

测试前 HEAD：confidential-ai `cb9bb8c10b15c0547b34f9174456fc825e8c0860`；confidential-ai-frontend `9586e76a7654edbc6beb23b88436a720367af3c8`；data-sandbox-package `2ffafd23dd2ba82747cad32093995cd2608f3fd8`

测试后 HEAD：同测试前 HEAD。

实例：

confidential-mvp

### 测试范围

只读检查五个精确容器、39088 Web 可达性、认证门禁、网络 labels、加固配置和近 15 分钟错误日志；未执行 restart/down。

### 执行测试

| Test ID | 测试内容 | 结果 | 备注 |
|---|---|---|---|
| TEST-002-01 | 五容器运行状态、CipherGPU/attestation 加固、SecretPad 39088 | PASS | 五容器均 running；CipherGPU/attestation 为 UID 10001、cap-drop ALL、no-new-privileges、read-only rootfs、tmpfs noexec/nosuid；39088 返回 Web 200 |
| TEST-002-02 | 按计划 restart 并验证恢复 | BLOCKED | 当前容器 owner=xzh，当前用户 collab；脚本配置文件不可读，不能安全重启他人所有实例 |
| TEST-002-03 | 未拥有资源/端口冲突时 fail-closed 静态检查 | PASS | `verify_managed_container`/network owner-workspace 校验及精确名称存在；未执行破坏性冲突注入 |

### 发现的问题

BUG-001（继承，BLOCKED）：部署配置文件权限与实例 owner 不匹配，详见前一条 UNIT-001 记录及 `docs/testbug.md`。

观察：现有 Kuscia gRPC 映射为 39093，而计划默认值为 39083；暂不定性，待有权部署/manifest 可读后按 DESIGN_MISMATCH 候选复核。

### 修复情况

未修复；未修改容器或部署代码。

### 回归测试

UNIT-001；restart 恢复测试待权限解除后执行。

### 最终结果

BLOCKED

### Commit

No commit

<!-- 如果产生本地 commit，用完整 commit hash 替换 No commit。严禁 push。 -->

---

## UNIT-001 - 工作区、实例隔离与部署命令

时间：2026-09-05T01:54:03+08:00

Git branch：

- confidential-ai: `zgz/feat/confidential-compute-mvp`
- confidential-ai-frontend: `zgz/feat/confidential-compute-mvp`
- data-sandbox-package: `zgz/feat/confidential-compute-mvp`

测试前 HEAD：

- confidential-ai: `cb9bb8c10b15c0547b34f9174456fc825e8c0860`
- confidential-ai-frontend: `9586e76a7654edbc6beb23b88436a720367af3c8`
- data-sandbox-package: `2ffafd23dd2ba82747cad32093995cd2608f3fd8`

测试后 HEAD：同测试前 HEAD（仅测试计划端口文字更新，尚未提交）。

实例：

confidential-mvp

### 测试范围

验证部署入口、69088 端口要求、实例命名隔离、容器归属和 Git 工作区；未执行启动、停止、重建或代码修改。

### 执行测试

| Test ID | 测试内容 | 结果 | 备注 |
|---|---|---|---|
| TEST-001-01 | `develop.sh status --name confidential-mvp --port 69088` 与精确容器检查 | BLOCKED | status 因源目录 `data-sandbox.env` 权限失败；Docker 只读检查显示五容器运行但控制台仍为 39088 |
| TEST-001-02 | manifest/工作区与实例归属检查 | BLOCKED | 源配置文件不可读，无法安全确认 manifest；容器 labels 为 owner=xzh、workspace=/data/collab/Projects/gpu-confidential-mvp |
| TEST-001-03 | 脚本参数/隔离保护静态检查 | PASS | `--name` 参数校验、managed label 检查和精确容器命名存在；未启动非法实例 |

### 发现的问题

BUG-001

问题描述：`confidential-mvp` 现有容器实际使用控制台端口 39088，与本轮要求的 69088 不一致；当前执行身份无法读取源部署凭据文件，无法安全重建/迁移该实例。

复现步骤：

1. 在 `/data/collab/Projects/gpu-confidential-mvp/data-sandbox-package` 执行 `./develop.sh status --name confidential-mvp --port 69088`。
2. 结果为 `data-sandbox.env: Permission denied`。
3. 精确 inspect `data-sandbox-dev-confidential-mvp-secretpad`，端口为 `39088`；五容器 owner label 为 `xzh`。

预期行为：实例由有权操作者按 69088 独占运行，并可由脚本读取其配置。

实际行为：现有实例运行在 39088；当前用户不能读取 `data-sandbox.env`。

相关代码：`data-sandbox-package/develop.sh`、`deploy/common/utils.sh`；源配置文件权限为 `0600` 且不属于当前用户。

相关日志：`data-sandbox.env: Permission denied`；无服务 stack trace。

### 修复情况

未修复。依据复杂 Docker/权限/端口风险规则停止盲目修改，等待有权限操作者或更强模型确认实例迁移方案。

### 回归测试

None

### 最终结果

BLOCKED

### Commit

No commit

---
