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

<!-- 如果产生本地 commit，用完整 commit hash 替换 No commit。严禁 push。 -->
