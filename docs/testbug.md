# Confidential Compute MVP 测试问题（简明跟踪）

本文件面向直接阅读，详细复现证据保存在 `docs/testlog.md`。实例固定为 `confidential-mvp`；不记录任何 secret；禁止 push。

## BUG-001：部署配置权限阻塞（BLOCKED）

- 发现：端口要求已恢复为现有实例的 `39088`，但 `develop.sh up/status` 仍无法读取源目录 `data-sandbox.env`（权限 `0600`，owner=`nobody`）。现有五容器 owner 为 `xzh`，当前执行身份为 `collab`。
- 影响：无法安全启动/重启或接管现有 `confidential-mvp`；容器当前保持运行，未被修改。
- 修复情况：未修复；按复杂 Docker/权限规则标记 BLOCKED，等待有权限操作者或更强模型处理配置归属。
- 相关记录：`docs/testlog.md` 的 UNIT-001 / TEST-001-01～03。
