/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service;

import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.web.service.tee.TeeResultMetadataService;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Controls mounted-data use and development-result view/export within this node. */
@Service
public class SandboxDataControlService {
    private static final ZoneId DISPLAY_ZONE = ZoneId.of("Asia/Shanghai");
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public SandboxDataControlService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    /** Lists mounted data that is physically available on the current node. */
    public List<Map<String, Object>> mountControls() {
        String node = nodeId();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select m.sandbox_id,m.asset_id,m.id mount_id,s.name sandbox_name,s.project_id,s.expires_at,"
                        + "a.name asset_name,a.provider_node_id,n.name provider_node_name," 
                        + "coalesce(c.allow_use,1) allow_use,c.use_until,coalesce(c.version,0) version,c.updated_at "
                        + "from ds_sandbox_dataset_mount m join ds_sandbox s on s.id=m.sandbox_id and s.deleted=0 "
                        + "join ds_data_asset a on a.id=m.asset_id and a.deleted=0 "
                        + "left join node n on (n.node_id=a.provider_node_id or n.inst_id=a.provider_node_id) and n.is_deleted=0 "
                        + "left join ds_sandbox_mount_control c on c.sandbox_id=m.sandbox_id and c.asset_id=m.asset_id "
                        + "where m.deleted=0 and m.status='READY' and (s.owner_id=? or s.owner_id=?) and s.created_by=? "
                        + "order by s.created_at desc,a.name", node, ownerId(), actor());
        rows.forEach(row -> {
            row.put("use_until", TeeResultMetadataService.earliest(row.get("use_until"), row.get("expires_at")));
            addMountState(row);
            applyAssetTimeWindow(row, string(row.get("asset_id")));
        });
        return rows;
    }

    @Transactional
    public Map<String, Object> saveMountControl(Map<String, Object> request) {
        String sandboxId = required(request, "sandboxId");
        String assetId = required(request, "assetId");
        requireSandboxCreator(sandboxId);
        requireRow("select m.id from ds_sandbox_dataset_mount m where m.sandbox_id=? and m.asset_id=? "
                + "and m.deleted=0 and m.status='READY'", sandboxId, assetId);
        boolean allowUse = bool(request.get("allowUse"), true);
        String useUntil = normalizeTime(string(request.get("useUntil")), "使用截止时间");
        if (useUntil.isBlank()) throw new IllegalArgumentException("必须设置使用截止时间");
        int expected = intValue(request.get("version"), 0);
        List<Map<String, Object>> existing = jdbc.queryForList(
                "select * from ds_sandbox_mount_control where sandbox_id=? and asset_id=?", sandboxId, assetId);
        String now = now();
        if (existing.isEmpty()) {
            if (expected != 0) throw new IllegalStateException("使用控制已被其他用户更新，请刷新后重试");
            jdbc.update("insert into ds_sandbox_mount_control(id,sandbox_id,asset_id,allow_use,use_until,version,updated_by,updated_at) "
                            + "values(?,?,?,?,?,1,?,?)",
                    UUID.randomUUID().toString(), sandboxId, assetId, allowUse ? 1 : 0, useUntil, actor(), now);
        } else {
            int affected = jdbc.update("update ds_sandbox_mount_control set allow_use=?,use_until=?,version=version+1,updated_by=?,updated_at=? "
                            + "where sandbox_id=? and asset_id=? and version=?",
                    allowUse ? 1 : 0, useUntil, actor(), now, sandboxId, assetId, expected);
            if (affected != 1) throw new IllegalStateException("使用控制已被其他用户更新，请刷新后重试");
        }
        Map<String, Object> result = requireRow(
                "select * from ds_sandbox_mount_control where sandbox_id=? and asset_id=?", sandboxId, assetId);
        result.putAll(mountPolicy(sandboxId, assetId));
        return result;
    }

    public List<Map<String, Object>> resultControls(String sandboxId) {
        requireSandboxCreator(sandboxId);
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select d.sandbox_id,d.table_name,d.name,d.row_count,t.id task_id,t.name task_name,t.finished_at,t.result_view_until,d.created_at,"
                        + "s.project_id,p.name project_name,s.name sandbox_name,c.view_until,c.allow_export,c.export_until,coalesce(c.version,0) version,c.updated_at "
                        + "from ds_sandbox_data_dir d left join ds_dev_task t on t.sandbox_id=d.sandbox_id "
                        + "and t.result_table_name=d.table_name and t.deleted=0 "
                        + "left join ds_sandbox s on s.id=d.sandbox_id left join project p on p.project_id=s.project_id "
                        + "left join ds_sandbox_result_control c on c.sandbox_id=d.sandbox_id and c.table_name=d.table_name "
                        + "where d.sandbox_id=? and d.kind='RESULT' and d.deleted=0 order by d.created_at desc", sandboxId);
        String sandboxUntil = sandboxUntil(sandboxId);
        rows.forEach(row -> {
            row.put("projectId", row.get("project_id"));
            row.put("projectName", row.get("project_name"));
            row.put("sandboxName", row.get("sandbox_name"));
            row.put("runId", row.get("task_id"));
            row.put("createdAt", TeeResultMetadataService.earliest(
                    string(row.get("finished_at")).isBlank() ? row.get("created_at") : row.get("finished_at")));
            row.put("view_until", TeeResultMetadataService.earliest(row.get("view_until"), row.get("result_view_until"), sandboxUntil));
            addResultState(row);
        });
        appendTeeResults(sandboxId, rows);
        return rows;
    }

    /**
     * 正式 TEE 任务不会在沙箱数据库落明文 RESULT 表，产出只存在于已验签的结果快照和
     * TEE 对象台账。原列表以 ds_sandbox_data_dir 为主表，因此这类成功任务始终显示为空。
     * 这里把密文对象与允许明文出域的报告补成只读行；它们的权限来自多方导出审批或
     * 输出规则，不能复用本地明文结果表的查看/导出开关。
     */
    private void appendTeeResults(String sandboxId, List<Map<String, Object>> rows) {
        List<Map<String, Object>> tasks = jdbc.queryForList(
                "select id task_id,sandbox_id,name task_name,result_rows,finished_at,result_preview,result_view_until,result_export_until "
                        + "from ds_dev_task where sandbox_id=? and run_mode='PROD' and status='SUCCEEDED' "
                        + "and deleted=0 and result_preview is not null and result_preview<>'' "
                        + "order by finished_at desc", sandboxId);
        for (Map<String, Object> task : tasks) {
            JsonNode preview;
            try {
                preview = mapper.readTree(string(task.get("result_preview")));
            } catch (Exception malformed) {
                continue;
            }
            if (!"SIMULATION".equals(preview.path("runtimeMode").asText())) continue;
            for (JsonNode output : preview.path("encryptedOutputs")) {
                Map<String, Object> row = teeBaseRow(task);
                copyText(output, row, "kind", "resultId", "objectId", "keyId", "keyVersion",
                        "ciphertextSha256", "exportState");
                row.put("name", string(task.get("task_name")) + " · "
                        + ("MODEL".equals(output.path("kind").asText()) ? "模型" : "数据") + " · "
                        + output.path("resultId").asText(output.path("objectId").asText("unknown")));
                row.put("table_name", "tee:" + output.path("resultId").asText(
                        output.path("objectId").asText("unknown")));
                row.put("contributors", stringList(output.path("contributors")));
                row.put("tee_encrypted", true);
                row.put("permission_mode", "MULTI_PARTY_EXPORT_APPROVAL");
                row.put("canPreview", false);
                row.put("canExport", false);
                rows.add(row);
            }
            int reportIndex = 0;
            for (JsonNode report : preview.path("reports")) {
                Map<String, Object> row = teeBaseRow(task);
                copyText(report, row, "kind", "reportKind");
                row.put("name", report.path("reportKind").asText("REPORT") + " 明文报告");
                row.put("table_name", "tee-report:" + task.get("task_id") + ":" + reportIndex++);
                row.put("tee_report", true);
                row.put("permission_mode", "RULE_AUTHORIZED");
                row.put("canPreview", !expired(string(row.get("view_until"))));
                row.put("canExport", false);
                rows.add(row);
            }
        }
    }

    private Map<String, Object> teeBaseRow(Map<String, Object> task) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("sandbox_id", task.get("sandbox_id"));
        row.put("task_id", task.get("task_id"));
        row.put("task_name", task.get("task_name"));
        row.put("row_count", task.get("result_rows"));
        row.put("finished_at", task.get("finished_at"));
        row.put("runtime_mode", "SIMULATION");
        row.put("view_until", TeeResultMetadataService.earliest(task.get("result_view_until"),
                sandboxUntil(string(task.get("sandbox_id")))));
        row.put("export_until", TeeResultMetadataService.earliest(task.get("result_export_until"), row.get("view_until")));
        row.put("use_until", row.get("view_until"));
        row.put("serverTime", Instant.now().toString());
        boolean available = !expired(string(row.get("view_until")));
        row.put("canUse", available);
        row.put("status", available ? "ACTIVE" : "EXPIRED");
        row.put("disabledReason", available ? "" : "已超过查看截止时间");
        return row;
    }

    private static void copyText(JsonNode source, Map<String, Object> target, String... fields) {
        for (String field : fields) {
            target.put(field, source.path(field).asText(""));
        }
    }

    private static List<String> stringList(JsonNode values) {
        List<String> result = new ArrayList<>();
        if (values.isArray()) values.forEach(value -> result.add(value.asText()));
        return result;
    }

    @Transactional
    public Map<String, Object> saveResultControl(Map<String, Object> request) {
        String sandboxId = required(request, "sandboxId");
        String tableName = required(request, "tableName");
        requireSandboxCreator(sandboxId);
        Map<String, Object> dir = requireRow("select * from ds_sandbox_data_dir where sandbox_id=? and table_name=? "
                + "and kind='RESULT' and deleted=0", sandboxId, tableName);
        String taskId = string(request.get("taskId"));
        if (taskId.isBlank()) {
            List<Map<String, Object>> tasks = jdbc.queryForList("select id from ds_dev_task where sandbox_id=? "
                    + "and result_table_name=? and deleted=0 order by created_at desc limit 1", sandboxId, tableName);
            taskId = tasks.isEmpty() ? string(dir.get("source_ref")) : string(tasks.get(0).get("id"));
        }
        ResultPolicy policy = policy(request);
        if (policy.viewUntil().isBlank()) throw new IllegalArgumentException("必须设置查看截止时间");
        int expected = intValue(request.get("version"), 0);
        upsertResult(sandboxId, tableName, taskId, policy, expected);
        if (!taskId.isBlank()) {
            jdbc.update("update ds_dev_task set result_view_until=?,allow_result_export=?,result_export_until=?,updated_at=? "
                            + "where id=? and sandbox_id=? and deleted=0",
                    policy.viewUntil(), policy.allowExport() ? 1 : 0, policy.exportUntil(), now(), taskId, sandboxId);
        }
        Map<String, Object> result = requireRow("select * from ds_sandbox_result_control where sandbox_id=? and table_name=?",
                sandboxId, tableName);
        result.put("view_until", TeeResultMetadataService.earliest(result.get("view_until"), sandboxUntil(sandboxId)));
        addResultState(result);
        return result;
    }

    /** Stores the requested output policy before a task can expose any result. */
    @Transactional
    public void prepareTaskResultControl(String taskId, String sandboxId, Map<String, Object> request) {
        if (sandboxId == null || sandboxId.isBlank()) return;
        ResultPolicy policy = policy(request);
        if (policy.viewUntil().isBlank()) {
            Map<String, Object> sandbox = requireRow("select expires_at from ds_sandbox where id=? and deleted=0", sandboxId);
            String fallback = normalizeTime(string(sandbox.get("expires_at")), "沙箱截止时间");
            if (fallback.isBlank()) throw new IllegalArgumentException("必须设置开发结果查看截止时间");
            if (!policy.exportUntil().isBlank()
                    && instant(policy.exportUntil(), "导出截止时间").isAfter(instant(fallback, "查看截止时间"))) {
                throw new IllegalArgumentException("导出截止时间不能晚于查看截止时间");
            }
            policy = new ResultPolicy(fallback, policy.allowExport(), policy.exportUntil());
        }
        String tableName = "result_" + sanitize(taskId);
        jdbc.update("update ds_dev_task set result_table_name=?,result_view_until=?,allow_result_export=?,result_export_until=?,updated_at=? "
                        + "where id=? and sandbox_id=? and deleted=0",
                tableName, policy.viewUntil(), policy.allowExport() ? 1 : 0, policy.exportUntil(), now(), taskId, sandboxId);
        upsertResult(sandboxId, tableName, taskId, policy, -1);
    }

    /** Synchronizes a preconfigured policy with the actual table name produced by execution. */
    @Transactional
    public void registerResultControl(String taskId, String sandboxId, String tableName) {
        if (sandboxId == null || sandboxId.isBlank() || tableName == null || tableName.isBlank()) return;
        Map<String, Object> task = requireRow("select result_view_until,allow_result_export,result_export_until "
                + "from ds_dev_task where id=? and sandbox_id=? and deleted=0", taskId, sandboxId);
        ResultPolicy policy = new ResultPolicy(string(task.get("result_view_until")),
                bool(task.get("allow_result_export"), false), string(task.get("result_export_until")));
        List<Map<String, Object>> old = jdbc.queryForList("select id from ds_sandbox_result_control where task_id=?", taskId);
        if (!old.isEmpty()) {
            jdbc.update("update ds_sandbox_result_control set table_name=?,view_until=?,allow_export=?,export_until=?," 
                            + "version=version+1,updated_by=?,updated_at=? where task_id=?",
                    tableName, policy.viewUntil(), policy.allowExport() ? 1 : 0, policy.exportUntil(), actor(), now(), taskId);
        } else {
            upsertResult(sandboxId, tableName, taskId, policy, -1);
        }
    }

    public Map<String, Object> enrichDirectory(Map<String, Object> directory) {
        directory.put("serverTime", Instant.now().toString());
        Object raw = directory.get("items");
        if (!(raw instanceof List<?> values)) return directory;
        String sandboxId = string(directory.get("sandboxId"));
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object value : values) {
            if (!(value instanceof Map<?, ?> source)) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            source.forEach((key, val) -> item.put(String.valueOf(key), val));
            String kind = string(item.get("kind"));
            String table = string(item.get("tableName"));
            if ("MOUNT".equals(kind)) {
                Map<String, Object> policy = mountPolicy(sandboxId, string(item.get("assetId")));
                item.putAll(policy);
                item.put("canPreview", policy.get("canPreview"));
                item.put("canExport", false);
            } else if ("RESULT".equals(kind)) {
                Map<String, Object> policy = resultPolicy(sandboxId, table);
                item.putAll(policy);
            } else {
                item.put("canPreview", true);
                item.put("canExport", false);
            }
            item.put("serverTime", directory.get("serverTime"));
            items.add(item);
        }
        directory.put("items", items);
        return directory;
    }

    public void requireTablePreview(String sandboxId, String tableName) {
        Map<String, Object> dir = dataDir(sandboxId, tableName);
        String kind = string(dir.get("kind"));
        if ("MOUNT".equals(kind) && !mountPreviewAllowed(sandboxId, string(dir.get("asset_id")))) {
            throw new SecurityException("该挂载数据不可预览：已被禁止使用，或已超过数据目录设置的访问 / 使用截止时间");
        }
        if ("RESULT".equals(kind) && !bool(resultPolicy(sandboxId, tableName).get("canPreview"), false)) {
            throw new SecurityException("开发结果已超过查看截止时间");
        }
    }

    public void requireMountTableUsable(String sandboxId, String tableName) {
        Map<String, Object> dir = dataDir(sandboxId, tableName);
        if ("MOUNT".equals(string(dir.get("kind"))) && !mountAllowed(sandboxId, string(dir.get("asset_id")))) {
            throw new SecurityException("该挂载数据已被禁止使用或已超过使用截止时间");
        }
        if ("RESULT".equals(string(dir.get("kind")))
                && !bool(resultPolicy(sandboxId, tableName).get("canUse"), false)) {
            throw new SecurityException("开发结果已超过使用截止时间");
        }
    }

    public void requireMountAssetUsable(String sandboxId, String assetId) {
        if (!mountAllowed(sandboxId, assetId)) {
            throw new SecurityException("该挂载数据已被禁止使用或已超过使用截止时间");
        }
    }

    public void requireResultExport(String sandboxId, String tableName) {
        Map<String, Object> dir = dataDir(sandboxId, tableName);
        if (!"RESULT".equals(string(dir.get("kind")))) throw new SecurityException("挂载数据不允许导出");
        if (!bool(resultPolicy(sandboxId, tableName).get("canExport"), false)) {
            throw new SecurityException("开发结果不允许导出或已超过导出截止时间");
        }
    }

    public void requireTaskResultView(Map<String, Object> task) {
        String sandboxId = string(task.get("sandbox_id"));
        String table = string(task.get("result_table_name"));
        String until = TeeResultMetadataService.earliest(task.get("result_view_until"), sandboxUntil(sandboxId));
        if (expired(until) || (!sandboxId.isBlank() && !table.isBlank()
                && !bool(resultPolicy(sandboxId, table).get("canPreview"), false))) {
            throw new SecurityException("开发结果已超过查看截止时间");
        }
    }

    public void requireTaskResultExport(Map<String, Object> task) {
        String sandboxId = string(task.get("sandbox_id"));
        String table = string(task.get("result_table_name"));
        if (sandboxId.isBlank() || table.isBlank()) throw new SecurityException("该任务没有可导出的沙箱结果");
        requireResultExport(sandboxId, table);
    }

    private Map<String, Object> resultPolicy(String sandboxId, String tableName) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_sandbox_result_control "
                + "where sandbox_id=? and table_name=?", sandboxId, tableName);
        Map<String, Object> result = rows.isEmpty() ? new LinkedHashMap<>() : new LinkedHashMap<>(rows.get(0));
        result.put("view_until", TeeResultMetadataService.earliest(result.get("view_until"), sandboxUntil(sandboxId)));
        addResultState(result);
        return result;
    }

    private void addResultState(Map<String, Object> row) {
        row.put("view_until", TeeResultMetadataService.earliest(row.get("view_until")));
        row.put("use_until", row.get("view_until"));
        row.put("serverTime", Instant.now().toString());
        boolean canView = !expired(string(row.get("view_until")));
        row.put("canUse", canView);
        row.put("status", canView ? "ACTIVE" : "EXPIRED");
        row.put("disabledReason", canView ? "" : "已超过查看截止时间");
        boolean canExport = canView && bool(row.get("allow_export"), false)
                && !string(row.get("export_until")).isBlank() && !expired(string(row.get("export_until")));
        row.put("canPreview", canView);
        row.put("canExport", canExport);
        row.put("controlled", intValue(row.get("version"), 0) > 0);
    }

    private void addMountState(Map<String, Object> row) {
        row.put("serverTime", Instant.now().toString());
        boolean allowed = bool(row.get("allow_use"), true);
        String useUntil = string(row.get("use_until"));
        boolean canUse = allowed && !expired(useUntil);
        row.put("canUse", canUse);
        row.put("controlled", intValue(row.get("version"), 0) > 0);
        row.put("disabledReason", canUse ? "" : allowed ? "已超过使用截止时间" : "已禁止使用");
    }

    private Map<String, Object> mountPolicy(String sandboxId, String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select allow_use,use_until,version from ds_sandbox_mount_control where sandbox_id=? and asset_id=?",
                sandboxId, assetId);
        Map<String, Object> policy = rows.isEmpty() ? new LinkedHashMap<>() : new LinkedHashMap<>(rows.get(0));
        policy.putIfAbsent("allow_use", 1);
        policy.put("use_until", TeeResultMetadataService.earliest(policy.get("use_until"), sandboxUntil(sandboxId)));
        addMountState(policy);
        applyAssetTimeWindow(policy, assetId);
        return policy;
    }

    private boolean mountAllowed(String sandboxId, String assetId) {
        return bool(mountPolicy(sandboxId, assetId).get("canUse"), false);
    }

    private boolean mountPreviewAllowed(String sandboxId, String assetId) {
        return bool(mountPolicy(sandboxId, assetId).get("canPreview"), false);
    }

    /**
     * 叠加数据目录为该资产设置的时间窗：使用截止时间决定能否参与计算，访问截止时间决定能否预览。
     * 数据目录的设置对所有沙箱统一生效，因此与沙箱内的挂载开关取交集。
     */
    private void applyAssetTimeWindow(Map<String, Object> policy, String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select access_start,access_end,valid_from,valid_until "
                + "from ds_asset_usage_control where asset_id=?", assetId);
        Map<String, Object> control = rows.isEmpty() ? syncedTimeWindow(assetId) : rows.get(0);
        policy.put("use_until", TeeResultMetadataService.earliest(policy.get("use_until"), control.get("valid_until")));
        boolean canUse = bool(policy.get("canUse"), false) && !expired(string(policy.get("use_until")));
        if (!canUse && bool(policy.get("allow_use"), true)) policy.put("disabledReason", "已超过使用截止时间");
        if (canUse && !AssetTimeWindow.within(control.get("valid_from"), control.get("valid_until"))) {
            canUse = false;
            policy.put("disabledReason", "已超过数据目录设置的使用截止时间");
        }
        String viewUntil = TeeResultMetadataService.earliest(control.get("access_end"), policy.get("use_until"));
        boolean canPreview = canUse && !expired(viewUntil)
                && AssetTimeWindow.within(control.get("access_start"), control.get("access_end"));
        if (canUse && !canPreview) {
            policy.put("disabledReason", "已超过数据目录设置的访问截止时间");
        }
        policy.put("canUse", canUse);
        policy.put("canPreview", canPreview);
        policy.put("view_until", viewUntil);
        policy.put("status", canUse ? "ACTIVE" : expired(string(policy.get("use_until"))) ? "EXPIRED" : "DISABLED");
    }

    /**
     * 供数方设置的时间窗只写在对方本地的 {@code ds_asset_usage_control}，本端读项目快照。
     *
     * <p>快照在挂载时留存、在供数方改动控制后刷新并随 P2P 同步下发，因此与供数方的设置一致。
     * 拿不到快照时返回空窗口，即不额外限制，由挂载开关与审批期限继续把关。</p>
     */
    private Map<String, Object> syncedTimeWindow(String assetId) {
        List<Map<String, Object>> attachments = jdbc.queryForList(
                "select asset_json from ds_project_asset where asset_id=? and deleted=0 limit 1", assetId);
        if (attachments.isEmpty()) {
            return new LinkedHashMap<>();
        }
        try {
            JsonNode snapshot = mapper.readTree(string(attachments.get(0).get("asset_json")));
            Map<String, Object> control = new LinkedHashMap<>();
            control.put("access_start", text(snapshot, "access_start"));
            control.put("access_end", text(snapshot, "access_end"));
            control.put("valid_from", text(snapshot, "control_valid_from", "valid_from"));
            control.put("valid_until", text(snapshot, "control_valid_until", "valid_until"));
            return control;
        } catch (Exception malformed) {
            return new LinkedHashMap<>();
        }
    }

    private static String text(JsonNode node, String... fields) {
        for (String field : fields) {
            String value = node.path(field).asText("");
            if (!value.isBlank() && !"null".equals(value)) {
                return value;
            }
        }
        return "";
    }

    private Map<String, Object> dataDir(String sandboxId, String tableName) {
        return requireRow("select * from ds_sandbox_data_dir where sandbox_id=? and table_name=? and deleted=0",
                sandboxId, tableName);
    }

    private void upsertResult(String sandboxId, String tableName, String taskId, ResultPolicy policy, int expected) {
        List<Map<String, Object>> existing = jdbc.queryForList("select version from ds_sandbox_result_control "
                + "where sandbox_id=? and table_name=?", sandboxId, tableName);
        String now = now();
        if (existing.isEmpty()) {
            if (expected > 0) throw new IllegalStateException("结果权限已被其他用户更新，请刷新后重试");
            jdbc.update("insert into ds_sandbox_result_control(id,sandbox_id,table_name,task_id,view_until,allow_export," 
                            + "export_until,version,updated_by,updated_at) values(?,?,?,?,?,?,?,1,?,?)",
                    UUID.randomUUID().toString(), sandboxId, tableName, taskId.isBlank() ? null : taskId, policy.viewUntil(),
                    policy.allowExport() ? 1 : 0, policy.exportUntil(), actor(), now);
        } else if (expected >= 0) {
            int affected = jdbc.update("update ds_sandbox_result_control set task_id=?,view_until=?,allow_export=?," 
                            + "export_until=?,version=version+1,updated_by=?,updated_at=? "
                            + "where sandbox_id=? and table_name=? and version=?",
                    taskId, policy.viewUntil(), policy.allowExport() ? 1 : 0, policy.exportUntil(), actor(), now,
                    sandboxId, tableName, expected);
            if (affected != 1) throw new IllegalStateException("结果权限已被其他用户更新，请刷新后重试");
        }
    }

    private ResultPolicy policy(Map<String, Object> request) {
        String viewUntil = normalizeTime(string(request.get("viewUntil")), "查看截止时间");
        boolean allowExport = bool(request.get("allowExport"), false);
        String exportUntil = normalizeTime(string(request.get("exportUntil")), "导出截止时间");
        if (allowExport && exportUntil.isBlank()) throw new IllegalArgumentException("允许导出时必须设置导出截止时间");
        if (!allowExport) exportUntil = "";
        if (!viewUntil.isBlank() && !exportUntil.isBlank()
                && instant(exportUntil, "导出截止时间").isAfter(instant(viewUntil, "查看截止时间"))) {
            throw new IllegalArgumentException("导出截止时间不能晚于查看截止时间");
        }
        return new ResultPolicy(viewUntil, allowExport, exportUntil);
    }

    private String normalizeTime(String value, String field) {
        if (value == null || value.isBlank() || "null".equalsIgnoreCase(value)) return "";
        return instant(value, field).atZone(DISPLAY_ZONE).toOffsetDateTime().toString();
    }

    private Instant instant(String value, String field) {
        try { return OffsetDateTime.parse(value).toInstant(); }
        catch (Exception ignored) {
            try { return LocalDateTime.parse(value).atZone(DISPLAY_ZONE).toInstant(); }
            catch (Exception e) { throw new IllegalArgumentException(field + "格式无效"); }
        }
    }

    private boolean expired(String value) {
        return !value.isBlank() && !Instant.now().isBefore(instant(value, "截止时间"));
    }

    private String sandboxUntil(String sandboxId) {
        if (sandboxId.isBlank()) return "";
        List<Map<String, Object>> rows = jdbc.queryForList("select expires_at from ds_sandbox where id=?", sandboxId);
        return rows.isEmpty() ? "" : TeeResultMetadataService.earliest(rows.get(0).get("expires_at"));
    }

    private void requireSandboxCreator(String sandboxId) {
        Map<String, Object> sandbox = requireRow("select * from ds_sandbox where id=? and deleted=0", sandboxId);
        if ((!Objects.equals(nodeId(), string(sandbox.get("owner_id")))
                && !Objects.equals(ownerId(), string(sandbox.get("owner_id"))))
                || !Objects.equals(actor(), string(sandbox.get("created_by")))) {
            throw new SecurityException("沙箱仅创建人可设置数据控制");
        }
    }

    private Map<String, Object> requireRow(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        if (rows.isEmpty()) throw new IllegalArgumentException("记录不存在");
        return new LinkedHashMap<>(rows.get(0));
    }

    private String nodeId() {
        UserContextDTO user = UserContext.getUserOrNotExist();
        if (user == null) return "kuscia-system";
        return user.getPlatformNodeId() != null && !user.getPlatformNodeId().isBlank()
                ? user.getPlatformNodeId() : ownerId();
    }

    private String ownerId() {
        UserContextDTO user = UserContext.getUserOrNotExist();
        return user == null ? "" : string(user.getOwnerId());
    }

    private String actor() {
        UserContextDTO user = UserContext.getUserOrNotExist();
        return user == null || user.getName() == null ? "system" : user.getName();
    }

    private static String sanitize(String value) { return value.replaceAll("[^a-zA-Z0-9_]", "_"); }
    private static String required(Map<String, Object> request, String key) {
        String value = string(request.get(key));
        if (value.isBlank()) throw new IllegalArgumentException(key + " 不能为空");
        return value;
    }
    private static String string(Object value) { return value == null ? "" : String.valueOf(value); }
    private static String now() { return LocalDateTime.now().toString(); }
    private static int intValue(Object value, int fallback) {
        if (value instanceof Number number) return number.intValue();
        try { return value == null || String.valueOf(value).isBlank() ? fallback : Integer.parseInt(String.valueOf(value)); }
        catch (NumberFormatException ignored) { return fallback; }
    }
    private static boolean bool(Object value, boolean fallback) {
        if (value == null) return fallback;
        if (value instanceof Boolean bool) return bool;
        if (value instanceof Number number) return number.intValue() != 0;
        String text = String.valueOf(value).trim();
        return text.isBlank() ? fallback : "true".equalsIgnoreCase(text) || "1".equals(text);
    }

    private record ResultPolicy(String viewUntil, boolean allowExport, String exportUntil) {}
}
