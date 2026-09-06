/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

/** 将密文对象关联到真实任务来源，并统一返回带时区的业务期限。 */
@Service
public class TeeResultMetadataService {
    private static final ZoneId DISPLAY_ZONE = ZoneId.of("Asia/Shanghai");
    private final JdbcTemplate jdbc;

    public TeeResultMetadataService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Metadata resolve(TeeObjectDO object) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select t.id,t.name task_name,t.sandbox_id,coalesce(nullif(t.project_id,''),s.project_id) project_id,t.finished_at,t.created_at,"
                        + "t.result_view_until,t.result_export_until,s.name sandbox_name,s.expires_at,"
                        + "p.name project_name,nr.run_id,c.name canvas_name "
                        + "from ds_dev_task t left join ds_sandbox s on s.id=t.sandbox_id "
                        + "left join project p on p.project_id=coalesce(nullif(t.project_id,''),s.project_id) "
                        + "left join ds_compute_node_run nr on nr.task_id=t.id "
                        + "left join ds_compute_canvas c on c.id=nr.canvas_id "
                        + "where t.id=? order by nr.created_at desc limit 1", object.getTaskId());
        String createdAt = object.getGmtCreate() == null ? "" : object.getGmtCreate().toInstant(ZoneOffset.UTC).toString();
        String identifier = text(object.getResultId());
        if (identifier.isBlank() && object.getUpk() != null) identifier = text(object.getUpk().getObjectId());
        String suffix = identifier.isBlank() ? "" : " · " + identifier.substring(0, Math.min(12, identifier.length()));
        String kind = switch (text(object.getKind())) {
            case "MODEL" -> "模型";
            case "REPORT" -> "报告";
            case "DATA" -> "数据";
            default -> "未知类型";
        };
        if (rows.isEmpty()) {
            return new Metadata("历史" + kind + "结果（来源信息不完整）" + suffix,
                    "", "", "", "", "", "", createdAt, "", "");
        }
        Map<String, Object> row = rows.get(0);
        String taskName = text(row.get("task_name"));
        String resultName = (taskName.isBlank() ? "未命名任务" : taskName) + " · " + kind + suffix;
        String viewUntil = earliest(row.get("result_view_until"), row.get("expires_at"));
        String maxExportUntil = earliest(row.get("result_export_until"), viewUntil);
        String finishedAt = text(row.get("finished_at"));
        if (!finishedAt.isBlank()) createdAt = earliest(finishedAt);
        String runId = text(row.get("run_id"));
        if (runId.isBlank()) runId = text(row.get("id"));
        return new Metadata(resultName, text(row.get("project_id")), text(row.get("project_name")),
                text(row.get("sandbox_id")), text(row.get("sandbox_name")), taskName, runId,
                createdAt, viewUntil, maxExportUntil);
    }

    /** ds 历史无时区时间按北京时间解释；输出统一为 UTC Instant。 */
    public static String earliest(Object... values) {
        Instant earliest = null;
        for (Object value : values) {
            String text = text(value).trim();
            if (text.isBlank() || "null".equalsIgnoreCase(text)) continue;
            Instant parsed;
            try {
                parsed = OffsetDateTime.parse(text).toInstant();
            } catch (RuntimeException ignored) {
                try {
                    parsed = LocalDateTime.parse(text.replace(' ', 'T')).atZone(DISPLAY_ZONE).toInstant();
                } catch (RuntimeException malformed) {
                    // 无法解释的历史期限按失效处理，避免开放访问或阻断整页查询。
                    parsed = Instant.EPOCH;
                }
            }
            if (earliest == null || parsed.isBefore(earliest)) earliest = parsed;
        }
        return earliest == null ? "" : earliest.toString();
    }

    private static String text(Object value) { return value == null ? "" : String.valueOf(value); }

    public record Metadata(String resultName, String projectId, String projectName, String sandboxId,
                           String sandboxName, String taskName, String runId, String createdAt,
                           String viewUntil, String maxExportUntil) { }
}
