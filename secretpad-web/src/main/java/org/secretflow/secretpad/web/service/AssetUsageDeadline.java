/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** 数据使用截止时间的统一解析与来源选择；挂载期限只是此值的副本。 */
public final class AssetUsageDeadline {
    private static final ZoneId PLATFORM_ZONE = ZoneId.of("Asia/Shanghai");

    private AssetUsageDeadline() {
    }

    /** found 区分尚未同步的数据与供数方明确未设置截止时间。 */
    public record Deadline(boolean found, Instant expiresAt) {
        public String value() {
            return expiresAt == null ? "" : expiresAt.toString();
        }
    }

    /** 本方管控优先；跨节点按当前项目的供数方快照读取，不能混用其他项目的旧快照。 */
    public static Deadline resolve(JdbcTemplate jdbc, ObjectMapper mapper, String projectId, String assetId) {
        List<Map<String, Object>> controls = jdbc.queryForList(
                "select valid_until from ds_asset_usage_control where asset_id=?", assetId);
        if (!controls.isEmpty()) {
            return new Deadline(true, parse(controls.get(0).get("valid_until")));
        }
        if (projectId != null && !projectId.isBlank()) {
            List<Map<String, Object>> snapshots = jdbc.queryForList(
                    "select asset_json,expires_at from ds_project_asset where project_id=? and asset_id=? "
                            + "and deleted=0 and coalesce(is_deleted,0)=0", projectId, assetId);
            if (!snapshots.isEmpty()) {
                Map<String, Object> row = snapshots.get(0);
                try {
                    JsonNode asset = mapper.readTree(Objects.toString(row.get("asset_json"), "{}"));
                    if (asset != null && asset.has("control_valid_until")) {
                        return new Deadline(true, parse(asset.path("control_valid_until").asText("")));
                    }
                    if (asset != null && asset.has("valid_until")) {
                        return new Deadline(true, parse(asset.path("valid_until").asText("")));
                    }
                    return new Deadline(true, parse(row.get("expires_at")));
                } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) {
                    throw new IllegalArgumentException("数据使用期限快照无法解析，请等待供数方重新同步", invalid);
                }
            }
        }
        List<Map<String, Object>> assets = jdbc.queryForList(
                "select valid_until from ds_data_asset where id=? and deleted=0", assetId);
        return assets.isEmpty() ? new Deadline(false, null)
                : new Deadline(true, parse(assets.get(0).get("valid_until")));
    }

    /** 日期选择表示当天可用；具体时分保留原值，截止瞬间起禁止使用。空值不添加额外限制。 */
    public static Instant parse(Object value) {
        String text = Objects.toString(value, "").trim();
        if (text.isEmpty() || "null".equalsIgnoreCase(text)) {
            return null;
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (DateTimeParseException notOffset) {
            try {
                return LocalDateTime.parse(text).atZone(PLATFORM_ZONE).toInstant();
            } catch (DateTimeParseException notLocalTime) {
                try {
                    return LocalDate.parse(text).plusDays(1).atStartOfDay(PLATFORM_ZONE).toInstant();
                } catch (DateTimeParseException invalid) {
                    throw new IllegalArgumentException("使用截止时间格式无效: " + text, invalid);
                }
            }
        }
    }

    public static Instant earlier(Instant left, Instant right) {
        return left == null ? right : right == null || left.isBefore(right) ? left : right;
    }
}
