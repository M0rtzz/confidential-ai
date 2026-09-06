/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 数据使用期限解析及来源优先级测试。 */
class AssetUsageDeadlineTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PROJECT = "project-1";
    private static final String ASSET = "asset-1";

    @Test
    void dateDeadlineStartsAtNextDayMidnightInPlatformTimezone() {
        assertEquals(Instant.parse("2026-09-30T16:00:00Z"),
                AssetUsageDeadline.parse("2026-09-30"));
    }

    @Test
    void utcAndLocalDateTimeRepresentTheSameInstant() {
        Instant utc = AssetUsageDeadline.parse("2026-09-30T16:00:00Z");
        Instant local = AssetUsageDeadline.parse("2026-10-01T00:00:00");

        assertEquals(utc, local);
    }

    @Test
    void nonEmptyInvalidDateIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> AssetUsageDeadline.parse("2026-09-30T-not-a-time"));
    }

    @Test
    void emptyOrNullValueAddsNoDeadline() {
        assertNull(AssetUsageDeadline.parse(null));
        assertNull(AssetUsageDeadline.parse(""));
        assertNull(AssetUsageDeadline.parse("  "));
        assertNull(AssetUsageDeadline.parse("null"));
    }

    @Test
    void localUsageControlTakesPriority() {
        FakeJdbcTemplate jdbc = new FakeJdbcTemplate()
                .rows("ds_asset_usage_control", List.of(Map.of(
                        "valid_until", "2026-09-30T16:00:00Z")))
                .rows("ds_project_asset", List.of(Map.of(
                        "asset_json", "{\"control_valid_until\":\"2027-01-01\"}",
                        "expires_at", "2025-01-01")));

        AssetUsageDeadline.Deadline deadline = AssetUsageDeadline.resolve(
                jdbc, MAPPER, PROJECT, ASSET);

        assertTrue(deadline.found());
        assertEquals(Instant.parse("2026-09-30T16:00:00Z"), deadline.expiresAt());
    }

    @Test
    void projectSnapshotControlDeadlineTakesPriorityOverBaseAndAttachmentDeadline() {
        FakeJdbcTemplate jdbc = new FakeJdbcTemplate()
                .rows("ds_project_asset", List.of(Map.of(
                        "asset_json", "{\"control_valid_until\":\"2026-09-30T16:00:00Z\","
                                + "\"valid_until\":\"2027-01-01\"}",
                        "expires_at", "2025-01-01")))
                .rows("ds_data_asset", List.of(Map.of(
                        "valid_until", "2024-01-01")));

        AssetUsageDeadline.Deadline deadline = AssetUsageDeadline.resolve(
                jdbc, MAPPER, PROJECT, ASSET);

        assertTrue(deadline.found());
        assertEquals(Instant.parse("2026-09-30T16:00:00Z"), deadline.expiresAt());
    }

    @Test
    void noAvailableSourceReportsNotFound() {
        AssetUsageDeadline.Deadline deadline = AssetUsageDeadline.resolve(
                new FakeJdbcTemplate(), MAPPER, PROJECT, ASSET);

        assertFalse(deadline.found());
        assertNull(deadline.expiresAt());
        assertEquals("", deadline.value());
    }

    /** 按表名返回预置行，避免单元测试连接真实数据库。 */
    private static final class FakeJdbcTemplate extends JdbcTemplate {
        private final Map<String, List<Map<String, Object>>> rows = new HashMap<>();

        FakeJdbcTemplate rows(String table, List<Map<String, Object>> tableRows) {
            rows.put(table, tableRows);
            return this;
        }

        @Override
        public List<Map<String, Object>> queryForList(String sql, Object... args) {
            for (Map.Entry<String, List<Map<String, Object>>> entry : rows.entrySet()) {
                if (sql.contains(entry.getKey())) {
                    return entry.getValue();
                }
            }
            return List.of();
        }
    }
}
