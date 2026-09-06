/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SandboxDataControlTimeTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final SandboxDataControlService service = new SandboxDataControlService(jdbc, new ObjectMapper());

    @Test
    void deniesExpiredTeeTaskWithoutPlaintextTable() {
        assertThatThrownBy(() -> service.requireTaskResultView(Map.of(
                "sandbox_id", "sandbox-1", "result_view_until", "2020-01-01T08:00:00")))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void deniesMalformedHistoricalTeeDeadline() {
        assertThatThrownBy(() -> service.requireTaskResultView(Map.of(
                "sandbox_id", "sandbox-1", "result_view_until", "invalid-date")))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void deniesTeeResultWhenSandboxExpiresBeforeTask() {
        when(jdbc.queryForList("select expires_at from ds_sandbox where id=?", "sandbox-1"))
                .thenReturn(List.of(Map.of("expires_at", "2020-01-01T00:00:00Z")));
        assertThatThrownBy(() -> service.requireTaskResultView(Map.of(
                "sandbox_id", "sandbox-1", "result_view_until", "2099-01-01T00:00:00Z")))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void mountDirectoryAndExecutionShareEarliestEffectiveDeadline() {
        when(jdbc.queryForList("select expires_at from ds_sandbox where id=?", "sandbox-1"))
                .thenReturn(List.of(Map.of("expires_at", "2099-01-01T00:00:00Z")));
        when(jdbc.queryForList(startsWith("select allow_use,use_until,version"), eq("sandbox-1"), eq("asset-1")))
                .thenReturn(List.of(Map.of("allow_use", 1, "use_until", "2098-01-01T00:00:00Z")));
        when(jdbc.queryForList(startsWith("select access_start,access_end,valid_from,valid_until"), eq("asset-1")))
                .thenReturn(List.of(Map.of("valid_until", "2020-01-01T08:00:00")));
        Map<String, Object> directory = new LinkedHashMap<>(Map.of("sandboxId", "sandbox-1", "items",
                List.of(Map.of("kind", "MOUNT", "assetId", "asset-1", "tableName", "data"))));
        service.enrichDirectory(directory);
        Map<?, ?> item = (Map<?, ?>) ((List<?>) directory.get("items")).get(0);
        assertThat(item.get("use_until")).isEqualTo("2020-01-01T00:00:00Z");
        assertThat(item.get("canUse")).isEqualTo(false);
        assertThat(item.get("canPreview")).isEqualTo(false);
        assertThat(Instant.parse(String.valueOf(directory.get("serverTime")))).isNotNull();
        assertThatThrownBy(() -> service.requireMountAssetUsable("sandbox-1", "asset-1"))
                .isInstanceOf(SecurityException.class);
    }
}
