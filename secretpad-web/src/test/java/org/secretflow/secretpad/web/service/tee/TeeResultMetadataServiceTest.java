/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TeeResultMetadataServiceTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final TeeResultMetadataService service = new TeeResultMetadataService(jdbc);

    @Test
    void resolvesRealTaskAndCapsExportByViewAndSandbox() {
        when(jdbc.queryForList(anyString(), eq("task-1"))).thenReturn(List.of(Map.ofEntries(
                Map.entry("id", "task-1"), Map.entry("task_name", "联合统计"), Map.entry("sandbox_id", "sandbox-1"),
                Map.entry("project_id", "project-1"), Map.entry("sandbox_name", "统计沙箱"),
                Map.entry("project_name", "项目一"), Map.entry("run_id", "run-1"),
                Map.entry("finished_at", "2026-09-06T16:00:00"),
                Map.entry("result_view_until", "2026-09-07T16:00:00"),
                Map.entry("result_export_until", "2026-09-09T00:00:00Z"),
                Map.entry("expires_at", "2026-09-07T00:00:00Z"))));
        TeeResultMetadataService.Metadata metadata = service.resolve(object());
        assertThat(metadata.resultName()).contains("联合统计", "数据", "result-1");
        assertThat(metadata.runId()).isEqualTo("run-1");
        assertThat(metadata.createdAt()).isEqualTo("2026-09-06T08:00:00Z");
        assertThat(metadata.viewUntil()).isEqualTo("2026-09-07T00:00:00Z");
        assertThat(metadata.maxExportUntil()).isEqualTo(metadata.viewUntil());
    }

    @Test
    void missingHistoricalSourceDoesNotInventDeadlineAndKeepsJpaUtcTime() {
        TeeObjectDO object = object();
        object.setGmtCreate(LocalDateTime.of(2026, 9, 6, 8, 0));
        TeeResultMetadataService.Metadata metadata = service.resolve(object);
        assertThat(metadata.resultName()).contains("来源信息不完整");
        assertThat(metadata.viewUntil()).isEmpty();
        assertThat(metadata.maxExportUntil()).isEmpty();
        assertThat(metadata.createdAt()).isEqualTo("2026-09-06T08:00:00Z");
    }

    @Test
    void malformedHistoricalDeadlineFailsClosedWithoutBreakingList() {
        assertThat(TeeResultMetadataService.earliest("not-a-date", "2099-01-01T00:00:00Z"))
                .isEqualTo("1970-01-01T00:00:00Z");
    }

    private TeeObjectDO object() {
        return TeeObjectDO.builder().taskId("task-1").resultId("result-1").kind("DATA").build();
    }
}
