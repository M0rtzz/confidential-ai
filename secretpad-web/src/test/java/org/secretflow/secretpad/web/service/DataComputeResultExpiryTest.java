/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.sandbox.SandboxApprovalService;
import org.secretflow.secretpad.web.service.storage.SandboxDbService;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DataComputeResultExpiryTest {
    @Test
    void reportListDoesNotExposeExpiredTaskPayload() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        SandboxDataControlService control = mock(SandboxDataControlService.class);
        DataComputeService service = new DataComputeService(jdbc, new ObjectMapper(),
                mock(SandboxApprovalService.class), mock(DataAssetService.class), mock(SandboxDbService.class), control);
        when(jdbc.queryForList("select * from ds_sandbox where id=? and deleted=0", "sandbox-1"))
                .thenReturn(List.of(Map.of("id", "sandbox-1", "project_id", "project-1")));
        when(jdbc.queryForObject(anyString(), eq(Long.class), eq("project-1"), eq("kuscia-system"))).thenReturn(1L);
        Map<String, Object> task = Map.of("id", "task-1", "result_preview", "{\"secret\":123}");
        when(jdbc.queryForList(startsWith("select t.*,nr.run_id canvas_run_id"), eq("sandbox-1")))
                .thenReturn(List.of(task));
        doThrow(new SecurityException("开发结果已超过查看截止时间")).when(control).requireTaskResultView(task);
        assertThat(service.reports("sandbox-1", "PROGRAM_RESULT")).isEmpty();
    }
}
