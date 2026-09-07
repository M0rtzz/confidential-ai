/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.dev;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.SandboxDataControlService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.secretflow.secretpad.web.service.tee.TeeModelReportAccess;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class DataDevResultExpiryTest {
    @Test
    void expiredTaskDetailHidesReportsAndKeepsEncryptedMetadata() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        SandboxDataControlService control = mock(SandboxDataControlService.class);
        DataDevService service = new DataDevService(jdbc, new ObjectMapper(), null, null, null, null, null, null, control, null);
        TeeModelReportAccess reportAccess = mock(TeeModelReportAccess.class);
        ReflectionTestUtils.setField(service, "modelReportAccess", reportAccess);
        Map<String, Object> task = Map.of("id", "task-1", "result_preview",
                "{\"reports\":[{\"secret\":123}],\"encryptedOutputs\":[{\"resultId\":\"result-1\"}]}");
        when(jdbc.queryForList("select * from ds_dev_task where id=? and deleted=0", "task-1"))
                .thenReturn(List.of(task));
        doThrow(new SecurityException("开发结果已超过查看截止时间")).when(control).requireTaskResultView(task);
        Map<String, Object> result = service.taskDetail("task-1");
        assertThat(result).containsEntry("resultViewAllowed", false)
                .containsEntry("disabledReason", "开发结果已超过查看截止时间")
                .doesNotContainKey("result_preview");
        assertThat(result.get("reports")).asList().isEmpty();
        assertThat(result.get("encryptedOutputs")).asList().hasSize(1);
        verify(reportAccess).requireReportRead("task-1");
    }
}
