/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.secretflow.secretpad.web.service.canvas.CanvasOperatorRegistry;
import org.secretflow.secretpad.web.service.canvas.SandboxCanvasService;
import org.secretflow.secretpad.web.service.dev.TeeDevTaskDispatcher;
import org.secretflow.secretpad.web.service.sandbox.SandboxApprovalService;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.util.ReflectionTestUtils;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 验证新上传资产、跨节点资产与画布中间结果的字段授权保持一致。 */
class TeeColumnFlowTest {
    private SingleConnectionDataSource database;
    private JdbcTemplate jdbc;
    private SandboxApprovalService approvals;
    private SandboxCanvasService canvas;

    @BeforeEach
    void setUp() {
        database = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        jdbc = new JdbcTemplate(database);
        jdbc.execute("create table ds_data_asset(id text,deleted integer default 0)");
        jdbc.execute("create table ds_asset_usage_control(asset_id text,valid_from text,valid_until text,access_start text,access_end text)");
        jdbc.execute("create table ds_node_dataset(asset_id text,table_columns_json text,updated_at text,deleted integer default 0)");
        jdbc.execute("create table ds_project_asset(project_id text,asset_id text,asset_json text,provider_node_id text,deleted integer default 0,is_deleted integer default 0)");
        jdbc.execute("create table tee_runtime_task(task_id text,task_jws text,status text,receipt_verified integer,is_deleted integer default 0)");
        approvals = mock(SandboxApprovalService.class, CALLS_REAL_METHODS);
        ReflectionTestUtils.setField(approvals, "jdbc", jdbc);
        ReflectionTestUtils.setField(approvals, "objectMapper", new ObjectMapper());
        canvas = mock(SandboxCanvasService.class, CALLS_REAL_METHODS);
        ReflectionTestUtils.setField(canvas, "jdbc", jdbc);
        ReflectionTestUtils.setField(canvas, "mapper", new ObjectMapper());
    }

    @AfterEach
    void tearDown() { database.destroy(); }

    @Test
    void newUploadUsesActualNodeColumnsAndUnionsRemoteColumns() {
        jdbc.update("insert into ds_data_asset(id) values('new-upload')");
        jdbc.update("insert into ds_node_dataset(asset_id,table_columns_json) values(?,?)",
                "new-upload", "[\"age\",\"annual_income\",\"is_default\"]");
        jdbc.update("insert into ds_project_asset(project_id,asset_id,asset_json,provider_node_id) values(?,?,?,?)",
                "project-1", "remote", "{\"schema_columns\":[\"age\",\"tenure_months\"]}", "node-b");
        assertEquals(List.of("age", "annual_income", "is_default", "tenure_months"),
                approvedColumns(List.of("new-upload", "remote")));
    }

    @Test
    void missingUploadSchemaCannotSilentlyReduceApproval() {
        jdbc.update("insert into ds_data_asset(id) values('new-upload')");
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> approvedColumns(List.of("new-upload")));
        assertTrue(failure.getMessage().contains("new-upload"));
    }

    @Test
    void corruptUploadSchemaCannotBecomeAnApprovalColumn() {
        jdbc.update("insert into ds_data_asset(id) values('new-upload')");
        jdbc.update("insert into ds_node_dataset(asset_id,table_columns_json) values('new-upload','not-json')");
        assertThrows(IllegalArgumentException.class, () -> approvedColumns(List.of("new-upload")));
    }

    @Test
    void intermediateSchemaUsesExecutedColumnsInsteadOfOriginalFullSchema() {
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"columns\":[\"age\",\"is_default\"]}".getBytes(StandardCharsets.UTF_8));
        jdbc.update("insert into tee_runtime_task(task_id,task_jws,status,receipt_verified) values(?,?,?,?)",
                "task-1", "header." + payload + ".signature", "SUCCEEDED", 1);
        List<String> actual = ReflectionTestUtils.invokeMethod(canvas, "executedInputColumns", "task-1");
        assertEquals(List.of("age", "is_default"),
                CanvasOperatorRegistry.outputColumns("preprocessing.standardize", Map.of(), actual));
        assertFalse(actual.contains("annual_income"));
    }

    @Test
    void unverifiedTaskCannotSupplyIntermediateSchema() {
        jdbc.update("insert into tee_runtime_task(task_id,task_jws,status,receipt_verified) values('task-1','invalid','SUCCEEDED',0)");
        assertThrows(IllegalStateException.class,
                () -> ReflectionTestUtils.invokeMethod(canvas, "executedInputColumns", "task-1"));
    }

    @Test
    void dnnReportsMissingFeatureAndLabelBeforeDispatch() {
        TeeException failure = assertThrows(TeeException.class, () -> checkParameters(
                Map.of("features", List.of("age", "annual_income"), "label", "is_default"), List.of("age")));
        assertTrue(failure.getMessage().contains("annual_income"));
        assertTrue(failure.getMessage().contains("is_default"));
        assertDoesNotThrow(() -> checkParameters(
                Map.of("features", List.of("age", "annual_income"), "label", "is_default"),
                List.of("age", "annual_income", "is_default")));
    }

    @Test
    void standardizeRejectsUnavailableConfiguredColumn() {
        assertThrows(TeeException.class, () -> checkParameters(Map.of("columns", "age,balance"), List.of("age")));
        assertDoesNotThrow(() -> checkParameters(Map.of("columns", List.of()), List.of("age")));
    }

    private List<String> approvedColumns(List<String> assetIds) {
        return ReflectionTestUtils.invokeMethod(approvals, "approvedColumns", "project-1", assetIds);
    }

    private void checkParameters(Map<String, Object> params, List<String> columns) {
        ReflectionTestUtils.invokeMethod(TeeDevTaskDispatcher.class, "requireAuthorizedParameters", params, columns);
    }
}
