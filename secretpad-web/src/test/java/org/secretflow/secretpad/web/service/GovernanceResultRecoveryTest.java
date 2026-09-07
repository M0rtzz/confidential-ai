/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.kuscia.v1alpha1.service.impl.KusciaGrpcClientAdapter;
import org.secretflow.secretpad.web.service.governance.GovernanceCustomExecutor;
import org.secretflow.secretpad.web.service.storage.NodeDatasetStore;
import org.secretflow.secretpad.web.service.tee.TeeAssetEncryptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.util.ReflectionTestUtils;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** 覆盖后台无登录上下文的结果回收与异常收敛。 */
class GovernanceResultRecoveryTest {
    private SingleConnectionDataSource database;
    private JdbcTemplate jdbc;
    private TeeAssetEncryptor encryptor;
    private NodeDatasetStore datasets;
    private MinioAssetStorage storage;
    private DataAssetService assets;
    private final byte[] csv = "id\n1\n".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        UserContext.remove();
        database = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        jdbc = new JdbcTemplate(database);
        jdbc.execute("create table node(node_id text,inst_id text,is_deleted integer default 0)");
        jdbc.execute("create table ds_governance_task(id text,name text,source_datatable_id text,source_node_id text,"
                + "exec_params text,created_by text,status text,error_message text,finished_at text,updated_at text,deleted integer default 0)");
        jdbc.execute("create table ds_data_asset(id text,name text,provider_node_id text,processor_node_id text,"
                + "ingestion_type text,modality text,data_stage text,source_asset_id text,datatable_id text,storage_uri text,"
                + "metadata_json text,sampling_method text,masking_json text,created_by text,created_at text,updated_at text,"
                + "version integer,status text,deleted integer default 0)");
        jdbc.update("insert into node(node_id,inst_id) values('node-a','inst-a')");
        jdbc.update("insert into ds_data_asset(id,datatable_id,provider_node_id) values('source','source','node-a')");
        jdbc.update("insert into ds_governance_task(id,name,source_datatable_id,source_node_id,exec_params,created_by,status) "
                + "values('task-1','任务','source','node-a','{}','operator','RUNNING')");
        encryptor = mock(TeeAssetEncryptor.class);
        datasets = mock(NodeDatasetStore.class);
        storage = mock(MinioAssetStorage.class);
        assets = new DataAssetService(jdbc, new ObjectMapper(), storage, null, null, datasets, null, encryptor);
        when(encryptor.available()).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        UserContext.remove();
        database.destroy();
    }

    @Test
    void recoversInstitutionAndStoresEncryptedResultWithoutLogin() throws Exception {
        when(encryptor.seal(eq("inst-a"), anyString(), eq("1"), eq(csv)))
                .thenReturn(new TeeAssetEncryptor.Sealed(null, "sealed".getBytes(StandardCharsets.UTF_8), "key-1", "1", "hash"));
        when(storage.put(anyString(), any(), eq("application/json"), anyString())).thenReturn("s3://governed/result.enc");
        assertNull(UserContext.getUserOrNotExist());
        Map<String, Object> result = assets.registerGovernedResult("task-1", "node-a", csv);
        assertEquals("node-a", result.get("provider_node_id"));
        assertEquals("s3://governed/result.enc", result.get("storage_uri"));
        assertTrue(new ObjectMapper().readTree((String) result.get("metadata_json")).get("encrypted").asBoolean());
        verify(encryptor).seal(eq("inst-a"), eq((String) result.get("id")), eq("1"), eq(csv));
        verify(datasets).materializeExternal(eq((String) result.get("id")), eq("node-a"), eq((String) result.get("id")), anyList(), anyList(), anyString());
    }

    @Test
    void missingOrAmbiguousInstitutionFailsBeforeWritingResults() {
        jdbc.update("delete from node");
        assertThrows(DataAssetService.GovernanceResultIdentityException.class,
                () -> assets.registerGovernedResult("task-1", "node-a", csv));
        jdbc.update("insert into node(node_id,inst_id) values('node-a','inst-a'),('node-a','inst-b')");
        assertThrows(DataAssetService.GovernanceResultIdentityException.class,
                () -> assets.registerGovernedResult("task-1", "node-a", csv));
        verifyNoInteractions(storage, datasets);
        verify(encryptor, never()).seal(anyString(), anyString(), anyString(), any());
    }

    @Test
    void permanentIdentityFailureEndsTaskAndPreservesCancellation() {
        jdbc.update("delete from node");
        GovernanceCustomExecutor executor = executor(assets);
        complete(executor);
        assertEquals("FAILED", status());
        assertTrue(jdbc.queryForObject("select error_message from ds_governance_task", String.class).contains("未关联唯一机构"));
        jdbc.update("update ds_governance_task set status='CANCELED'");
        complete(executor);
        assertEquals("CANCELED", status());
    }

    @Test
    void transientSaveFailureRemainsRetryable() {
        DataAssetService failingAssets = mock(DataAssetService.class);
        when(failingAssets.registerGovernedResult(eq("task-1"), eq("node-a"), any(byte[].class)))
                .thenThrow(new IllegalStateException("暂时无法访问密钥服务"));
        assertThrows(IllegalStateException.class, () -> complete(executor(failingAssets)));
        assertEquals("RUNNING", status());
    }

    private GovernanceCustomExecutor executor(DataAssetService service) {
        return new GovernanceCustomExecutor(jdbc, new ObjectMapper(), mock(KusciaGrpcClientAdapter.class),
                mock(DataSandboxMvpService.class), service);
    }

    private void complete(GovernanceCustomExecutor executor) {
        ReflectionTestUtils.invokeMethod(executor, "completeSuccess",
                jdbc.queryForMap("select * from ds_governance_task where id='task-1'"), "job-1", csv);
    }

    private String status() {
        return jdbc.queryForObject("select status from ds_governance_task where id='task-1'", String.class);
    }
}
