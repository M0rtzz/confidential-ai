/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.web.service.DataAssetService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

/** 用独立内存数据库复现两个挂载副本分别为空、过期时的同步及重复执行。 */
class TeeDeadlineSynchronizerTest {
    @Test
    void bothMountsFollowProviderDeadlineAndRepeatedSyncDoesNotRewrite() throws Exception {
        try (var connection = java.sql.DriverManager.getConnection("jdbc:sqlite::memory:")) {
            JdbcTemplate jdbc = new JdbcTemplate(new SingleConnectionDataSource(connection, true));
            jdbc.execute("create table ds_sandbox(id text,project_id text,deleted integer)");
            jdbc.execute("create table ds_sandbox_dataset_mount(id text,asset_id text,sandbox_id text,expires_at text,updated_at text,deleted integer,status text)");
            jdbc.execute("create table ds_asset_usage_control(asset_id text,valid_until text)");
            jdbc.execute("create table ds_project_asset(project_id text,asset_id text,asset_json text,expires_at text,deleted integer,is_deleted integer)");
            jdbc.update("insert into ds_sandbox values('sandbox','project',0)");
            String snapshot = "{\"control_valid_until\":\"2026-09-29T16:00:00.000Z\",\"valid_until\":null}";
            for (String asset : new String[]{"asset-a", "asset-b"}) {
                jdbc.update("insert into ds_sandbox_dataset_mount values(?,?, 'sandbox',?,'before',0,'READY')",
                        asset, asset, asset.equals("asset-a") ? "" : "2026-09-05T12:00:00Z");
                jdbc.update("insert into ds_project_asset values('project',?,?,?,0,0)",
                        asset, snapshot, "2026-09-29T16:00:00.000Z");
            }
            TeeDeadlineSynchronizer sync = new TeeDeadlineSynchronizer(jdbc, new ObjectMapper(),
                    mock(DataAssetService.class), mock(TeeAssetRepository.class), mock(TeePolicyService.class));
            sync.synchronize();
            assertEquals(2, jdbc.queryForObject("select count(*) from ds_sandbox_dataset_mount where expires_at='2026-09-29T16:00:00Z'", Integer.class));
            jdbc.update("update ds_sandbox_dataset_mount set updated_at='unchanged'");
            sync.synchronize();
            assertEquals(2, jdbc.queryForObject("select count(*) from ds_sandbox_dataset_mount where updated_at='unchanged'", Integer.class));
            jdbc.update("update ds_project_asset set asset_json=? where asset_id='asset-a'",
                    "{\"control_valid_until\":\"2026-09-10T16:00:00Z\"}");
            sync.synchronize();
            assertEquals("2026-09-10T16:00:00Z", jdbc.queryForObject("select expires_at from ds_sandbox_dataset_mount where asset_id='asset-a'", String.class));
            assertEquals("2026-09-29T16:00:00Z", jdbc.queryForObject("select expires_at from ds_sandbox_dataset_mount where asset_id='asset-b'", String.class));
        }
    }
}
