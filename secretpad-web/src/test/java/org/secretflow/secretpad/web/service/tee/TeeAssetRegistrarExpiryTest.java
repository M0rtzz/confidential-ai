/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 供数端登记密文资产时，期限来源选择与拒绝条件测试。 */
class TeeAssetRegistrarExpiryTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PROJECT = "project-1";
    private static final String SANDBOX = "sandbox-1";

    @Test
    void missingLocalSandboxUsesEarlierApprovalAndAssetDeadlineWithExactTime() {
        FakeJdbcTemplate jdbc = new FakeJdbcTemplate()
                .usage("asset-a", "2099-09-30T17:45:00Z");
        TeeAssetRegistrarImpl registrar = registrar(jdbc);
        JsonNode approval = json("{\"projectId\":\"" + PROJECT
                + "\",\"expiresAt\":\"2099-09-30T16:35:45Z\"}");

        String expiry = registrar.expiry(approval, SANDBOX, "asset-a");

        assertEquals("2099-09-30T16:35:45Z", expiry);
    }

    @Test
    void assetDeadlinesDoNotLeakAcrossAssets() {
        FakeJdbcTemplate jdbc = new FakeJdbcTemplate()
                .usage("asset-a", "2099-09-30T09:10:11Z")
                .usage("asset-b", "2099-10-15T12:13:14Z");
        TeeAssetRegistrarImpl registrar = registrar(jdbc);
        JsonNode approval = json("{\"projectId\":\"" + PROJECT
                + "\",\"expiresAt\":\"2099-12-31T00:00:00Z\"}");

        assertEquals("2099-09-30T09:10:11Z", registrar.expiry(approval, SANDBOX, "asset-a"));
        assertEquals("2099-10-15T12:13:14Z", registrar.expiry(approval, SANDBOX, "asset-b"));
    }

    @Test
    void dataChangeWithoutExpiryFallsBackToCompletedCreateOrRenewApproval() {
        FakeJdbcTemplate jdbc = new FakeJdbcTemplate()
                .completedSandboxApproval("{\"expiresAt\":\"2099-11-05T06:07:08Z\"}");
        TeeAssetRegistrarImpl registrar = registrar(jdbc);
        JsonNode dataChange = json("{\"projectId\":\"" + PROJECT
                + "\",\"approvalType\":\"DATA_CHANGE\"}");

        assertEquals("2099-11-05T06:07:08Z", registrar.expiry(dataChange, SANDBOX, "asset-a"));
    }

    @Test
    void unknownDeadlineIsRejectedWithoutOneDayDefault() {
        TeeAssetRegistrarImpl registrar = registrar(new FakeJdbcTemplate());
        JsonNode approval = json("{\"projectId\":\"" + PROJECT + "\"}");

        TeeException refused = assertThrows(TeeException.class,
                () -> registrar.expiry(approval, SANDBOX, "asset-a"));

        assertEquals(TeeContract.Error.POLICY_DENIED, refused.error());
    }

    @Test
    void invalidExpiryDateIsRejected() {
        TeeAssetRegistrarImpl registrar = registrar(new FakeJdbcTemplate());
        JsonNode approval = json("{\"projectId\":\"" + PROJECT
                + "\",\"expiresAt\":\"2099-09-30T-not-a-time\"}");

        assertThrows(IllegalArgumentException.class,
                () -> registrar.expiry(approval, SANDBOX, "asset-a"));
    }

    private static TeeAssetRegistrarImpl registrar(FakeJdbcTemplate jdbc) {
        // expiry 只读取数据库与审批 JSON，不调用存储和网关；传入惰性依赖避免启动真实外部服务。
        MinioAssetStorage storage = new MinioAssetStorage(
                "http://127.0.0.1:9000", "test-access", "test-secret", "test-bucket");
        TeeKeyGateway keyGateway = new TeeKeyGateway(null, null, null, null, null, null, null);
        return new TeeAssetRegistrarImpl(jdbc, MAPPER, storage, keyGateway);
    }

    private static JsonNode json(String value) {
        try {
            return MAPPER.readTree(value);
        } catch (Exception invalid) {
            throw new AssertionError(invalid);
        }
    }

    /** 按查询表和 assetId 返回预置行，测试过程中不访问真实数据库或对象存储。 */
    private static final class FakeJdbcTemplate extends JdbcTemplate {
        private final Map<String, List<Map<String, Object>>> usageByAsset = new HashMap<>();
        private List<Map<String, Object>> sandboxApprovals = List.of();

        FakeJdbcTemplate usage(String assetId, String validUntil) {
            usageByAsset.put(assetId, List.of(Map.of("valid_until", validUntil)));
            return this;
        }

        FakeJdbcTemplate completedSandboxApproval(String payload) {
            sandboxApprovals = List.of(Map.of("payload_json", payload));
            return this;
        }

        @Override
        public List<Map<String, Object>> queryForList(String sql, Object... args) {
            if (sql.contains("from ds_sandbox ")) {
                return List.of();
            }
            if (sql.contains("ds_asset_usage_control")) {
                String assetId = args.length == 0 ? "" : String.valueOf(args[0]);
                return usageByAsset.getOrDefault(assetId, List.of());
            }
            if (sql.contains("ds_project_asset")) {
                return List.of();
            }
            if (sql.contains("ds_data_asset")) {
                return List.of();
            }
            if (sql.contains("ds_sandbox_approval")) {
                return sandboxApprovals;
            }
            return List.of();
        }
    }
}
