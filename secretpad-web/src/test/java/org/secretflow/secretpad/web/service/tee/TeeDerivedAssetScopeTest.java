/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 画布中间产物的授权继承。
 *
 * <p>派生资产没有独立的挂载与审批记录，授权只能从上游输入继承。这里校验三件事：上游批准的列
 * 与派生新增的列都能用；供数方收回授权后派生资产同样不可用；越出继承范围的列被拒。
 */
class TeeDerivedAssetScopeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String OWNER = "inst-a";
    private static final String SANDBOX = "sbx-1";
    private static final String SOURCE = "asset-1";
    private static final String DERIVED = "result-1";

    /** 按「SQL 片段 + 首个参数」返回预置行的假 JdbcTemplate，用于区分同表的不同查询。 */
    private static class Rows extends JdbcTemplate {
        private final List<Object[]> entries = new ArrayList<>();

        Rows on(String fragment, String arg, Map<String, Object> row) {
            entries.add(new Object[]{fragment, arg, row == null ? List.of() : List.of(row)});
            return this;
        }

        @Override
        @SuppressWarnings("unchecked")
        public List<Map<String, Object>> queryForList(String sql, Object... args) {
            for (Object[] entry : entries) {
                String arg = (String) entry[1];
                if (sql.contains((String) entry[0])
                        && (arg == null || (args.length > 0 && arg.equals(args[0])))) {
                    return (List<Map<String, Object>>) entry[2];
                }
            }
            return List.of();
        }
    }

    private static String platformTime(long hours) {
        return LocalDateTime.ofInstant(Instant.now().plusSeconds(hours * 3600),
                ZoneId.of("Asia/Shanghai")).withNano(0).toString();
    }

    private static String json(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    /** 上游是一份正常挂载并已审批的资产，派生资产比它多一列 pred。 */
    private static Rows chain() {
        return chain(1);
    }

    private static Rows chain(int allowUse) {
        return new Rows()
                .on("source_asset_id,metadata_json", DERIVED,
                        Map.of("source_asset_id", SOURCE,
                                "metadata_json", json(Map.of("derived", true,
                                        "columns", List.of("age", "income", "pred")))))
                .on("source_asset_id,metadata_json", SOURCE, null)
                .on("select metadata_json from ds_data_asset", DERIVED,
                        Map.of("metadata_json", json(Map.of("columns", List.of("age", "income", "pred")))))
                .on("select metadata_json from ds_data_asset", SOURCE,
                        Map.of("metadata_json", json(Map.of("columns", List.of("age", "income")))))
                .on("ds_sandbox_dataset_mount", SANDBOX,
                        Map.of("asset_version", 1, "expires_at", platformTime(3)))
                .on("ds_sandbox_mount_control", SANDBOX,
                        Map.of("allow_use", allowUse, "use_until", platformTime(3)))
                .on("ds_sandbox_approval", SANDBOX,
                        Map.of("id", "apr-1", "approval_type", "DATA_CHANGE",
                                "payload_json", json(Map.of("datasetAssetIds", List.of(SOURCE),
                                        "teeColumns", List.of("age", "income"),
                                        "teeOperators", List.of("preprocessing.standardize",
                                                "ml.linear_regression"),
                                        "teeExpiresAt", Instant.now().plusSeconds(7200).toString()))))
                .on("ds_sandbox ", SANDBOX,
                        Map.of("owner_id", OWNER, "expires_at", platformTime(4)));
    }

    private static TeeApprovalPolicySource.Approved scope(Rows rows, List<String> columns) {
        return new TeeApprovalPolicySource(rows, MAPPER, "node-a")
                .approvedScope(OWNER, SANDBOX, DERIVED, columns, List.of("ml.linear_regression"));
    }

    @Test
    void derivedAssetInheritsUpstreamColumnsAndKeepsProducedOnes() {
        var approved = scope(chain(), List.of("age", "pred"));
        assertEquals("apr-1", approved.approvalId());
        assertEquals(List.of("age", "income", "pred"), approved.columns());
    }

    @Test
    void columnOutsideInheritedScopeIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> scope(chain(), List.of("age", "credit_score"))).error());
    }

    @Test
    void operatorOutsideUpstreamApprovalIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> new TeeApprovalPolicySource(chain(), MAPPER, "node-a")
                        .approvedScope(OWNER, SANDBOX, DERIVED, List.of("age"), List.of("ml.xgboost")))
                .error());
    }

    @Test
    void stoppedUpstreamMountAlsoBlocksDerivedAsset() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> scope(chain(0), List.of("age"))).error());
    }

    @Test
    void derivedAssetWithoutSourceIsRejected() {
        Rows rows = new Rows()
                .on("source_asset_id,metadata_json", DERIVED,
                        Map.of("source_asset_id", "",
                                "metadata_json", json(Map.of("derived", true, "columns", List.of("age")))))
                .on("ds_sandbox ", SANDBOX, Map.of("owner_id", OWNER, "expires_at", platformTime(4)));
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> scope(rows, List.of("age"))).error());
    }
}
