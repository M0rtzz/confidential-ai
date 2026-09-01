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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 授权规则必须由有效审批生成。
 *
 * <p>契约第四节要求 {@code /policies/register} 的规则来自有效审批；没有这层校验，
 * 任何持有会话的数据方都能凭空登记任意列与算子的授权，列级管控形同虚设。
 */
class TeeApprovalPolicySourceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String OWNER = "inst-a";
    private static final String SANDBOX = "sbx-1";
    private static final String ASSET = "asset-1";

    /** 按 SQL 关键字返回预置行的假 JdbcTemplate；用例只关心校验分支，不接触真实库。 */
    private static class Rows extends JdbcTemplate {
        private final Map<String, List<Map<String, Object>>> tables = new LinkedHashMap<>();

        Rows put(String table, Map<String, Object> row) {
            tables.computeIfAbsent(table, key -> new ArrayList<>()).add(row);
            return this;
        }

        @Override
        public List<Map<String, Object>> queryForList(String sql, Object... args) {
            for (String table : tables.keySet()) {
                if (sql.contains(table)) {
                    return tables.get(table);
                }
            }
            return List.of();
        }
    }

    private static String platformTime(long hours) {
        return LocalDateTime.ofInstant(Instant.now().plusSeconds(hours * 3600),
                ZoneId.of("Asia/Shanghai")).withNano(0).toString();
    }

    private static String payload(List<String> columns, List<String> operators) {
        try {
            return MAPPER.writeValueAsString(Map.of("datasetAssetIds", List.of(ASSET),
                    "teeColumns", columns, "teeOperators", operators,
                    "teeExpiresAt", Instant.now().plusSeconds(7200).toString()));
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static Rows complete(List<String> columns, List<String> operators) {
        return new Rows()
                .put("ds_sandbox_dataset_mount", Map.of("asset_version", 1,
                        "expires_at", platformTime(3)))
                .put("ds_sandbox_mount_control", Map.of("allow_use", 1,
                        "use_until", platformTime(3)))
                .put("ds_sandbox_approval", Map.of("id", "apr-1", "approval_type", "DATA_CHANGE",
                        "payload_json", payload(columns, operators)))
                .put("ds_sandbox ", Map.of("owner_id", OWNER, "expires_at", platformTime(4)));
    }

    private static TeeApprovalPolicySource source(Rows rows) {
        return new TeeApprovalPolicySource(rows, MAPPER, "node-a");
    }

    private static TeeApprovalPolicySource.Approved check(Rows rows, List<String> columns,
                                                          List<String> operators, long seconds) {
        return source(rows).requireApproved(OWNER, SANDBOX, ASSET, columns, operators,
                Instant.now().plusSeconds(seconds));
    }

    @Test
    void approvedScopeIsAccepted() {
        var approved = check(complete(List.of("age", "income"), List.of("ml.xgboost")),
                List.of("age"), List.of("ml.xgboost"), 3600);
        assertEquals("apr-1", approved.approvalId());
        assertEquals(List.of("age", "income"), approved.columns());
    }

    @Test
    void missingSandboxIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(new Rows(), List.of("age"), List.of("ml.xgboost"), 3600)).error());
    }

    @Test
    void sandboxOfAnotherInstitutionIsRejected() {
        Rows rows = complete(List.of("age"), List.of("ml.xgboost"));
        rows.tables.put("ds_sandbox ", List.of(Map.of("owner_id", "inst-b", "expires_at", platformTime(4))));
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(rows, List.of("age"), List.of("ml.xgboost"), 3600)).error());
    }

    @Test
    void assetWithoutMountIsRejected() {
        Rows rows = complete(List.of("age"), List.of("ml.xgboost"));
        rows.tables.put("ds_sandbox_dataset_mount", List.of());
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(rows, List.of("age"), List.of("ml.xgboost"), 3600)).error());
    }

    @Test
    void stoppedMountControlIsRejected() {
        Rows rows = complete(List.of("age"), List.of("ml.xgboost"));
        rows.tables.put("ds_sandbox_mount_control",
                List.of(Map.of("allow_use", 0, "use_until", platformTime(3))));
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(rows, List.of("age"), List.of("ml.xgboost"), 3600)).error());
    }

    @Test
    void approvalWithoutOperatorsIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(complete(List.of("age"), List.of()),
                        List.of("age"), List.of("ml.xgboost"), 3600)).error());
    }

    @Test
    void columnsBeyondApprovalAreRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(complete(List.of("age"), List.of("ml.xgboost")),
                        List.of("age", "id_card"), List.of("ml.xgboost"), 3600)).error());
    }

    @Test
    void operatorsBeyondApprovalAreRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(complete(List.of("age"), List.of("ml.xgboost")),
                        List.of("age"), List.of("ml.dnn"), 3600)).error());
    }

    @Test
    void expiryBeyondApprovalDeadlineIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(complete(List.of("age"), List.of("ml.xgboost")),
                        List.of("age"), List.of("ml.xgboost"), 30 * 24 * 3600)).error());
    }

    @Test
    void unrelatedApprovalIsNotAccepted() {
        Rows rows = complete(List.of("age"), List.of("ml.xgboost"));
        rows.tables.put("ds_sandbox_approval", List.of(Map.of("id", "apr-2",
                "approval_type", "CONFIG_CHANGE", "payload_json",
                payload(List.of("age"), List.of("ml.xgboost")))));
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> check(rows, List.of("age"), List.of("ml.xgboost"), 3600)).error());
    }
}
