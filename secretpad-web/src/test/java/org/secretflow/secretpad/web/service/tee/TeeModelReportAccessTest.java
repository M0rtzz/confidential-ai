/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 模型报告只能从已核实训练回执回溯，并继承原训练来源的授权边界。 */
class TeeModelReportAccessTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private TeeObjectRepository objects;
    private TeeRuntimeTaskRepository tasks;
    private TeePolicyService policies;
    private TeeKeyService keys;
    private JdbcTemplate jdbc;
    private TeeModelReportAccess access;
    private TeeObjectDO model;
    private TeePolicyDO sourcePolicy;
    private TeeKeyDO key;
    private TeeTaskSpec source;

    @BeforeEach
    void setUp() throws Exception {
        objects = mock(TeeObjectRepository.class);
        tasks = mock(TeeRuntimeTaskRepository.class);
        policies = mock(TeePolicyService.class);
        keys = mock(TeeKeyService.class);
        jdbc = mock(JdbcTemplate.class);
        access = new TeeModelReportAccess(objects, tasks, policies, keys, mapper, jdbc);

        source = sourceTask(Instant.now().minusSeconds(60));
        model = TeeObjectDO.builder().upk(new TeeObjectDO.UPK("model-1")).kind("MODEL")
                .ownerId("center").taskId("train-1").resultId("asset-1")
                .keyId("model-key").keyVersion("1").ciphertextSha256("c".repeat(64))
                .sizeBytes(42L).contributorsJson("[\"client-a\"]").exportState("NONE").build();
        sourcePolicy = policy("ACTIVE", List.of(TeeModelReportAccess.OPERATOR),
                List.of(TeeModelReportAccess.REPORT_KIND));
        key = TeeKeyDO.builder().upk(new TeeKeyDO.UPK("model-key", "1"))
                .assetId("asset-1").assetVersion("1").ownerId("center")
                .resourceUri("cm://asset-1").state("ACTIVE").issuedAt(Instant.now().toString())
                .claimCount(0).releaseCount(0).build();

        String taskJws = payloadJws(source);
        TeeRuntimeTaskDO training = TeeRuntimeTaskDO.builder().upk(new TeeRuntimeTaskDO.UPK("train-1"))
                .taskJws(taskJws).receiptJws(payloadJws(receipt("model-1")))
                .status("SUCCEEDED").receiptVerified(true).build();
        when(objects.findById(any())).thenReturn(Optional.of(model));
        when(tasks.findById(any())).thenReturn(Optional.of(training));
        when(policies.resultSourcePolicy("policy-1", "1")).thenReturn(sourcePolicy);
        when(policies.reportKinds(sourcePolicy)).thenReturn(List.of(TeeModelReportAccess.REPORT_KIND));
        when(keys.require("model-key", "1")).thenReturn(key);
        when(keys.require("source-key", "1")).thenReturn(key);
    }

    @Test
    void directOriginalPolicyAllowsReport() {
        TeeModelReportAccess.Authorized result = access.authorize("model-1", "sandbox-1", List.of("age"));
        assertEquals(List.of("client-a"), result.contributors());
    }

    @Test
    void revokedOriginalPolicyIsRejected() {
        doThrow(TeeException.of(TeeContract.Error.POLICY_DENIED, "revoked"))
                .when(policies).requireAllows(any(), any(), anyString());
        assertThrows(TeeException.class, () -> access.authorize("model-1", "sandbox-1", List.of("age")));
    }

    @Test
    void receiptObjectMismatchIsRejected() throws Exception {
        TeeRuntimeTaskDO training = tasks.findById(new TeeRuntimeTaskDO.UPK("train-1")).orElseThrow();
        training.setReceiptJws(payloadJws(receipt("other-model")));
        assertThrows(TeeException.class, () -> access.authorize("model-1", "sandbox-1", List.of("age")));
    }

    @Test
    void recordedContributorsMustMatchSourcePolicies() {
        model.setContributorsJson("[\"center\"]");
        assertThrows(TeeException.class, () -> access.authorize("model-1", "sandbox-1", List.of("age")));
    }

    @Test
    void historicalModelWithoutExplicitGrantIsRejected() throws Exception {
        sourcePolicy.setOperatorsJson("[]");
        when(jdbc.queryForList(anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn(List.of());
        assertThrows(TeeException.class, () -> access.authorize("model-1", "sandbox-1", List.of("age")));
    }

    @Test
    void exactHistoricalGrantAllowsReport() throws Exception {
        sourcePolicy.setOperatorsJson("[]");
        when(jdbc.queryForList(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(List.of(Map.of("id", "grant-1", "expires_at", Instant.now().plusSeconds(600).toString())));
        assertEquals(List.of("client-a"), access.authorize("model-1", "sandbox-1", List.of("age")).contributors());
    }

    @Test
    void standardTrainingReportCutoffAllowsSupportedAlgorithm() throws Exception {
        sourcePolicy.setOperatorsJson("[]");
        when(jdbc.<String>query(anyString(), any(RowMapper.class)))
                .thenReturn(List.of(Instant.now().minusSeconds(120).toString()));
        assertEquals(List.of("client-a"), access.authorize("model-1", "sandbox-1", List.of("age")).contributors());
    }

    private String payloadJws(Object value) throws Exception {
        return "e30." + TeeCrypto.encodeUrl(mapper.writeValueAsBytes(value)) + ".AA";
    }

    private TeePolicyDO policy(String state, List<String> operators, List<String> reports) throws Exception {
        return TeePolicyDO.builder().upk(new TeePolicyDO.UPK("policy-1", "1"))
                .assetId("asset-1").assetVersion("1").ownerId("client-a").sandboxId("sandbox-1")
                .columnsJson("[\"age\"]").operatorsJson(mapper.writeValueAsString(operators))
                .reportKindsJson(mapper.writeValueAsString(reports)).expiresAt(Instant.now().plusSeconds(600).toString())
                .state(state).approvalId("approval-1").build();
    }

    private TeeTaskSpec sourceTask(Instant issuedAt) {
        return new TeeTaskSpec(TeeContract.VERSION, "train-1", "request-1", "center", "runtime",
                "sandbox-1", "ml.decision_tree", List.of("age"),
                List.of(new TeeTaskSpec.Input("asset-1", 1, "source-key", 1, "policy-1", 1,
                        "source-object", "s".repeat(64), 10)),
                new TeeTaskSpec.Program("BUILTIN", null, "p".repeat(64), Map.of()),
                issuedAt.toString(), issuedAt.plusSeconds(600).toString(), "nonce-1",
                new TeeTaskSpec.OutputPolicy(List.of("MODEL"), false, true, true), "sha256:image");
    }

    private Map<String, Object> receipt(String objectId) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("objectId", objectId);
        output.put("kind", "MODEL");
        output.put("artifactType", "TREE");
        output.put("ciphertextSha256", model.getCiphertextSha256());
        output.put("keyId", model.getKeyId());
        output.put("keyVersion", model.getKeyVersion());
        return Map.of("outputs", List.of(output));
    }
}
