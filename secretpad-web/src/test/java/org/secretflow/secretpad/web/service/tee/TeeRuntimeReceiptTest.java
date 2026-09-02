/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeRequestDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeRequestRepository;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** P5 回执只能由放行时绑定的工作负载证书签名，并严格绑定任务事实。 */
class TeeRuntimeReceiptTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private TeeRuntimeGrantService grants;
    private TeeRuntimeService runtime;
    private TeeRuntimeTaskDO accepted;

    @BeforeEach
    void setUp() throws Exception {
        TeeTaskSpec task = task();
        String storedTaskJws = "e30." + TeeCrypto.encodeUrl(mapper.writeValueAsBytes(task)) + ".AA";
        String fingerprint = TeeCrypto.certificateSha256(TeeTestMaterial.certificate());
        accepted = TeeRuntimeTaskDO.builder().upk(new TeeRuntimeTaskDO.UPK(task.taskId()))
                .requestId(task.requestId()).callerId("center-runtime")
                .workloadCertSha256(fingerprint).objectIdsJson("[\"object-1\"]")
                .contributorsJson("[\"client-a\"]").resultBindingsJson("{}")
                .taskJws(storedTaskJws).expiresAt(Instant.now().plusSeconds(1800).toString())
                .status("ACCEPTED").receiptVerified(false).build();
        grants = mock(TeeRuntimeGrantService.class);
        when(grants.requireTask("center-runtime", "task-1")).thenReturn(accepted);
        when(grants.resultBindings("center-runtime", "task-1")).thenReturn(Map.of());
        TeeRequestRepository requests = mock(TeeRequestRepository.class);
        when(requests.findById(any())).thenReturn(Optional.empty());
        when(requests.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        TeeIdentityRegistry registry = new TeeIdentityRegistry(mapper, "/dev/null", "/dev/null") {
            @Override
            public String workloadCertificatePem() {
                try {
                    return TeeTestMaterial.certificatePem();
                } catch (Exception failure) {
                    throw new IllegalStateException(failure);
                }
            }
        };
        TeeAssetService assets = mock(TeeAssetService.class);
        when(assets.taskObjects("task-1")).thenReturn(List.of());
        runtime = new TeeRuntimeService(null, null, null, assets, null, registry,
                new TeeIdempotency(requests, mapper), grants, mapper);
    }

    @Test
    void validWorkloadReceiptIsPersistedAsVerified() throws Exception {
        String receiptJws = signReceipt(successReceipt());
        TeeRuntimeService.ReceiptResult result = runtime.receipt("center-runtime", "task-1",
                new TeeRuntimeService.ReceiptRequest(TeeContract.VERSION, "receipt-request-1", receiptJws));
        assertEquals("task-1", result.taskId());
        assertEquals(true, result.signatureVerified());
        verify(grants).saveReceipt("center-runtime", "task-1", receiptJws, "SUCCEEDED");
    }

    @Test
    void tamperedReceiptIsRejectedBeforePersistence() throws Exception {
        String signed = signReceipt(successReceipt());
        String[] parts = signed.split("\\.");
        Map<String, Object> tampered = new LinkedHashMap<>(successReceipt());
        tampered.put("keyReleaseCount", 0);
        String compact = parts[0] + "." + TeeCrypto.encodeUrl(mapper.writeValueAsBytes(tampered))
                + "." + parts[2];
        assertEquals(TeeContract.Error.TASK_SIGNATURE_INVALID,
                assertThrows(TeeException.class, () -> runtime.receipt("center-runtime", "task-1",
                        new TeeRuntimeService.ReceiptRequest(
                                TeeContract.VERSION, "receipt-request-2", compact))).error());
    }

    private String signReceipt(Map<String, Object> payload) throws Exception {
        String kid = TeeCrypto.certificateSha256(TeeTestMaterial.certificate());
        String header = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(
                Map.of("alg", "RS256", "typ", "JWS", "kid", kid)));
        String body = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(payload));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(TeeTestMaterial.privateKey());
        signature.update((header + "." + body).getBytes(StandardCharsets.US_ASCII));
        return header + "." + body + "." + TeeCrypto.encodeUrl(signature.sign());
    }

    private static TeeTaskSpec task() {
        Instant now = Instant.now();
        return new TeeTaskSpec(TeeContract.VERSION, "task-1", "task-request-1", "center",
                "runtime", "sandbox-1", "ml.logistic", List.of("age"),
                List.of(new TeeTaskSpec.Input("asset-1", 1, "key-1", 1,
                        "policy-1", 1, "object-1", "a".repeat(64), 10)),
                new TeeTaskSpec.Program("BUILTIN", null, "b".repeat(64), Map.of()),
                now.toString(), now.plusSeconds(120).toString(), "nonce-1",
                new TeeTaskSpec.OutputPolicy(List.of("EVALUATION_METRICS"), true, true, true),
                "sha256:image");
    }

    private static Map<String, Object> successReceipt() {
        Instant now = Instant.now();
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("contractVersion", TeeContract.VERSION);
        value.put("taskId", "task-1");
        value.put("requestId", "task-request-1");
        value.put("status", "SUCCEEDED");
        value.put("runtimeMode", "SIMULATION");
        value.put("attestationVerified", false);
        value.put("policyVersion", 1);
        value.put("keyReleaseCount", 1);
        value.put("outputs", List.of(Map.of("kind", "REPORT",
                "reportKind", "EVALUATION_METRICS", "encrypted", false,
                "content", Map.of("accuracy", 0.9))));
        value.put("startedAt", now.minusSeconds(2).toString());
        value.put("finishedAt", now.minusSeconds(1).toString());
        value.put("errorCode", null);
        return value;
    }
}
