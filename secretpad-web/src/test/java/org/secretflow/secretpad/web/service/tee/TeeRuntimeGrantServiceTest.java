/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** P5 已接受任务只能读取签名对象，并且结果标识、类型与密钥不可换绑。 */
class TeeRuntimeGrantServiceTest {

    private final AtomicReference<TeeRuntimeTaskDO> saved = new AtomicReference<>();
    private TeeRuntimeGrantService grants;

    @BeforeEach
    void setUp() {
        TeeRuntimeTaskRepository tasks = mock(TeeRuntimeTaskRepository.class);
        TeeAssetRepository assets = mock(TeeAssetRepository.class);
        when(tasks.findById(any())).thenAnswer(invocation -> Optional.ofNullable(saved.get()));
        when(tasks.save(any())).thenAnswer(invocation -> {
            TeeRuntimeTaskDO value = invocation.getArgument(0);
            saved.set(value);
            return value;
        });
        when(assets.findById(new TeeAssetDO.UPK("asset-1", "1"))).thenReturn(Optional.of(
                TeeAssetDO.builder().upk(new TeeAssetDO.UPK("asset-1", "1"))
                        .ownerId("client-a").objectId("object-1").schemaJson("[]")
                        .policyId("policy-1").policyVersion("1")
                        .keyId("key-1").keyVersion("1").build()));
        grants = new TeeRuntimeGrantService(tasks, assets, new ObjectMapper());
    }

    @Test
    void acceptedTaskScopesReadsAndBindsResult() {
        assertEquals(List.of("client-a"), grants.accept("center-runtime", task(),
                "header.payload.signature", "a".repeat(64)));
        grants.requireObjectRead("center-runtime", "task-1", "object-1");
        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED,
                assertThrows(TeeException.class, () -> grants.requireObjectRead(
                        "center-runtime", "task-1", "object-other")).error());

        grants.bindResult("center-runtime", "task-1", "result-1", "DATA", "result-key", "1");
        assertEquals("DATA", grants.requireResult("center-runtime", "task-1", "result-1",
                "DATA", "result-key", "1").kind());
        assertEquals(TeeContract.Error.POLICY_DENIED,
                assertThrows(TeeException.class, () -> grants.bindResult(
                        "center-runtime", "task-1", "result-1", "MODEL", "other", "1")).error());
    }

    @Test
    void callerAndExpiryAreEnforced() {
        grants.accept("center-runtime", task(), "header.payload.signature", "b".repeat(64));
        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED,
                assertThrows(TeeException.class, () -> grants.requireObjectRead(
                        "other-runtime", "task-1", "object-1")).error());
        saved.get().setExpiresAt(Instant.now().minusSeconds(60).toString());
        assertEquals(TeeContract.Error.TASK_EXPIRED,
                assertThrows(TeeException.class, () -> grants.requireObjectRead(
                        "center-runtime", "task-1", "object-1")).error());
    }

    private static TeeTaskSpec task() {
        Instant now = Instant.now();
        return new TeeTaskSpec(TeeContract.VERSION, "task-1", "task-request-1", "center",
                "runtime", "sandbox-1", "ml.logistic", List.of("age"),
                List.of(new TeeTaskSpec.Input("asset-1", 1, "key-1", 1,
                        "policy-1", 1, "object-1", "c".repeat(64), 10)),
                new TeeTaskSpec.Program("BUILTIN", null, "d".repeat(64), Map.of()),
                now.toString(), now.plusSeconds(120).toString(), "nonce-1",
                new TeeTaskSpec.OutputPolicy(List.of("EVALUATION_METRICS"), true, true, true),
                "sha256:image");
    }
}
