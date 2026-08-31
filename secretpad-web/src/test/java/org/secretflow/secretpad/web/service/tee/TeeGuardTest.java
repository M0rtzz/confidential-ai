/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 三条底座不校验的边界必须在契约层被拒绝。
 *
 * <p>密钥服务对空列请求不作限制、把 '*' 当作放开全部，这两条已由 P4 前置实测确认；
 * 因此这里的用例是整条放行链路的安全依据，不能因为「底座会拦」而放宽。
 */
class TeeGuardTest {

    @Test
    void emptyGrantSetIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED,
                assertThrows(TeeException.class, () -> TeeGuard.requireGrantSet(List.of(), "列")).error());
        assertEquals(TeeContract.Error.POLICY_DENIED,
                assertThrows(TeeException.class, () -> TeeGuard.requireGrantSet(null, "算子")).error());
    }

    @Test
    void wildcardGrantIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> TeeGuard.requireGrantSet(List.of("age", "*"), "列")).error());
    }

    @Test
    void grantSetIsDeduplicatedAndTrimmed() {
        assertEquals(List.of("age", "income"),
                TeeGuard.requireGrantSet(List.of(" age ", "income", "age"), "列"));
    }

    @Test
    void subsetOutsideGrantIsRejected() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> TeeGuard.requireSubset(List.of("age", "id_card"), List.of("age", "income"), "列")).error());
    }

    @Test
    void emptyRequestedColumnsCannotBypassColumnCheck() {
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> TeeGuard.requireSubset(List.of(), List.of("age"), "列")).error());
    }

    @Test
    void ownerMismatchIsRejected() {
        assertEquals(TeeContract.Error.ASSET_OWNER_MISMATCH, assertThrows(TeeException.class,
                () -> TeeGuard.requireOwner("alice", "bob")).error());
    }

    @Test
    void expiredAuthorizationIsRejected() {
        Instant past = Instant.now().minusSeconds(TeeContract.CLOCK_SKEW_SECONDS + 60);
        assertEquals(TeeContract.Error.POLICY_DENIED, assertThrows(TeeException.class,
                () -> TeeGuard.requireNotExpired(past, TeeContract.Error.POLICY_DENIED, "过期")).error());
    }

    @Test
    void reportKindOutsideWhitelistIsRejected() {
        assertEquals(TeeContract.Error.CONTRACT_INVALID, assertThrows(TeeException.class,
                () -> TeeGuard.requireReportKinds(List.of("RAW_ROWS"))).error());
    }

    @Test
    void contractVersionMismatchIsRejected() {
        assertEquals(TeeContract.Error.CONTRACT_INVALID, assertThrows(TeeException.class,
                () -> TeeGuard.requireVersion("tee-contract/2.0")).error());
    }

    @Test
    void oversizePayloadIsRejected() {
        assertEquals(TeeContract.Error.PAYLOAD_TOO_LARGE, assertThrows(TeeException.class,
                () -> TeeGuard.requireSize(TeeContract.MAX_OBJECT_PLAINTEXT_BYTES + 1,
                        TeeContract.MAX_OBJECT_PLAINTEXT_BYTES)).error());
    }
}
