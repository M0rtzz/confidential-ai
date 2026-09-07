/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** GPU 链路聚合：分段构成、计数来源与明细分页边界。 */
class GpuChainServiceTest {

    private static final String OWNER = "intbeukj";

    private static GpuChainService newService(JdbcTemplate jdbc) {
        ConfidentialComputeService compute = mock(ConfidentialComputeService.class);
        when(compute.domains()).thenReturn(List.of(
                Map.of("id", "a100-domain-a", "status", "active", "trustStatus", "trusted"),
                Map.of("id", "a100-domain-b", "status", "active", "trustStatus", "blocked")));
        return new GpuChainService(jdbc, compute);
    }

    private static JdbcTemplate countingJdbc(long value) {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(Long.class), any(Object[].class))).thenReturn(value);
        return jdbc;
    }

    @Test
    void summaryReturnsSixSegmentsInChainOrder() {
        GpuChainService service = newService(countingJdbc(0L));
        List<String> keys = service.summary(OWNER).segments().stream().map(GpuChainService.Segment::key).toList();
        assertEquals(List.of("IDENTITY", "ASSET_ENCRYPT", "DOMAIN_VERIFY", "ATTESTATION",
                "GRANT_RELEASE", "EXECUTION_EGRESS"), keys);
    }

    @Test
    void emptyLedgerMarksDataSegmentsEmpty() {
        GpuChainService service = newService(countingJdbc(0L));
        Map<String, String> states = service.summary(OWNER).segments().stream()
                .collect(java.util.stream.Collectors.toMap(GpuChainService.Segment::key,
                        GpuChainService.Segment::state));
        assertEquals("EMPTY", states.get("IDENTITY"));
        assertEquals("EMPTY", states.get("ASSET_ENCRYPT"));
        assertEquals("EMPTY", states.get("ATTESTATION"));
        // 可信域来自固定登记表，不随台账为空而变化。
        assertEquals("OK", states.get("DOMAIN_VERIFY"));
    }

    @Test
    void attestationStaysWarnWhileEvidenceIsSimulated() {
        GpuChainService service = newService(countingJdbc(3L));
        GpuChainService.Segment segment = service.summary(OWNER).segments().stream()
                .filter(item -> "ATTESTATION".equals(item.key())).findFirst().orElseThrow();
        assertEquals("WARN", segment.state());
    }

    @Test
    void domainSegmentCountsOnlyUsableDomains() {
        GpuChainService service = newService(countingJdbc(0L));
        GpuChainService.Segment segment = service.summary(OWNER).segments().stream()
                .filter(item -> "DOMAIN_VERIFY".equals(item.key())).findFirst().orElseThrow();
        assertEquals(1L, metric(segment, "可用"));
        assertEquals(2L, metric(segment, "已登记"));
    }

    @Test
    void runtimeNeverClaimsVerifiedAttestation() {
        GpuChainService.Runtime runtime = newService(countingJdbc(0L)).runtime();
        assertEquals(ConfidentialContract.SIM_PROFILE, runtime.securityProfile());
        assertEquals(ConfidentialContract.SIM_EVIDENCE, runtime.evidenceType());
        assertTrue(runtime.simulated());
        assertFalse(runtime.attestationVerified());
    }

    @Test
    void pageSizeIsClampedAndTotalComesFromDatabase() {
        JdbcTemplate jdbc = countingJdbc(500L);
        when(jdbc.queryForList(anyString(), any(Object[].class))).thenReturn(List.of());
        GpuChainService.PageView view = newService(jdbc).identities(OWNER, 0, 5000);
        assertEquals(1, view.page());
        assertEquals(200, view.size());
        assertEquals(500L, view.total());
    }

    @Test
    void detailColumnsAreExposedAsCamelCase() {
        JdbcTemplate jdbc = countingJdbc(1L);
        when(jdbc.queryForList(anyString(), any(Object[].class))).thenReturn(List.of(
                new java.util.LinkedHashMap<>(Map.of("event_hash", "aa", "previous_hash", "bb"))));
        GpuChainService.PageView view = newService(jdbc).auditEvents(OWNER, 1, 20);
        Map<String, Object> row = view.items().get(0);
        assertTrue(row.containsKey("eventHash"));
        assertTrue(row.containsKey("previousHash"));
        assertFalse(row.containsKey("event_hash"));
    }

    private static long metric(GpuChainService.Segment segment, String label) {
        return segment.metrics().stream().filter(item -> label.equals(item.label()))
                .findFirst().orElseThrow().value();
    }
}
