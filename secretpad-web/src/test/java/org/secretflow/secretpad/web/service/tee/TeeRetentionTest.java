/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeNonceDO;
import org.secretflow.secretpad.persistence.entity.TeeRequestDO;
import org.secretflow.secretpad.persistence.repository.TeeNonceRepository;
import org.secretflow.secretpad.persistence.repository.TeeRequestRepository;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 幂等记录与 nonce 的保留期清理。
 *
 * <p>两张表原本只增不删。清理只能删除已过保留期的记录：保留期内的重试判定与重放判定
 * 必须保持原样，否则同一 requestId 的重试会重复执行、已消费的 nonce 会重新可用。
 */
class TeeRetentionTest {

    @Test
    void onlyRecordsPastRetentionAreRemoved() {
        TeeNonceRepository nonces = mock(TeeNonceRepository.class);
        TeeRequestRepository requests = mock(TeeRequestRepository.class);
        TeeNonceDO nonce = TeeNonceDO.builder().upk(new TeeNonceDO.UPK("issuer", "n-1")).build();
        TeeRequestDO request = TeeRequestDO.builder().upk(new TeeRequestDO.UPK("k-1")).build();
        when(nonces.findRetentionExpired(anyString())).thenReturn(List.of(nonce));
        when(requests.findCreatedBefore(anyString())).thenReturn(List.of(request));

        assertEquals(2, new TeeRetention(nonces, requests).purgeOnce(Instant.parse("2026-09-01T00:00:00Z")));
        verify(nonces).delete(nonce);
        verify(requests).delete(request);
    }

    @Test
    void retentionDeadlinesFollowContract() {
        TeeNonceRepository nonces = mock(TeeNonceRepository.class);
        TeeRequestRepository requests = mock(TeeRequestRepository.class);
        when(nonces.findRetentionExpired(anyString())).thenReturn(List.of());
        when(requests.findCreatedBefore(anyString())).thenReturn(List.of());
        Instant now = Instant.parse("2026-09-01T00:00:00Z");

        assertEquals(0, new TeeRetention(nonces, requests).purgeOnce(now));
        // nonce 记录本身存的就是过期加保留期之后的时刻，按当前时刻比较即可。
        verify(nonces).findRetentionExpired(now.toString());
        verify(requests).findCreatedBefore(now.minusSeconds(TeeContract.RETENTION_SECONDS).toString());
    }

    @Test
    void nothingIsRemovedWhenBothTablesAreWithinRetention() {
        TeeNonceRepository nonces = mock(TeeNonceRepository.class);
        TeeRequestRepository requests = mock(TeeRequestRepository.class);
        when(nonces.findRetentionExpired(anyString())).thenReturn(List.of());
        when(requests.findCreatedBefore(anyString())).thenReturn(List.of());

        assertEquals(0, new TeeRetention(nonces, requests).purgeOnce(Instant.now()));
        verify(nonces, never()).delete(org.mockito.ArgumentMatchers.any(TeeNonceDO.class));
        verify(requests, never()).delete(org.mockito.ArgumentMatchers.any(TeeRequestDO.class));
    }
}
