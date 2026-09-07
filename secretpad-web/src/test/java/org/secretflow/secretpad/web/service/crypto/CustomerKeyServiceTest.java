/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** 客户密钥生命周期：状态机推进、归属校验与回收的双表一致性。 */
class CustomerKeyServiceTest {

    private static final String OWNER = "intbeukj";

    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final ConfidentialComputeService compute = mock(ConfidentialComputeService.class);
    private final ConfidentialMetadataStore store = mock(ConfidentialMetadataStore.class);
    private final CustomerKeyService service =
            new CustomerKeyService(jdbc, compute, store, new ObjectMapper());

    private void keyRow(String kid, String status) {
        when(jdbc.queryForList(contains("from ds_customer_encryption_key where kid=?"), eq(kid), eq(OWNER)))
                .thenReturn(List.of(Map.of("kid", kid, "status", status)));
    }

    @Test
    void unknownKeyIsRejectedAsOwnerMismatch() {
        when(jdbc.queryForList(contains("from ds_customer_encryption_key where kid=?"), anyString(), anyString()))
                .thenReturn(List.of());
        assertThrows(TeeException.class, () -> service.revoke(OWNER, "user_missing"));
    }

    @Test
    void revokeStopsBothIdentityTables() {
        keyRow("user_a", "ACTIVE");
        Map<String, Object> result = service.revoke(OWNER, "user_a");
        assertEquals("REVOKED", result.get("status"));
        assertEquals(true, result.get("changed"));
        verify(jdbc).update(contains("update ds_customer_encryption_key set status=?,revoked_at=?"),
                eq("REVOKED"), anyString(), eq("user_a"));
        verify(jdbc).update(contains("update ds_crypto_identity set status=?,revoked_at=?"),
                eq("REVOKED"), anyString(), eq("user_a"));
        verify(jdbc).update(contains("update ds_crypto_signing_identity set status=?,revoked_at=?"),
                eq("REVOKED"), anyString(), eq("user_a"));
    }

    @Test
    void revokeIsIdempotent() {
        keyRow("user_a", "REVOKED");
        assertEquals(false, service.revoke(OWNER, "user_a").get("changed"));
        verify(jdbc, never()).update(contains("update ds_customer_encryption_key"), any(), any(), any());
    }

    @Test
    void destroyedKeyCannotBeRevokedAgain() {
        keyRow("user_a", "DESTROYED");
        assertThrows(TeeException.class, () -> service.revoke(OWNER, "user_a"));
    }

    @Test
    void destroyRequiresMatchingConfirmation() {
        keyRow("user_a", "ACTIVE");
        assertThrows(TeeException.class, () -> service.destroy(OWNER, "user_a", "user_b"));
        verify(jdbc, never()).update(contains("destroyed_at"), any(), any(), any(), any());
    }

    @Test
    void destroyWritesAuditAndAdvancesState() {
        keyRow("user_a", "ACTIVE");
        assertEquals("DESTROYED", service.destroy(OWNER, "user_a", "user_a").get("status"));
        verify(store).audit(eq(OWNER), eq("CUSTOMER_KEY_DESTROYED"), eq("user_a"), any());
    }

    @Test
    void rotateSupersedesPreviousActiveVersion() {
        when(jdbc.queryForList(contains("where tenant_id=? and status=? order by key_version desc"),
                eq(OWNER), eq("ACTIVE")))
                .thenReturn(List.of(Map.of("kid", "user_old", "key_version", 1)));
        Map<String, Object> result = service.rotate(OWNER,
                new CustomerKeyService.RotateRequest("user_new", "enc", "sig", "proof"));
        assertEquals("user_old", result.get("rotatedFromKid"));
        verify(compute).registerIdentity(eq(OWNER), any());
        verify(jdbc).update(contains("set status=?,superseded_at=?"), eq("SUPERSEDED"), anyString(),
                eq(OWNER), eq("ACTIVE"), eq("user_new"));
        verify(store).audit(eq(OWNER), eq("CUSTOMER_KEY_ROTATED"), eq("user_new"), any());
    }

    @Test
    void rotateRejectsReusingTheSameKid() {
        when(jdbc.queryForList(contains("where tenant_id=? and status=? order by key_version desc"),
                eq(OWNER), eq("ACTIVE")))
                .thenReturn(List.of(Map.of("kid", "user_a", "key_version", 1)));
        assertThrows(TeeException.class, () -> service.rotate(OWNER,
                new CustomerKeyService.RotateRequest("user_a", "enc", "sig", "proof")));
        verify(compute, never()).registerIdentity(anyString(), any());
    }

    @Test
    void rotationStatusSeparatesAssetsStillBoundToThePreviousKey() {
        when(jdbc.queryForList(contains("where tenant_id=? and status=? order by key_version desc"),
                eq(OWNER), eq("ACTIVE")))
                .thenReturn(List.of(Map.of("kid", "user_new", "key_version", 2)));
        when(jdbc.queryForList(contains("from ds_crypto_asset_version where owner_id=?"),
                eq(String.class), eq(OWNER))).thenReturn(List.of("av1", "av2", "av3"));
        when(jdbc.queryForList(contains("from ds_crypto_key_envelope where recipient_kid=?"),
                eq(String.class), eq("user_new"))).thenReturn(List.of("av1"));
        CustomerKeyService.RotationStatus status = service.rotationStatus(OWNER);
        assertEquals(3L, status.total());
        assertEquals(1L, status.boundToActive());
        assertEquals(List.of("av2", "av3"), status.boundToPrevious());
    }

    @Test
    void rotationStatusIsEmptyWithoutAnActiveKey() {
        when(jdbc.queryForList(contains("where tenant_id=? and status=? order by key_version desc"),
                eq(OWNER), eq("ACTIVE"))).thenReturn(List.of());
        CustomerKeyService.RotationStatus status = service.rotationStatus(OWNER);
        assertEquals(0L, status.total());
        assertTrue(status.boundToPrevious().isEmpty());
    }
}
