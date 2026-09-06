/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** 期限变更必须更新当前资产引用，同时保留旧策略并拒绝越过最新期限的旧任务。 */
class TeePolicyDeadlineTest {
    private final TeePolicyRepository policies = mock(TeePolicyRepository.class);
    private final TeeAssetRepository assets = mock(TeeAssetRepository.class);
    private final TeeKeyService keys = mock(TeeKeyService.class);
    private final TeeApprovalPolicySource approvals = mock(TeeApprovalPolicySource.class);
    private final KeyAdapterClient adapter = mock(KeyAdapterClient.class);
    private final List<TeePolicyDO> versions = new ArrayList<>();
    private TeePolicyService service;
    private TeeAssetDO asset;
    private TeePolicyDO original;
    private TeeKeyDO key;
    private String policyId;

    @BeforeEach
    void setUp() {
        policyId = "pl-" + TeeCrypto.sha256Hex("asset-1|sandbox-1".getBytes(StandardCharsets.UTF_8)).substring(0, 12);
        original = TeePolicyDO.builder().upk(new TeePolicyDO.UPK(policyId, "1"))
                .assetId("asset-1").assetVersion("1").ownerId("owner-1").sandboxId("sandbox-1")
                .columnsJson("[\"age\"]").operatorsJson("[\"sql.query\",\"python.execute\"]")
                .reportKindsJson("[]").approvalId("apr-1").state("ACTIVE")
                .expiresAt(Instant.now().minusSeconds(86400).toString()).build();
        versions.add(original);
        asset = TeeAssetDO.builder().upk(new TeeAssetDO.UPK("asset-1", "1"))
                .ownerId("owner-1").policyId(policyId).policyVersion("1")
                .objectId("object-1").schemaJson("[\"age\"]").keyId("key-1").keyVersion("1").build();
        key = TeeKeyDO.builder().ownerId("owner-1").assetId("asset-1").assetVersion("1").state("ACTIVE").build();
        when(assets.findById(asset.getUpk())).thenReturn(Optional.of(asset));
        when(policies.findById(any())).thenAnswer(invocation -> {
            TeePolicyDO.UPK id = invocation.getArgument(0);
            return versions.stream().filter(policy -> policy.getUpk().equals(id)).findFirst();
        });
        when(policies.findByAssetIdAndAssetVersion("asset-1", "1")).thenReturn(versions);
        when(policies.save(any())).thenAnswer(invocation -> {
            TeePolicyDO row = invocation.getArgument(0);
            versions.add(row);
            return row;
        });
        when(keys.require("key-1", "1")).thenReturn(key);
        service = new TeePolicyService(policies, keys, approvals, adapter,
                mock(TeeIdentityRegistry.class), mock(TeeIdempotency.class), new ObjectMapper(), assets);
    }

    private void deadline(Instant deadline) {
        when(approvals.approvedScope(anyString(), anyString(), anyString(), anyList(), anyList()))
                .thenReturn(new TeeApprovalPolicySource.Approved("apr-1", List.of("age"),
                        List.of("sql.query", "python.execute"), deadline));
    }

    @Test
    void expiredAutomaticPolicyGetsNewVersionWithoutChangingOriginalScope() {
        String oldDeadline = original.getExpiresAt();
        Instant until = Instant.parse("2099-09-29T16:00:00Z");
        deadline(until);
        TeePolicyDO refreshed = service.refreshForAsset(asset, "sandbox-1");
        assertEquals("2", refreshed.getUpk().getPolicyVersion());
        assertEquals(until.toString(), refreshed.getExpiresAt());
        assertEquals("2", asset.getPolicyVersion());
        assertEquals(oldDeadline, original.getExpiresAt());
        assertEquals(original.getColumnsJson(), refreshed.getColumnsJson());
        assertEquals(original.getOperatorsJson(), refreshed.getOperatorsJson());
        assertEquals("object-1", asset.getObjectId());
        verify(assets).save(asset);
        verifyNoInteractions(adapter);
        assertSame(refreshed, service.refreshForAsset(asset, "sandbox-1"));
        assertEquals(2, versions.size());
    }

    @Test
    void shorteningToPastStillSynchronizesDeadlineButCannotExecute() {
        Instant shortened = Instant.now().minusSeconds(60);
        deadline(shortened);
        TeePolicyDO refreshed = service.refreshForAsset(asset, "sandbox-1");
        assertEquals(shortened.toString(), refreshed.getExpiresAt());
        assertThrows(TeeException.class, () -> service.requireAllows(refreshed, List.of("age"), "sql.query"));
    }

    @Test
    void oldSignedPolicyIsCheckedAgainstCurrentDataControl() {
        original.setExpiresAt("2099-10-01T00:00:00Z");
        when(approvals.resolveApproved(anyString(), anyString(), anyString(), anyList(), anyList()))
                .thenThrow(TeeException.of(TeeContract.Error.POLICY_DENIED, "数据使用截止时间已过"));
        assertThrows(TeeException.class, () -> service.requireAllows(original, List.of("age"), "sql.query"));
    }

    @Test
    void manualPolicyIsNotAutomaticallyExtended() {
        original.setUpk(new TeePolicyDO.UPK("manual-policy", "1"));
        asset.setPolicyId("manual-policy");
        assertSame(original, service.refreshForAsset(asset, "sandbox-1"));
        verifyNoInteractions(approvals);
        verify(policies, never()).save(any());
    }

    @Test
    void stoppedPolicyCannotBeRevived() {
        original.setState("REVOKED");
        assertSame(original, service.refreshForAsset(asset, "sandbox-1"));
        verifyNoInteractions(approvals);
        verify(policies, never()).save(any());
    }

    @Test
    void revokedKeyCannotBeRevivedByDeadlineChange() {
        deadline(Instant.parse("2099-09-29T16:00:00Z"));
        doThrow(TeeException.of(TeeContract.Error.KEY_REVOKED, "密钥已吊销")).when(keys).requireActive(key);
        assertThrows(TeeException.class, () -> service.refreshForAsset(asset, "sandbox-1"));
        verify(policies, never()).save(any());
        assertEquals("1", asset.getPolicyVersion());
    }

    @Test
    void missingOrStoppedApprovalCannotExtendPolicy() {
        when(approvals.approvedScope(anyString(), anyString(), anyString(), anyList(), anyList()))
                .thenThrow(TeeException.of(TeeContract.Error.POLICY_DENIED, "数据方已停止使用"));
        assertThrows(TeeException.class, () -> service.refreshForAsset(asset, "sandbox-1"));
        verify(policies, never()).save(any());
    }

    @Test
    void anotherSandboxCannotRefreshPolicy() {
        assertThrows(TeeException.class, () -> service.refreshForAsset(asset, "another-sandbox"));
        verifyNoInteractions(approvals);
        verify(policies, never()).save(any());
    }
}
