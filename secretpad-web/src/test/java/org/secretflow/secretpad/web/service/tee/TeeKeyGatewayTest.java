/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeKeyRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * 密钥与规则请求的落点选择。
 *
 * <p>密钥服务只有一处。客户端实例必须把签发、申领、吊销与规则登记原样交给中心端，
 * 不得在本地裁决；中心实例则不应绕经通道再回到自己。委派后保留的本地镜像只用于
 * 密文资产登记时的绑定校验，不含密钥材料，也不承担台账职责。
 */
class TeeKeyGatewayTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private record Fixture(TeeKeyGateway gateway, TeeKeyService keys, TeePolicyService policies,
                           TeeCenterClient center, TeeKeyRepository keyRepository,
                           TeePolicyRepository policyRepository) {
    }

    private Fixture fixture(boolean delegated) {
        TeeKeyService keys = mock(TeeKeyService.class);
        TeePolicyService policies = mock(TeePolicyService.class);
        TeeCenterClient center = mock(TeeCenterClient.class);
        TeeKeyRepository keyRepository = mock(TeeKeyRepository.class);
        TeePolicyRepository policyRepository = mock(TeePolicyRepository.class);
        when(center.configured()).thenReturn(delegated);
        return new Fixture(new TeeKeyGateway(keys, policies, mock(TeeAssetService.class), center,
                keyRepository, policyRepository, mapper),
                keys, policies, center, keyRepository, policyRepository);
    }

    private TeeKeyService.IssueRequest issueRequest() {
        return new TeeKeyService.IssueRequest(TeeContract.VERSION, "req-1", "asset-1", "1");
    }

    private TeePolicyService.RegisterRequest policyRequest() {
        return new TeePolicyService.RegisterRequest(TeeContract.VERSION, "req-2",
                new TeePolicyService.Policy(TeeContract.VERSION, "", "", "asset-1", "1", "inst-a",
                        "sandbox-1", List.of("age"), List.of("ml.xgboost"),
                        Instant.now().plusSeconds(3600).toString(), List.of("EVALUATION_METRICS")));
    }

    @Test
    void centerInstanceDecidesLocallyWithoutTheChannel() {
        Fixture fixture = fixture(false);
        when(fixture.keys().issue(eq("inst-a"), any()))
                .thenReturn(new TeeKeyService.IssueResult(TeeContract.VERSION, "kd-1", "1", "ACTIVE"));

        assertEquals("kd-1", fixture.gateway().issue("inst-a", issueRequest()).keyId());
        verify(fixture.center(), never()).post(any(), any(), any());
        verify(fixture.keyRepository(), never()).save(any());
    }

    @Test
    void clientInstanceDelegatesIssueAndKeepsBindingMirror() {
        Fixture fixture = fixture(true);
        when(fixture.center().post(eq("/keys/issue"), any(), eq(TeeKeyService.IssueResult.class)))
                .thenReturn(new TeeKeyService.IssueResult(TeeContract.VERSION, "kd-9", "1", "ACTIVE"));
        when(fixture.keyRepository().findById(any())).thenReturn(Optional.empty());

        assertEquals("kd-9", fixture.gateway().issue("inst-a", issueRequest()).keyId());
        verifyNoInteractions(fixture.keys());
        verify(fixture.keyRepository()).save(any(TeeKeyDO.class));
    }

    @Test
    void clientInstanceDelegatesClaimWithoutStoringAnything() {
        Fixture fixture = fixture(true);
        TeeKeyService.KeyEnvelope envelope = new TeeKeyService.KeyEnvelope("kd-9", "1",
                TeeContract.ENVELOPE_ALGORITHM, "fingerprint", "AAAA");
        when(fixture.center().post(eq("/keys/claim"), any(), eq(TeeKeyService.ClaimResult.class)))
                .thenReturn(new TeeKeyService.ClaimResult(TeeContract.VERSION, envelope));

        TeeKeyService.ClaimResult result = fixture.gateway().claim("inst-a",
                new TeeKeyService.ClaimRequest(TeeContract.VERSION, "req-3", "asset-1", "1",
                        "kd-9", "1", "pem"));
        assertEquals("AAAA", result.keyEnvelope().wrappedKeyB64());
        verifyNoInteractions(fixture.keys());
        verify(fixture.keyRepository(), never()).save(any());
    }

    @Test
    void clientInstanceDelegatesPolicyRegistrationAndMirrorsItWithoutApproval() {
        Fixture fixture = fixture(true);
        when(fixture.center().post(eq("/policies/register"), any(),
                eq(TeePolicyService.RegisterResult.class)))
                .thenReturn(new TeePolicyService.RegisterResult(TeeContract.VERSION, "pl-1", "1", "ACTIVE"));
        when(fixture.policyRepository().findById(any())).thenReturn(Optional.empty());

        assertEquals("pl-1", fixture.gateway().registerPolicy("inst-a", policyRequest()).policyId());
        verifyNoInteractions(fixture.policies());
        org.mockito.ArgumentCaptor<TeePolicyDO> saved =
                org.mockito.ArgumentCaptor.forClass(TeePolicyDO.class);
        verify(fixture.policyRepository()).save(saved.capture());
        // 审批核验发生在中心端，本地镜像不得看起来像已在本地核验过。
        assertEquals("", saved.getValue().getApprovalId());
        assertEquals("inst-a", saved.getValue().getOwnerId());
    }

    @Test
    void clientInstanceReadsTheLedgerFromTheCenter() {
        Fixture fixture = fixture(true);
        when(fixture.center().get(eq("/keys"), eq(com.fasterxml.jackson.databind.JsonNode.class))).thenReturn(mapper.createObjectNode()
                .set("items", mapper.createArrayNode().add(mapper.createObjectNode()
                        .put("keyId", "kd-9").put("keyVersion", "1").put("assetId", "asset-1")
                        .put("ownerId", "inst-a").put("state", "ACTIVE")
                        .put("issuedAt", "2026-09-01T00:00:00Z")
                        .put("claimCount", 2).put("releaseCount", 1))));

        List<TeeKeyService.LedgerItem> items = fixture.gateway().ledger("inst-a");
        assertEquals(1, items.size());
        assertEquals(2, items.get(0).claimCount());
        verifyNoInteractions(fixture.keys());
    }

    @Test
    void delegationFlagFollowsTheChannelConfiguration() {
        assertTrue(fixture(true).gateway().delegated());
    }
}
