/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.repository.InstRepository;
import org.secretflow.secretpad.persistence.repository.NodeRepository;
import org.secretflow.secretpad.persistence.repository.NodeRouteRepository;
import org.secretflow.secretpad.persistence.repository.ProjectJobRepository;
import org.secretflow.secretpad.persistence.repository.ProjectNodeRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportRequestRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportVoteRepository;
import org.secretflow.secretpad.persistence.repository.TeeKeyRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 信任链聚合服务：两端可见性差异与密文预览鉴权。 */
class TrustChainServiceTest {

    private static TeeEnvironmentService.Environment emptyEnvironment() {
        return new TeeEnvironmentService.Environment(TeeEnvironmentService.CONTRACT_VERSION, "SIMULATION",
                null, false, new TeeEnvironmentService.DeviceChecks(false, false, false),
                false, false, false, List.of());
    }

    private static TrustChainService newService(TeeCenterClient center, TeeObjectRepository objectRepository,
                                                 TeeObjectStore objectStore, TeeKeyGateway keyGateway,
                                                 TeeExportGateway exportGateway) {
        TeeEnvironmentService environmentService = mock(TeeEnvironmentService.class);
        when(environmentService.environment()).thenReturn(emptyEnvironment());
        TeeKeyRepository keyRepository = mock(TeeKeyRepository.class);
        TeePolicyRepository policyRepository = mock(TeePolicyRepository.class);
        TeeExportRequestRepository exportRequestRepository = mock(TeeExportRequestRepository.class);
        TeeExportVoteRepository exportVoteRepository = mock(TeeExportVoteRepository.class);
        TeeRuntimeTaskRepository taskRepository = mock(TeeRuntimeTaskRepository.class);
        NodeRepository nodeRepository = mock(NodeRepository.class);
        NodeRouteRepository nodeRouteRepository = mock(NodeRouteRepository.class);
        InstRepository instRepository = mock(InstRepository.class);
        ProjectNodeRepository projectNodeRepository = mock(ProjectNodeRepository.class);
        ProjectJobRepository projectJobRepository = mock(ProjectJobRepository.class);
        TeeIdentityRegistry identityRegistry = mock(TeeIdentityRegistry.class);
        DataSandboxMvpService mvp = mock(DataSandboxMvpService.class);
        when(projectNodeRepository.findByNodeId(anyString())).thenReturn(List.of());
        TrustChainService service = new TrustChainService(center, environmentService, keyRepository, keyGateway,
                policyRepository, objectRepository, objectStore, exportRequestRepository, exportVoteRepository,
                exportGateway, taskRepository, nodeRepository, nodeRouteRepository, instRepository,
                projectNodeRepository, projectJobRepository, identityRegistry, mvp, new ObjectMapper());
        ReflectionTestUtils.setField(service, "allowedEndRoles", "CENTER,CLIENT");
        ReflectionTestUtils.setField(service, "runtimeImageId", "");
        return service;
    }

    @Test
    void clientInstanceSummaryOnlyReturnsFourSegments() {
        TeeCenterClient center = mock(TeeCenterClient.class);
        when(center.configured()).thenReturn(true);
        TeeObjectRepository objectRepository = mock(TeeObjectRepository.class);
        when(objectRepository.findTop200ByOwnerIdOrderByGmtCreateDesc(anyString())).thenReturn(List.of());
        TeeKeyGateway keyGateway = mock(TeeKeyGateway.class);
        when(keyGateway.ledger(anyString())).thenReturn(List.of());
        TeeExportGateway exportGateway = mock(TeeExportGateway.class);
        when(exportGateway.exportable(anyString()))
                .thenReturn(new TeeExportService.ExportableResult(TeeContract.VERSION, List.of()));
        when(exportGateway.mine(anyString()))
                .thenReturn(new TeeExportService.ListResult(TeeContract.VERSION, List.of()));
        TrustChainService service = newService(center, objectRepository, mock(TeeObjectStore.class),
                keyGateway, exportGateway);

        TrustChainService.SummaryView summary = service.summary("inst-a", "机构 A");

        List<String> keys = summary.segments().stream().map(TrustChainService.Segment::key).toList();
        assertEquals(4, keys.size());
        assertEquals(List.of("KEY_ISSUE", "DATA_ENCRYPT", "ATTESTATION", "EGRESS"), keys);
        assertFalse(keys.contains("POLICY_CHECK"));
        assertFalse(keys.contains("TEE_EXEC"));
    }

    @Test
    void centerInstanceSummaryReturnsAllSixSegments() {
        TeeCenterClient center = mock(TeeCenterClient.class);
        when(center.configured()).thenReturn(false);
        TeeObjectRepository objectRepository = mock(TeeObjectRepository.class);
        when(objectRepository.findTop200ByOrderByGmtCreateDesc()).thenReturn(List.of());
        // 中心端不经由委派网关，两个 mock 不打桩即可暴露误用（Mockito 默认返回 null 会在使用处报错）。
        TrustChainService service = newService(center, objectRepository, mock(TeeObjectStore.class),
                mock(TeeKeyGateway.class), mock(TeeExportGateway.class));

        TrustChainService.SummaryView summary = service.summary("center-owner", "中心机构");

        List<String> keys = summary.segments().stream().map(TrustChainService.Segment::key).toList();
        assertEquals(6, keys.size());
        assertTrue(keys.containsAll(List.of("KEY_ISSUE", "DATA_ENCRYPT", "POLICY_CHECK",
                "ATTESTATION", "TEE_EXEC", "EGRESS")));
    }

    @Test
    void previewDeniedForNonContributingInstitution() {
        TeeCenterClient center = mock(TeeCenterClient.class);
        when(center.configured()).thenReturn(true); // 本实例是客户端，不是中心端豁免访问。
        TeeObjectRepository objectRepository = mock(TeeObjectRepository.class);
        TeeObjectDO object = TeeObjectDO.builder()
                .upk(new TeeObjectDO.UPK("obj-1")).kind("DATA").ownerId("inst-owner")
                .keyId("kd-1").keyVersion("1").ciphertextSha256("sha").sizeBytes(10L)
                .contributorsJson("[\"inst-owner\"]").exportState("PENDING_APPROVAL").build();
        when(objectRepository.findById(new TeeObjectDO.UPK("obj-1"))).thenReturn(Optional.of(object));
        TrustChainService service = newService(center, objectRepository, mock(TeeObjectStore.class),
                mock(TeeKeyGateway.class), mock(TeeExportGateway.class));

        TeeException refused = assertThrows(TeeException.class,
                () -> service.preview("inst-other", "obj-1"));

        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, refused.error());
    }
}
