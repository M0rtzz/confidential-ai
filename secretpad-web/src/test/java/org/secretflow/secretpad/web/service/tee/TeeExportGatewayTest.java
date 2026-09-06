/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** 客户端实例只通过中心通道处理导出审批，不在本地保存或裁决工单。 */
class TeeExportGatewayTest {

    @Test
    void clientDelegatesCreateAndInjectsManagedCertificate() {
        TeeExportService service = mock(TeeExportService.class);
        TeeCenterClient center = mock(TeeCenterClient.class);
        TeeInstitutionKey key = mock(TeeInstitutionKey.class);
        DataSandboxMvpService mvp = mock(DataSandboxMvpService.class);
        when(center.configured()).thenReturn(true);
        when(key.certificatePem()).thenReturn("managed-pem");
        TeeExportService.RequestView response = mock(TeeExportService.RequestView.class);
        when(center.post(eq("/exports"), any(), eq(TeeExportService.RequestView.class)))
                .thenReturn(response);
        TeeExportGateway gateway = new TeeExportGateway(service, center, key, mvp, new ObjectMapper());

        gateway.create("inst-a", "alice", new TeeExportService.CreateRequest(
                TeeContract.VERSION, "req-1", "result-1", "",
                "2099-01-01T00:00:00Z", "测试导出"));

        org.mockito.ArgumentCaptor<TeeExportService.CreateRequest> captured =
                org.mockito.ArgumentCaptor.forClass(TeeExportService.CreateRequest.class);
        verify(center).post(eq("/exports"), captured.capture(), eq(TeeExportService.RequestView.class));
        assertEquals("managed-pem", captured.getValue().recipientCertPem());
        verifyNoInteractions(service);
    }

    @Test
    void centerInstanceDecidesLocally() {
        TeeExportService service = mock(TeeExportService.class);
        TeeCenterClient center = mock(TeeCenterClient.class);
        TeeInstitutionKey key = mock(TeeInstitutionKey.class);
        DataSandboxMvpService mvp = mock(DataSandboxMvpService.class);
        when(center.configured()).thenReturn(false);
        when(key.certificatePem()).thenReturn("managed-pem");
        TeeExportService.RequestView response = mock(TeeExportService.RequestView.class);
        when(service.create(eq("inst-a"), eq("alice"), any())).thenReturn(response);
        TeeExportGateway gateway = new TeeExportGateway(service, center, key, mvp, new ObjectMapper());

        gateway.create("inst-a", "alice", new TeeExportService.CreateRequest(
                TeeContract.VERSION, "req-2", "result-2", null,
                "2099-01-01T00:00:00Z", "测试导出"));

        verify(service).create(eq("inst-a"), eq("alice"), any());
        verify(center, never()).post(any(), any(), any());
    }

    @Test
    void centerInstanceRefusesLocalUnsealing() {
        TeeExportService service = mock(TeeExportService.class);
        TeeCenterClient center = mock(TeeCenterClient.class);
        TeeInstitutionKey key = mock(TeeInstitutionKey.class);
        DataSandboxMvpService mvp = mock(DataSandboxMvpService.class);
        when(center.configured()).thenReturn(false);
        TeeExportGateway gateway = new TeeExportGateway(service, center, key, mvp, new ObjectMapper());

        TeeException refused = assertThrows(TeeException.class,
                () -> gateway.download("inst-a", "alice", "exp-1"));

        assertEquals(TeeContract.Error.END_ROLE_DENIED, refused.error());
        verifyNoInteractions(key);
        verifyNoInteractions(service);
    }

    @Test
    void onlyRequesterCanDownload() {
        TeeExportGateway gateway = downloadGateway("inst-owner", "APPROVED");

        TeeException refused = assertThrows(TeeException.class,
                () -> gateway.download("inst-other", "bob", "exp-1"));

        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, refused.error());
    }

    @Test
    void unapprovedRequestCannotBeDownloaded() {
        TeeExportGateway gateway = downloadGateway("inst-a", "PENDING_APPROVAL");

        TeeException refused = assertThrows(TeeException.class,
                () -> gateway.download("inst-a", "alice", "exp-1"));

        assertEquals(TeeContract.Error.EXPORT_NOT_APPROVED, refused.error());
    }

    /** 构造一个已配置中心通道的客户端网关，工单归属与状态按参数给定。 */
    private static TeeExportGateway downloadGateway(String requester, String status) {
        TeeExportService service = mock(TeeExportService.class);
        TeeCenterClient center = mock(TeeCenterClient.class);
        TeeInstitutionKey key = mock(TeeInstitutionKey.class);
        DataSandboxMvpService mvp = mock(DataSandboxMvpService.class);
        when(center.configured()).thenReturn(true);
        TeeExportService.RequestView view = requestView(requester, status, false);
        when(center.get(eq("/exports/exp-1"), eq(TeeExportService.RequestView.class))).thenReturn(view);
        return new TeeExportGateway(service, center, key, mvp, new ObjectMapper());
    }

    @Test
    void delegatedActionsAreAuditedLocally() {
        TeeExportService service = mock(TeeExportService.class);
        TeeCenterClient center = mock(TeeCenterClient.class);
        TeeInstitutionKey key = mock(TeeInstitutionKey.class);
        DataSandboxMvpService mvp = mock(DataSandboxMvpService.class);
        when(center.configured()).thenReturn(true);
        when(key.certificatePem()).thenReturn("managed-pem");
        TeeExportService.RequestView view = requestView("inst-a", "PENDING_APPROVAL", true);
        when(center.post(eq("/exports"), any(), eq(TeeExportService.RequestView.class))).thenReturn(view);
        when(center.post(eq("/exports/exp-1/action"), any(), eq(TeeExportService.RequestView.class)))
                .thenReturn(view);
        TeeExportGateway gateway = new TeeExportGateway(service, center, key, mvp, new ObjectMapper());

        gateway.create("inst-a", "alice", new TeeExportService.CreateRequest(
                TeeContract.VERSION, "req-1", "result-1", "",
                "2099-01-01T00:00:00Z", "测试导出"));
        gateway.action("inst-a", "alice", "exp-1",
                new TeeExportService.ActionRequest(TeeContract.VERSION, "REJECT", "不同意"));

        // 权威台账在中心端，但本机构的统一日志必须能看到本方操作员做过什么。
        verify(mvp).auditAs(eq("TEE"), eq("INFO"), eq("alice"), eq("TEE_EXPORT_SUBMIT"),
                eq("TEE_EXPORT"), eq("exp-1"), org.mockito.ArgumentMatchers.contains("delegated=true"),
                eq(true));
        verify(mvp).auditAs(eq("TEE"), eq("INFO"), eq("alice"), eq("TEE_EXPORT_REJECT"),
                eq("TEE_EXPORT"), eq("exp-1"), org.mockito.ArgumentMatchers.contains("delegated=true"),
                eq(true));
    }

    private static TeeExportService.RequestView requestView(String requester, String status,
                                                             boolean canDownload) {
        return new ObjectMapper().convertValue(Map.ofEntries(
                Map.entry("contractVersion", TeeContract.VERSION),
                Map.entry("exportId", "exp-1"),
                Map.entry("resultId", "result-1"),
                Map.entry("objectId", "object-1"),
                Map.entry("kind", "DATA"),
                Map.entry("taskId", "task-1"),
                Map.entry("ciphertextSha256", "0"),
                Map.entry("keyId", "kd-1"),
                Map.entry("keyVersion", "1"),
                Map.entry("requesterOwnerId", requester),
                Map.entry("recipientCertSha256", "cert"),
                Map.entry("status", status),
                Map.entry("approvedAt", ""),
                Map.entry("canVote", false),
                Map.entry("canCancel", false),
                Map.entry("votes", java.util.List.of()),
                Map.entry("resultName", "结果"),
                Map.entry("projectId", "project-1"),
                Map.entry("projectName", "项目"),
                Map.entry("sandboxId", "sandbox-1"),
                Map.entry("sandboxName", "沙箱"),
                Map.entry("taskName", "任务"),
                Map.entry("runId", "run-1"),
                Map.entry("createdAt", "2098-01-01T00:00:00Z"),
                Map.entry("viewUntil", "2099-01-01T00:00:00Z"),
                Map.entry("maxExportUntil", "2099-01-01T00:00:00Z"),
                Map.entry("requestedAt", "2098-01-01T00:00:00Z"),
                Map.entry("exportUntil", "2099-01-01T00:00:00Z"),
                Map.entry("effectiveExportUntil", "2099-01-01T00:00:00Z"),
                Map.entry("purpose", "测试导出"),
                Map.entry("accessStatus", "ACTIVE"),
                Map.entry("canDownload", canDownload),
                Map.entry("disabledReason", ""),
                Map.entry("serverTime", "2098-01-01T00:00:00Z")),
                TeeExportService.RequestView.class);
    }
}
