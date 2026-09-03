/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        when(center.configured()).thenReturn(true);
        when(key.certificatePem()).thenReturn("managed-pem");
        TeeExportService.RequestView response = mock(TeeExportService.RequestView.class);
        when(center.post(eq("/exports"), any(), eq(TeeExportService.RequestView.class)))
                .thenReturn(response);
        TeeExportGateway gateway = new TeeExportGateway(service, center, key, new ObjectMapper());

        gateway.create("inst-a", "alice", new TeeExportService.CreateRequest(
                TeeContract.VERSION, "req-1", "result-1", ""));

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
        when(center.configured()).thenReturn(false);
        when(key.certificatePem()).thenReturn("managed-pem");
        TeeExportService.RequestView response = mock(TeeExportService.RequestView.class);
        when(service.create(eq("inst-a"), eq("alice"), any())).thenReturn(response);
        TeeExportGateway gateway = new TeeExportGateway(service, center, key, new ObjectMapper());

        gateway.create("inst-a", "alice", new TeeExportService.CreateRequest(
                TeeContract.VERSION, "req-2", "result-2", null));

        verify(service).create(eq("inst-a"), eq("alice"), any());
        verify(center, never()).post(any(), any(), any());
    }
}
