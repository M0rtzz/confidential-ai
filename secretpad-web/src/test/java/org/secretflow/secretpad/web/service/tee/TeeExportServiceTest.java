/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeExportRequestDO;
import org.secretflow.secretpad.persistence.entity.TeeExportVoteDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.repository.TeeExportRequestRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportVoteRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** P7 导出审批在进入密钥路径前必须完成类型、贡献方和当前机构票权校验。 */
class TeeExportServiceTest {

    private final TeeExportRequestRepository requests = mock(TeeExportRequestRepository.class);
    private final TeeExportVoteRepository votes = mock(TeeExportVoteRepository.class);
    private final TeeObjectRepository objects = mock(TeeObjectRepository.class);
    private final TeeRuntimeTaskRepository tasks = mock(TeeRuntimeTaskRepository.class);
    private final TeeIdentityRegistry registry = mock(TeeIdentityRegistry.class);
    private final TeeIdempotency idempotency = mock(TeeIdempotency.class);
    private final TeeExportService service = new TeeExportService(requests, votes, objects, tasks,
            mock(TeeAssetService.class), mock(TeePolicyService.class), mock(TeeKeyService.class),
            mock(KeyAdapterClient.class), registry, idempotency,
            mock(DataSandboxMvpService.class), new ObjectMapper());

    @Test
    void reportCannotCreateExportRequest() {
        when(objects.findByResultId("report-1")).thenReturn(List.of(object("REPORT", "[\"inst-a\"]")));

        TeeException rejected = assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                new TeeExportService.CreateRequest(TeeContract.VERSION, "req-1", "report-1", "pem")));

        assertEquals(TeeContract.Error.CONTRACT_INVALID, rejected.error());
    }

    @Test
    void institutionOutsideContributorsCannotCreateRequest() {
        when(objects.findByResultId("result-1")).thenReturn(List.of(object("DATA", "[\"inst-a\"]")));

        TeeException rejected = assertThrows(TeeException.class, () -> service.create("inst-b", "bob",
                new TeeExportService.CreateRequest(TeeContract.VERSION, "req-2", "result-1", "pem")));

        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, rejected.error());
    }

    @Test
    void detailExposesOnlyCurrentInstitutionActions() {
        TeeExportRequestDO request = TeeExportRequestDO.builder()
                .upk(new TeeExportRequestDO.UPK("exp-1"))
                .resultId("result-1").objectId("object-1").kind("DATA").taskId("task-1")
                .ciphertextSha256("sha256").keyId("kd-1").keyVersion("1")
                .requesterOwnerId("inst-a").recipientCertSha256("cert")
                .requestId("req-3").status("PENDING_APPROVAL").approvedAt("").build();
        TeeExportVoteDO vote = TeeExportVoteDO.builder()
                .upk(new TeeExportVoteDO.UPK("exp-1", "inst-a"))
                .status("PENDING").voter("").comment("").votedAt("").build();
        when(requests.findById(new TeeExportRequestDO.UPK("exp-1"))).thenReturn(Optional.of(request));
        when(votes.findById(new TeeExportVoteDO.UPK("exp-1", "inst-a"))).thenReturn(Optional.of(vote));
        when(votes.findByUpkExportIdOrderByUpkVoterOwnerId("exp-1")).thenReturn(List.of(vote));

        TeeExportService.RequestView detail = service.detail("inst-a", "exp-1");

        assertTrue(detail.canVote());
        assertTrue(detail.canCancel());
        assertEquals("PENDING", detail.votes().get(0).status());
    }

    @Test
    void rejectionRequiresCommentBeforeLookingUpTheRequest() {
        TeeException rejected = assertThrows(TeeException.class, () -> service.action("inst-a", "alice",
                "exp-1", new TeeExportService.ActionRequest(TeeContract.VERSION, "REJECT", " ")));

        assertEquals(TeeContract.Error.CONTRACT_INVALID, rejected.error());
    }

    @Test
    void retrievalRechecksCertificateBeforeIdempotencyCache() throws Exception {
        TeeExportRequestDO request = TeeExportRequestDO.builder()
                .upk(new TeeExportRequestDO.UPK("exp-2"))
                .resultId("result-2").objectId("object-2").kind("DATA").taskId("task-2")
                .ciphertextSha256("sha256").keyId("kd-2").keyVersion("1")
                .requesterOwnerId("inst-a").recipientCertSha256("different")
                .requestId("req-4").status("APPROVED").approvedAt("2026-09-03T00:00:00Z").build();
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(requests.findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(
                "result-2", "inst-a", "APPROVED")).thenReturn(List.of(request));
        when(registry.requireInstitutionCertificate("inst-a", "pem")).thenReturn(certificate);

        TeeException rejected = assertThrows(TeeException.class, () -> service.export("inst-a", "alice",
                "result-2", new TeeExportService.ExportRequest(TeeContract.VERSION, "req-5", "pem")));

        assertEquals(TeeContract.Error.ASSET_OWNER_MISMATCH, rejected.error());
        verifyNoInteractions(idempotency);
    }

    private TeeObjectDO object(String kind, String contributors) {
        return TeeObjectDO.builder().upk(new TeeObjectDO.UPK("object-1"))
                .kind(kind).ownerId("runtime").taskId("task-1").resultId(
                        "REPORT".equals(kind) ? "report-1" : "result-1")
                .keyId("kd-1").keyVersion("1").ciphertextSha256("sha256")
                .sizeBytes(10L).contributorsJson(contributors).exportState("PENDING_APPROVAL").build();
    }
}
