/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.TeeExportRequestDO;
import org.secretflow.secretpad.persistence.entity.TeeExportVoteDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeExportRequestRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportVoteRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;

import java.security.cert.X509Certificate;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
    private final TeePolicyService policies = mock(TeePolicyService.class);
    private final TeeResultMetadataService metadata = mock(TeeResultMetadataService.class);
    private final TeeExportService service = new TeeExportService(requests, votes, objects, tasks,
            mock(TeeAssetService.class), policies, mock(TeeKeyService.class),
            mock(KeyAdapterClient.class), registry, idempotency,
            mock(DataSandboxMvpService.class), new ObjectMapper(), metadata);

    @BeforeEach
    void setUp() {
        when(metadata.resolve(any(TeeObjectDO.class))).thenReturn(new TeeResultMetadataService.Metadata(
                "测试结果", "project-1", "项目", "sandbox-1", "沙箱", "任务", "run-1",
                "2098-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"));
        when(tasks.findById(any(TeeRuntimeTaskDO.UPK.class))).thenAnswer(invocation -> {
            TeeRuntimeTaskDO.UPK key = invocation.getArgument(0);
            return Optional.of(task(key.getTaskId()));
        });
        when(policies.require(anyString(), anyString())).thenReturn(TeePolicyDO.builder()
                .state(TeeContract.STATE_ACTIVE).expiresAt("2099-01-01T00:00:00Z")
                .columnsJson("[\"age\"]").operatorsJson("[\"operator-1\"]").build());
    }

    @Test
    void reportCannotCreateExportRequest() {
        when(objects.findByResultId("report-1")).thenReturn(List.of(object("REPORT", "[\"inst-a\"]")));

        TeeException rejected = assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                new TeeExportService.CreateRequest(TeeContract.VERSION, "req-1", "report-1", "pem",
                        "2099-01-01T00:00:00Z", "测试导出")));

        assertEquals(TeeContract.Error.CONTRACT_INVALID, rejected.error());
    }

    @Test
    void institutionOutsideContributorsCannotCreateRequest() {
        when(objects.findByResultId("result-1")).thenReturn(List.of(object("DATA", "[\"inst-a\"]")));

        TeeException rejected = assertThrows(TeeException.class, () -> service.create("inst-b", "bob",
                new TeeExportService.CreateRequest(TeeContract.VERSION, "req-2", "result-1", "pem",
                        "2099-01-01T00:00:00Z", "测试导出")));

        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, rejected.error());
    }

    @Test
    void exportableNormalizesNodeAliasToAuthenticatedInstitution() {
        TeeObjectDO result = object("DATA", "[\"domain-client-a\"]");
        TeeRuntimeTaskDO task = TeeRuntimeTaskDO.builder()
                .upk(new TeeRuntimeTaskDO.UPK("task-1"))
                .status("SUCCEEDED").receiptVerified(true).taskJws(taskJws("task-1")).build();
        when(registry.canonicalInstitutionId("domain-client-a")).thenReturn("inst-a");
        when(objects.findByKindInOrderByGmtCreateDesc(List.of("DATA", "MODEL")))
                .thenReturn(List.of(result));
        when(tasks.findById(new TeeRuntimeTaskDO.UPK("task-1"))).thenReturn(Optional.of(task));
        when(requests.findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc("result-1", "inst-a"))
                .thenReturn(List.of());

        TeeExportService.ExportableResult exportable = service.exportable("inst-a");

        assertEquals(1, exportable.items().size());
        assertEquals(List.of("inst-a"), exportable.items().get(0).contributors());
    }

    @Test
    void detailExposesOnlyCurrentInstitutionActions() {
        TeeExportRequestDO request = TeeExportRequestDO.builder()
                .upk(new TeeExportRequestDO.UPK("exp-1"))
                .resultId("result-1").objectId("object-1").kind("DATA").taskId("task-1")
                .ciphertextSha256("sha256").keyId("kd-1").keyVersion("1")
                .requesterOwnerId("inst-a").recipientCertSha256("cert")
                .requestId("req-3").status("PENDING_APPROVAL").approvedAt("")
                .exportUntil("2099-01-01T00:00:00Z").purpose("测试导出").build();
        TeeExportVoteDO vote = TeeExportVoteDO.builder()
                .upk(new TeeExportVoteDO.UPK("exp-1", "inst-a"))
                .status("PENDING").voter("").comment("").votedAt("").build();
        when(requests.findById(new TeeExportRequestDO.UPK("exp-1"))).thenReturn(Optional.of(request));
        when(objects.findById(new TeeObjectDO.UPK("object-1"))).thenReturn(Optional.of(
                object("DATA", "[\"inst-a\"]", "result-1", "object-1", "task-1")));
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
                .requestId("req-4").status("APPROVED").approvedAt("2026-09-03T00:00:00Z")
                .exportUntil("2099-01-01T00:00:00Z").purpose("测试导出").build();
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(requests.findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(
                "result-2", "inst-a", "APPROVED")).thenReturn(List.of(request));
        when(objects.findByResultId("result-2")).thenReturn(List.of(object(
                "DATA", "[\"inst-a\"]", "result-2", "object-2", "task-2")));
        when(registry.requireInstitutionCertificate("inst-a", "pem")).thenReturn(certificate);

        TeeException rejected = assertThrows(TeeException.class, () -> service.export("inst-a", "alice",
                "result-2", new TeeExportService.ExportRequest(TeeContract.VERSION, "req-5", "pem", null)));

        assertEquals(TeeContract.Error.ASSET_OWNER_MISMATCH, rejected.error());
        verifyNoInteractions(idempotency);
    }

    private TeeObjectDO object(String kind, String contributors) {
        return object(kind, contributors, "REPORT".equals(kind) ? "report-1" : "result-1",
                "object-1", "task-1");
    }

    private TeeObjectDO object(String kind, String contributors, String resultId, String objectId,
                               String taskId) {
        return TeeObjectDO.builder().upk(new TeeObjectDO.UPK(objectId))
                .kind(kind).ownerId("runtime").taskId(taskId).resultId(
                        resultId)
                .keyId("kd-1").keyVersion("1").ciphertextSha256("sha256")
                .sizeBytes(10L).contributorsJson(contributors).exportState("PENDING_APPROVAL").build();
    }

    private static TeeRuntimeTaskDO task(String taskId) {
        return TeeRuntimeTaskDO.builder().upk(new TeeRuntimeTaskDO.UPK(taskId))
                .taskJws(taskJws(taskId)).status("SUCCEEDED").receiptVerified(true).build();
    }

    private static String taskJws(String taskId) {
        String payload = """
                {"contractVersion":"%s","taskId":"%s","requestId":"req-task",
                 "issuer":"inst-a","audience":"tee","sandboxId":"sandbox-1",
                 "operatorId":"operator-1","columns":["age"],
                 "inputs":[{"assetId":"asset-1","assetVersion":1,"keyId":"kd-1",
                 "keyVersion":1,"policyId":"policy-1","policyVersion":1,
                 "objectId":"object-1","ciphertextSha256":"sha256","plaintextBytes":10}],
                 "program":{"kind":"BUILTIN","objectId":"","sha256":"sha256","parameters":{}},
                 "issuedAt":"2098-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z",
                 "nonce":"nonce","outputPolicy":{"reportKinds":[],"encryptData":true,
                 "encryptModel":true,"exportRequiresAllContributors":true},
                 "runtimeImageDigest":"sha256"}
                """.formatted(TeeContract.VERSION, taskId).replaceAll("\\s+", " ");
        return "e30." + TeeCrypto.encodeUrl(payload.getBytes(StandardCharsets.UTF_8)) + ".c2ln";
    }
}
