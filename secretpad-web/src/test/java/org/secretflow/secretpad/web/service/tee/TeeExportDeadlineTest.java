/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.secretflow.secretpad.persistence.entity.TeeExportRequestDO;
import org.secretflow.secretpad.persistence.entity.TeeExportVoteDO;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeExportRequestRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportVoteRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** 业务截止时间贯穿建单、审批、幂等取回与短期信封，不能通过旧工单或重复请求绕过。 */
class TeeExportDeadlineTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final TeeExportRequestRepository requests = mock(TeeExportRequestRepository.class);
    private final TeeExportVoteRepository votes = mock(TeeExportVoteRepository.class);
    private final TeeObjectRepository objects = mock(TeeObjectRepository.class);
    private final TeeRuntimeTaskRepository tasks = mock(TeeRuntimeTaskRepository.class);
    private final TeeAssetService assets = mock(TeeAssetService.class);
    private final TeePolicyService policies = mock(TeePolicyService.class);
    private final TeeKeyService keys = mock(TeeKeyService.class);
    private final KeyAdapterClient adapter = mock(KeyAdapterClient.class);
    private final TeeIdentityRegistry registry = mock(TeeIdentityRegistry.class);
    private final TeeIdempotency idempotency = mock(TeeIdempotency.class);
    private final TeeResultMetadataService metadata = mock(TeeResultMetadataService.class);
    private final TeeExportService service = new TeeExportService(requests, votes, objects, tasks,
            assets, policies, keys, adapter, registry, idempotency, mock(DataSandboxMvpService.class), mapper, metadata);
    private final Instant upperBound = Instant.now().plusSeconds(7200);
    private final TeeObjectDO object = TeeObjectDO.builder().upk(new TeeObjectDO.UPK("object-1"))
            .kind("DATA").taskId("task-1").resultId("result-1").keyId("key-1").keyVersion("1")
            .ciphertextSha256("sha").sizeBytes(100L).contributorsJson("[\"inst-a\",\"inst-b\"]")
            .exportState("PENDING_APPROVAL").build();
    private TeePolicyDO policy;
    private String certificateSha;

    @BeforeEach
    void prepare() throws Exception {
        when(objects.findByResultId("result-1")).thenReturn(List.of(object));
        when(objects.findById(new TeeObjectDO.UPK("object-1"))).thenReturn(Optional.of(object));
        when(objects.findByKindInOrderByGmtCreateDesc(any())).thenReturn(List.of(object));
        when(registry.canonicalInstitutionId(anyString())).thenAnswer(call -> call.getArgument(0));
        when(metadata.resolve(any())).thenReturn(new TeeResultMetadataService.Metadata(
                "收入计算 · 数据", "project-1", "示例项目", "sandbox-1", "示例沙箱", "收入计算", "run-1",
                Instant.now().minusSeconds(600).toString(), upperBound.toString(), upperBound.toString()));
        TeeTaskSpec spec = new TeeTaskSpec(TeeContract.VERSION, "task-1", "task-req", "center-1", "runtime",
                "sandbox-1", "sql.query", List.of("income"),
                List.of(new TeeTaskSpec.Input("asset-1", 1, "input-key", 1, "policy-1", 1, "input-object", "sha", 100)),
                null, Instant.now().minusSeconds(600).toString(), Instant.now().minusSeconds(300).toString(),
                "nonce", new TeeTaskSpec.OutputPolicy(List.of(), true, true, true), "digest");
        // 执行凭据已经过期，结果授权仍有效，两者不能混用。
        String compact = "header." + TeeCrypto.encodeUrl(mapper.writeValueAsBytes(spec)) + ".signature";
        when(tasks.findById(new TeeRuntimeTaskDO.UPK("task-1"))).thenReturn(Optional.of(
                TeeRuntimeTaskDO.builder().upk(new TeeRuntimeTaskDO.UPK("task-1"))
                        .taskJws(compact).status("SUCCEEDED").receiptVerified(true).build()));
        policy = TeePolicyDO.builder().upk(new TeePolicyDO.UPK("policy-1", "1"))
                .state("ACTIVE").expiresAt(upperBound.toString()).build();
        when(policies.require("policy-1", "1")).thenReturn(policy);
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        certificateSha = TeeCrypto.certificateSha256(certificate);
        when(registry.requireInstitutionCertificate("inst-a", "pem")).thenReturn(certificate);
        TeeKeyDO key = TeeKeyDO.builder().upk(new TeeKeyDO.UPK("key-1", "1"))
                .assetId("result-1").assetVersion("1").state("ACTIVE").resourceUri("resource-1").build();
        when(keys.require("key-1", "1")).thenReturn(key);
        when(keys.envelope(eq(key), any())).thenReturn(new TeeKeyService.KeyEnvelope(
                "key-1", "1", "RSA-OAEP-256", certificateSha, "wrapped"));
        when(assets.readObject("inst-a", "object-1")).thenReturn(new TeeCrypto.EncryptedObject(
                TeeContract.VERSION, "result-1", "1", "key-1", "1", "AES-256-GCM", "", "", "", "", "sha"));
        when(adapter.call(eq("/v1/keys/escrow-seal"), any())).thenReturn(mapper.createObjectNode());
    }

    @Test
    void createFreezesBusinessDeadlinePurposeAndSource() {
        String until = Instant.now().plusSeconds(120).toString();
        TeeExportService.RequestView view = service.create("inst-a", "alice", create("req-new", until, " 审计核查 "));
        ArgumentCaptor<TeeExportRequestDO> saved = ArgumentCaptor.forClass(TeeExportRequestDO.class);
        verify(requests).save(saved.capture());
        assertEquals(until, saved.getValue().getExportUntil());
        assertEquals("审计核查", saved.getValue().getPurpose());
        assertEquals("收入计算 · 数据", view.resultName());
        assertEquals("run-1", view.runId());
        assertEquals("ACTIVE", view.accessStatus());
    }

    @Test
    void missingOrExpiredDeadlineCannotCreateRequest() {
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice", create("r1", null, "审计")));
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice", create("r2", Instant.now().toString(), "审计")));
        verify(requests, never()).save(any());
    }

    @Test
    void requestedDeadlineCannotExceedResultOrPolicyLimit() {
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                create("r1", upperBound.plusSeconds(1).toString(), "审计")));
        policy.setExpiresAt(Instant.now().plusSeconds(120).toString());
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                create("r2", Instant.now().plusSeconds(240).toString(), "审计")));
        verify(requests, never()).save(any());
    }

    @Test
    void sameRequestIdCannotChangeDeadlineOrPurpose() {
        TeeExportRequestDO previous = request("exp-1", "PENDING_APPROVAL", Instant.now().plusSeconds(300).toString());
        when(requests.findByRequestId("req-existing")).thenReturn(Optional.of(previous));
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                create("req-existing", Instant.now().plusSeconds(400).toString(), "审计核查")));
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                create("req-existing", previous.getExportUntil(), "其他用途")));
        verify(requests, never()).save(any());
    }

    @Test
    void expiredApprovedRequestNeverReachesEnvelopeOrIdempotency() {
        request("exp-1", "APPROVED", Instant.now().toString());
        assertThrows(TeeException.class, () -> service.export("inst-a", "alice", "result-1", export("exp-1")));
        verifyNoInteractions(adapter, idempotency);
    }

    @Test
    void downloadMustUseSelectedRequestEvenWhenAnotherApprovalIsLive() {
        request("expired", "APPROVED", Instant.now().minusSeconds(1).toString());
        TeeExportRequestDO live = request("live", "APPROVED", Instant.now().plusSeconds(500).toString());
        when(requests.findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc("result-1", "inst-a", "APPROVED"))
                .thenReturn(List.of(live));
        assertThrows(TeeException.class, () -> service.export("inst-a", "alice", "result-1", export("expired")));
        verifyNoInteractions(idempotency);
    }

    @Test
    void oldUnboundedRequestRequiresNewApplication() {
        TeeExportRequestDO old = request("old", "APPROVED", null);
        when(requests.findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc("result-1", "inst-a"))
                .thenReturn(List.of(old));
        TeeExportService.RequestView detail = service.detail("inst-a", "old");
        assertEquals("DEADLINE_REQUIRED", detail.accessStatus());
        assertFalse(detail.canDownload());
        assertFalse(detail.canVote());
        assertTrue(service.exportable("inst-a").items().get(0).canApply());
        service.create("inst-a", "alice", create("replacement", Instant.now().plusSeconds(300).toString(), "审计"));
        verify(requests).save(any());
    }

    @Test
    void liveRequestPreventsDuplicateAndExpiredRequestAllowsNewOne() {
        TeeExportRequestDO previous = request("previous", "PENDING_APPROVAL", Instant.now().plusSeconds(300).toString());
        when(requests.findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc("result-1", "inst-a"))
                .thenReturn(List.of(previous));
        assertFalse(service.exportable("inst-a").items().get(0).canApply());
        assertThrows(TeeException.class, () -> service.create("inst-a", "alice",
                create("r1", Instant.now().plusSeconds(200).toString(), "审计")));
        previous.setExportUntil(Instant.now().minusSeconds(1).toString());
        assertTrue(service.exportable("inst-a").items().get(0).canApply());
    }

    @Test
    void expirationBlocksVotingAndKeepsHistory() {
        request("exp-1", "PENDING_APPROVAL", Instant.now().toString());
        TeeExportVoteDO vote = vote("exp-1", "inst-a", "PENDING");
        when(votes.findById(vote.getUpk())).thenReturn(Optional.of(vote));
        when(votes.findByUpkVoterOwnerIdAndStatusOrderByGmtCreateDesc("inst-a", "PENDING")).thenReturn(List.of(vote));
        when(votes.findByUpkVoterOwnerIdOrderByGmtCreateDesc("inst-a")).thenReturn(List.of(vote));
        assertThrows(TeeException.class, () -> service.action("inst-a", "alice", "exp-1",
                new TeeExportService.ActionRequest(TeeContract.VERSION, "APPROVE", "")));
        assertTrue(service.pending("inst-a").items().isEmpty());
        assertEquals("EXPIRED", service.history("inst-a").items().get(0).accessStatus());
        verify(votes, never()).saveAndFlush(any());
    }

    @Test
    void alreadyVotedPendingRequestRemainsInHistory() {
        request("exp-1", "PENDING_APPROVAL", Instant.now().plusSeconds(300).toString());
        TeeExportVoteDO vote = vote("exp-1", "inst-a", "APPROVED");
        when(votes.findByUpkExportIdOrderByUpkVoterOwnerId("exp-1")).thenReturn(List.of(vote));
        when(votes.findByUpkVoterOwnerIdOrderByGmtCreateDesc("inst-a")).thenReturn(List.of(vote));
        assertEquals(1, service.history("inst-a").items().size());
    }

    @Test
    @SuppressWarnings("unchecked")
    void issuedEnvelopeIsCappedByBusinessDeadline() {
        String until = Instant.now().plusSeconds(60).toString();
        request("exp-1", "APPROVED", until);
        when(idempotency.execute(anyString(), anyString(), anyString(), anyString(), eq(TeeExportService.ExportResult.class), any(), any()))
                .thenAnswer(call -> ((Supplier<TeeExportService.ExportResult>) call.getArgument(5)).get());
        TeeExportService.ExportResult result = service.export("inst-a", "alice", "result-1", export("exp-1"));
        assertEquals(until, result.expiresAt());
        assertTrue(Instant.parse(result.expiresAt()).isAfter(Instant.now()));
        verify(adapter).call(eq("/v1/keys/escrow-seal"), any());
    }

    @Test
    void cachedEnvelopeCannotExtendAChangedPolicy() {
        String until = Instant.now().plusSeconds(600).toString();
        request("exp-1", "APPROVED", until);
        String policyUntil = Instant.now().plusSeconds(30).toString();
        policy.setExpiresAt(policyUntil);
        when(idempotency.execute(anyString(), anyString(), anyString(), anyString(), eq(TeeExportService.ExportResult.class), any(), any()))
                .thenReturn(new TeeExportService.ExportResult(TeeContract.VERSION, "object-1", null, Instant.now().plusSeconds(300).toString()));
        assertEquals(policyUntil, service.export("inst-a", "alice", "result-1", export("exp-1")).expiresAt());
        verifyNoInteractions(adapter);
    }

    @Test
    void revokedPolicyBlocksCachedEnvelope() {
        request("exp-1", "APPROVED", Instant.now().plusSeconds(300).toString());
        policy.setState("REVOKED");
        assertThrows(TeeException.class, () -> service.export("inst-a", "alice", "result-1", export("exp-1")));
        verifyNoInteractions(adapter, idempotency);
    }

    @Test
    void centerCatalogIsReadOnlyAndScopedToTaskIssuer() {
        assertEquals(1, service.catalog("center-1").items().size());
        assertFalse(service.catalog("center-1").items().get(0).canApply());
        assertTrue(service.catalog("other-center").items().isEmpty());
        assertTrue(service.exportable("other-institution").items().isEmpty());
    }

    private TeeExportService.CreateRequest create(String id, String until, String purpose) {
        return new TeeExportService.CreateRequest(TeeContract.VERSION, id, "result-1", "pem", until, purpose);
    }

    private TeeExportService.ExportRequest export(String exportId) {
        return new TeeExportService.ExportRequest(TeeContract.VERSION, "export-request", "pem", exportId);
    }

    private TeeExportRequestDO request(String id, String status, String until) {
        TeeExportRequestDO request = TeeExportRequestDO.builder().upk(new TeeExportRequestDO.UPK(id))
                .resultId("result-1").objectId("object-1").taskId("task-1").kind("DATA")
                .keyId("key-1").keyVersion("1").ciphertextSha256("sha").requesterOwnerId("inst-a")
                .recipientCertSha256(certificateSha).requestId("req-existing").status(status)
                .approvedAt("").exportUntil(until).purpose("审计核查").build();
        when(requests.findById(new TeeExportRequestDO.UPK(id))).thenReturn(Optional.of(request));
        return request;
    }

    private TeeExportVoteDO vote(String exportId, String owner, String status) {
        return TeeExportVoteDO.builder().upk(new TeeExportVoteDO.UPK(exportId, owner))
                .status(status).voter("").comment("").votedAt("").build();
    }
}
