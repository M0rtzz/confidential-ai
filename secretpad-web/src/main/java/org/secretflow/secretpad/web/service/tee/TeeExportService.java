/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** P7 结果导出审批；权威工单、票据和密钥信封只在中心端生成。 */
@Service
public class TeeExportService {

    private static final String PENDING = "PENDING_APPROVAL";
    private static final String APPROVED = "APPROVED";
    private static final String REJECTED = "REJECTED";
    private static final String CANCELLED = "CANCELLED";
    private static final String VOTE_PENDING = "PENDING";
    private static final List<String> EXPORTABLE_KINDS = List.of("DATA", "MODEL");

    public record CreateRequest(String contractVersion, String requestId, String resultId,
                                String recipientCertPem) {
    }

    public record ActionRequest(String contractVersion, String action, String comment) {
    }

    public record CancelRequest(String contractVersion) {
    }

    public record ExportRequest(String contractVersion, String requestId, String recipientCertPem) {
    }

    public record VoteView(String ownerId, String status, String voter, String comment, String votedAt) {
    }

    public record RequestView(String contractVersion, String exportId, String resultId, String objectId,
                              String kind, String taskId, String ciphertextSha256, String keyId,
                              String keyVersion, String requesterOwnerId, String recipientCertSha256,
                              String status, String approvedAt, boolean canVote, boolean canCancel,
                              List<VoteView> votes) {
    }

    public record ListResult(String contractVersion, List<RequestView> items) {
    }

    public record ExportResult(String contractVersion, String objectId,
                               TeeKeyService.KeyEnvelope keyEnvelope, String expiresAt) {
    }

    public record ExportableView(String resultId, String objectId, String kind, String taskId,
                                 String ciphertextSha256, String keyId, String keyVersion,
                                 Long sizeBytes, List<String> contributors, String exportState,
                                 String latestExportId, String latestStatus) {
    }

    public record ExportableResult(String contractVersion, List<ExportableView> items) {
    }

    private final TeeExportRequestRepository requests;
    private final TeeExportVoteRepository votes;
    private final TeeObjectRepository objects;
    private final TeeRuntimeTaskRepository tasks;
    private final TeeAssetService assets;
    private final TeePolicyService policies;
    private final TeeKeyService keys;
    private final KeyAdapterClient adapter;
    private final TeeIdentityRegistry registry;
    private final TeeIdempotency idempotency;
    private final DataSandboxMvpService mvp;
    private final ObjectMapper mapper;

    public TeeExportService(TeeExportRequestRepository requests, TeeExportVoteRepository votes,
                            TeeObjectRepository objects, TeeRuntimeTaskRepository tasks,
                            TeeAssetService assets, TeePolicyService policies, TeeKeyService keys,
                            KeyAdapterClient adapter, TeeIdentityRegistry registry,
                            TeeIdempotency idempotency, DataSandboxMvpService mvp,
                            ObjectMapper mapper) {
        this.requests = requests;
        this.votes = votes;
        this.objects = objects;
        this.tasks = tasks;
        this.assets = assets;
        this.policies = policies;
        this.keys = keys;
        this.adapter = adapter;
        this.registry = registry;
        this.idempotency = idempotency;
        this.mvp = mvp;
        this.mapper = mapper;
    }

    /** 建单时冻结结果版本、贡献机构和接收者证书指纹；发起机构也必须投票。 */
    @Transactional
    public RequestView create(String ownerId, String actor, CreateRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String resultId = TeeGuard.requireText(request.resultId(), "resultId");
        TeeObjectDO object = resultObject(resultId);
        requireExportableKind(object.getKind());
        List<String> contributors = contributors(object);
        if (!contributors.contains(ownerId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "发起机构不是结果贡献方");
        }
        X509Certificate recipient = registry.requireInstitutionCertificate(ownerId,
                request.recipientCertPem());
        String certSha256 = TeeCrypto.certificateSha256(recipient);
        TeeExportRequestDO existing = requests.findByRequestId(requestId).orElse(null);
        if (existing != null) {
            if (!sameFrozenRequest(existing, ownerId, object, certSha256)) {
                throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT,
                        "requestId 已绑定其他导出内容");
            }
            return view(existing, ownerId);
        }
        requireSucceededResult(object);
        String exportId = "exp-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        TeeExportRequestDO created = TeeExportRequestDO.builder()
                .upk(new TeeExportRequestDO.UPK(exportId))
                .resultId(resultId).objectId(object.getUpk().getObjectId()).kind(object.getKind())
                .taskId(TeeGuard.requireText(object.getTaskId(), "taskId"))
                .ciphertextSha256(object.getCiphertextSha256())
                .keyId(object.getKeyId()).keyVersion(object.getKeyVersion())
                .requesterOwnerId(ownerId).recipientCertSha256(certSha256)
                .requestId(requestId).status(PENDING).approvedAt("").build();
        requests.save(created);
        for (String contributor : contributors) {
            votes.save(TeeExportVoteDO.builder()
                    .upk(new TeeExportVoteDO.UPK(exportId, contributor))
                    .status(VOTE_PENDING).voter("").comment("").votedAt("").build());
        }
        event(actor, "TEE_EXPORT_SUBMIT", created, "contributors=" + contributors.size());
        return view(created, ownerId);
    }

    /**
     * 本机构可发起导出的密文结果。
     *
     * <p>只列出本机构在贡献方集合内、且原任务已成功并核实回执的 DATA / MODEL 对象；
     * REPORT 按授权规则明文出域，不进这条流水线。
     */
    public ExportableResult exportable(String ownerId) {
        TeeGuard.requireText(ownerId, "ownerId");
        List<ExportableView> items = new ArrayList<>();
        for (TeeObjectDO object : objects.findTop200ByKindInOrderByGmtCreateDesc(EXPORTABLE_KINDS)) {
            List<String> contributors;
            try {
                contributors = contributors(object);
            } catch (TeeException damaged) {
                // 单条记录损坏不应让整张列表不可用；该结果建单时仍会被拒绝。
                continue;
            }
            if (!contributors.contains(ownerId) || !succeededResult(object)) {
                continue;
            }
            List<TeeExportRequestDO> owned = requests
                    .findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc(object.getResultId(), ownerId);
            TeeExportRequestDO latest = owned.isEmpty() ? null : owned.get(0);
            items.add(new ExportableView(object.getResultId(), object.getUpk().getObjectId(),
                    object.getKind(), object.getTaskId(), object.getCiphertextSha256(),
                    object.getKeyId(), object.getKeyVersion(), object.getSizeBytes(), contributors,
                    object.getExportState(),
                    latest == null ? "" : latest.getUpk().getExportId(),
                    latest == null ? "" : latest.getStatus()));
        }
        return new ExportableResult(TeeContract.VERSION, items);
    }

    public ListResult mine(String ownerId) {
        return new ListResult(TeeContract.VERSION, requests
                .findByRequesterOwnerIdOrderByGmtCreateDesc(ownerId).stream()
                .map(item -> view(item, ownerId)).toList());
    }

    public ListResult pending(String ownerId) {
        List<RequestView> items = votes.findByUpkVoterOwnerIdAndStatusOrderByGmtCreateDesc(
                        ownerId, VOTE_PENDING).stream()
                .map(vote -> requests.findById(new TeeExportRequestDO.UPK(vote.getUpk().getExportId()))
                        .orElse(null))
                .filter(item -> item != null && PENDING.equals(item.getStatus()))
                .map(item -> view(item, ownerId)).toList();
        return new ListResult(TeeContract.VERSION, items);
    }

    public RequestView detail(String ownerId, String exportId) {
        TeeExportRequestDO request = requireRequest(exportId);
        boolean voter = votes.findById(new TeeExportVoteDO.UPK(request.getUpk().getExportId(), ownerId))
                .isPresent();
        if (!request.getRequesterOwnerId().equals(ownerId) && !voter) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "无权查看该导出工单");
        }
        return view(request, ownerId);
    }

    /** 每个贡献机构一票；拒绝立即终止，全票通过后批准。 */
    @Transactional
    public synchronized RequestView action(String ownerId, String actor, String exportId,
                                           ActionRequest action) {
        TeeGuard.requireVersion(action.contractVersion());
        String normalized = TeeGuard.requireText(action.action(), "action").toUpperCase();
        if (!List.of("APPROVE", "REJECT").contains(normalized)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "投票动作无效");
        }
        String comment = action.comment() == null ? "" : action.comment().trim();
        if ("REJECT".equals(normalized) && comment.isBlank()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "拒绝必须填写意见");
        }
        if (comment.length() > 1000) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "审批意见不能超过 1000 个字符");
        }
        TeeExportRequestDO request = requireRequest(exportId);
        if (!PENDING.equals(request.getStatus())) {
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "工单已经结束");
        }
        TeeExportVoteDO vote = votes.findById(new TeeExportVoteDO.UPK(exportId, ownerId))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                        "当前机构不是该结果贡献方"));
        String target = "APPROVE".equals(normalized) ? APPROVED : REJECTED;
        if (!VOTE_PENDING.equals(vote.getStatus()) && !target.equals(vote.getStatus())) {
            throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT, "机构已经提交相反投票");
        }
        if (VOTE_PENDING.equals(vote.getStatus())) {
            vote.setStatus(target);
            vote.setVoter(actor);
            vote.setComment(comment);
            vote.setVotedAt(Instant.now().toString());
            votes.saveAndFlush(vote);
        }
        refreshStatus(request);
        event(actor, "TEE_EXPORT_" + normalized, request, "ownerId=" + ownerId);
        return view(request, ownerId);
    }

    @Transactional
    public synchronized RequestView cancel(String ownerId, String actor, String exportId,
                                           CancelRequest cancel) {
        TeeGuard.requireVersion(cancel.contractVersion());
        TeeExportRequestDO request = requireRequest(exportId);
        if (!request.getRequesterOwnerId().equals(ownerId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "只有发起机构可以撤回");
        }
        if (!PENDING.equals(request.getStatus())) {
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "只有待审批工单可以撤回");
        }
        request.setStatus(CANCELLED);
        requests.save(request);
        refreshObjectState(request.getObjectId());
        event(actor, "TEE_EXPORT_CANCEL", request, "");
        return view(request, ownerId);
    }

    /** 批准后重新核对不可变结果、密钥、原任务规则和接收者，再生成五分钟信封。 */
    @Transactional
    public synchronized ExportResult export(String ownerId, String actor, String resultId,
                                            ExportRequest export) {
        TeeGuard.requireVersion(export.contractVersion());
        String requestId = TeeGuard.requireText(export.requestId(), "requestId");
        TeeExportRequestDO request = approvedRequest(ownerId, resultId);
        X509Certificate recipient = registry.requireInstitutionCertificate(ownerId,
                export.recipientCertPem());
        String recipientSha256 = TeeCrypto.certificateSha256(recipient);
        if (!request.getRecipientCertSha256().equals(recipientSha256)) {
            throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH,
                    "接收者证书与审批记录不符");
        }
        String fingerprint = TeeIdempotency.fingerprint(List.of(request.getUpk().getExportId(),
                request.getCiphertextSha256(), recipientSha256));
        return idempotency.execute(ownerId, "results/export", requestId, fingerprint,
                ExportResult.class, () -> issueEnvelope(ownerId, actor, request, recipient),
                issued -> issued == null ? null : issued.expiresAt());
    }

    private ExportResult issueEnvelope(String ownerId, String actor, TeeExportRequestDO request,
                                       X509Certificate recipient) {
        TeeObjectDO object = resultObject(request.getResultId());
        if (!sameFrozenResult(request, object)) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "结果版本已变化");
        }
        TeeCrypto.EncryptedObject stored = assets.readObject(ownerId, object.getUpk().getObjectId());
        if (!request.getCiphertextSha256().equals(stored.ciphertextSha256())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文对象摘要已变化");
        }
        requirePoliciesActive(object.getTaskId());
        TeeKeyDO key = keys.require(request.getKeyId(), request.getKeyVersion());
        keys.requireActive(key);
        if (!request.getResultId().equals(key.getAssetId()) || !"1".equals(key.getAssetVersion())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "结果密钥绑定已变化");
        }
        JsonNode sealed = adapter.call("/v1/keys/escrow-seal", Map.of(
                "resourceUri", key.getResourceUri(),
                "recipientCertPemB64", TeeKeyService.encodeCertificate(recipient)));
        keys.countClaim(key);
        String expiresAt = Instant.now().plusSeconds(TeeContract.EXPORT_TTL_SECONDS).toString();
        event(actor, "TEE_RESULT_EGRESS", request, "expiresAt=" + expiresAt);
        return new ExportResult(TeeContract.VERSION, request.getObjectId(), keys.envelope(key, sealed), expiresAt);
    }

    private TeeExportRequestDO approvedRequest(String ownerId, String resultId) {
        List<TeeExportRequestDO> approved = requests
                .findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(
                        TeeGuard.requireText(resultId, "resultId"), ownerId, APPROVED);
        if (!approved.isEmpty()) {
            return approved.get(0);
        }
        // 并发投票时由取回路径再归并一次票面，避免两笔事务互相看不到而永久停在待审批。
        for (TeeExportRequestDO candidate : requests
                .findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(resultId, ownerId, PENDING)) {
            refreshStatus(candidate);
            if (APPROVED.equals(candidate.getStatus())) {
                return candidate;
            }
        }
        throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "导出工单尚未全票通过");
    }

    private void refreshStatus(TeeExportRequestDO request) {
        List<TeeExportVoteDO> current = votes.findByUpkExportIdOrderByUpkVoterOwnerId(
                request.getUpk().getExportId());
        if (current.stream().anyMatch(vote -> REJECTED.equals(vote.getStatus()))) {
            request.setStatus(REJECTED);
        } else if (!current.isEmpty() && current.stream().allMatch(vote -> APPROVED.equals(vote.getStatus()))) {
            request.setStatus(APPROVED);
            request.setApprovedAt(Instant.now().toString());
        }
        requests.save(request);
        refreshObjectState(request.getObjectId());
    }

    private void refreshObjectState(String objectId) {
        objects.findById(new TeeObjectDO.UPK(objectId)).ifPresent(object -> {
            boolean approved = !requests.findByObjectIdAndStatus(objectId, APPROVED).isEmpty();
            object.setExportState(approved ? TeeContract.EXPORT_APPROVED : TeeContract.EXPORT_PENDING);
            objects.save(object);
        });
    }

    private void requirePoliciesActive(String taskId) {
        TeeRuntimeTaskDO task = tasks.findById(new TeeRuntimeTaskDO.UPK(taskId))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.POLICY_DENIED, "结果原任务不存在"));
        TeeTaskSpec spec = taskSpec(task.getTaskJws());
        for (TeeTaskSpec.Input input : spec.inputs()) {
            TeePolicyDO policy = policies.require(input.policyId(), String.valueOf(input.policyVersion()));
            policies.requireAllows(policy, spec.columns(), spec.operatorId());
        }
    }

    /** 列表用的成功判定；与 requireSucceededResult 同一口径，只是不抛异常。 */
    private boolean succeededResult(TeeObjectDO object) {
        if (object.getResultId() == null || object.getResultId().isBlank()
                || object.getTaskId() == null || object.getTaskId().isBlank()) {
            return false;
        }
        return tasks.findById(new TeeRuntimeTaskDO.UPK(object.getTaskId()))
                .filter(task -> Boolean.TRUE.equals(task.getReceiptVerified())
                        && "SUCCEEDED".equals(task.getStatus()))
                .isPresent();
    }

    private void requireSucceededResult(TeeObjectDO object) {
        TeeRuntimeTaskDO task = tasks.findById(new TeeRuntimeTaskDO.UPK(
                        TeeGuard.requireText(object.getTaskId(), "taskId")))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.CONTRACT_INVALID, "结果原任务不存在"));
        if (!Boolean.TRUE.equals(task.getReceiptVerified()) || !"SUCCEEDED".equals(task.getStatus())) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "结果没有成功且已核实的执行回执");
        }
    }

    private TeeTaskSpec taskSpec(String compact) {
        try {
            String[] parts = TeeGuard.requireText(compact, "taskJws").split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("JWS");
            }
            return mapper.readValue(TeeCrypto.decodeUrl(parts[1]), TeeTaskSpec.class);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "结果原任务记录损坏");
        }
    }

    private TeeObjectDO resultObject(String resultId) {
        List<TeeObjectDO> found = objects.findByResultId(resultId);
        if (found.size() != 1) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "结果不存在或版本不唯一");
        }
        return found.get(0);
    }

    private void requireExportableKind(String kind) {
        if ("REPORT".equals(kind)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "REPORT 按授权规则明文出域，不创建导出工单");
        }
        if (!EXPORTABLE_KINDS.contains(kind)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "该对象类型不支持导出");
        }
    }

    private List<String> contributors(TeeObjectDO object) {
        try {
            List<String> values = mapper.readerForListOf(String.class).readValue(object.getContributorsJson());
            return List.copyOf(new LinkedHashSet<>(TeeGuard.requireGrantSet(values, "贡献方")));
        } catch (TeeException rejected) {
            throw rejected;
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "贡献方记录损坏");
        }
    }

    private boolean sameFrozenRequest(TeeExportRequestDO request, String ownerId,
                                      TeeObjectDO object, String certSha256) {
        return ownerId.equals(request.getRequesterOwnerId())
                && certSha256.equals(request.getRecipientCertSha256())
                && sameFrozenResult(request, object);
    }

    private boolean sameFrozenResult(TeeExportRequestDO request, TeeObjectDO object) {
        return request.getResultId().equals(object.getResultId())
                && request.getObjectId().equals(object.getUpk().getObjectId())
                && request.getKind().equals(object.getKind())
                && request.getTaskId().equals(object.getTaskId())
                && request.getCiphertextSha256().equals(object.getCiphertextSha256())
                && request.getKeyId().equals(object.getKeyId())
                && request.getKeyVersion().equals(object.getKeyVersion());
    }

    private TeeExportRequestDO requireRequest(String exportId) {
        return requests.findById(new TeeExportRequestDO.UPK(TeeGuard.requireText(exportId, "exportId")))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "导出工单不存在"));
    }

    private RequestView view(TeeExportRequestDO request, String ownerId) {
        List<VoteView> voteViews = votes.findByUpkExportIdOrderByUpkVoterOwnerId(
                        request.getUpk().getExportId()).stream()
                .map(vote -> new VoteView(vote.getUpk().getVoterOwnerId(), vote.getStatus(),
                        vote.getVoter(), vote.getComment(), vote.getVotedAt())).toList();
        boolean canVote = PENDING.equals(request.getStatus()) && voteViews.stream()
                .anyMatch(vote -> ownerId.equals(vote.ownerId()) && VOTE_PENDING.equals(vote.status()));
        boolean canCancel = PENDING.equals(request.getStatus())
                && ownerId.equals(request.getRequesterOwnerId());
        return new RequestView(TeeContract.VERSION, request.getUpk().getExportId(),
                request.getResultId(), request.getObjectId(), request.getKind(), request.getTaskId(),
                request.getCiphertextSha256(), request.getKeyId(), request.getKeyVersion(),
                request.getRequesterOwnerId(), request.getRecipientCertSha256(), request.getStatus(),
                request.getApprovedAt(), canVote, canCancel, voteViews);
    }

    private void event(String actor, String action, TeeExportRequestDO request, String detail) {
        mvp.auditAs("TEE", "INFO", actor, action, "TEE_EXPORT",
                request.getUpk().getExportId(), "stage=EGRESS resultId=" + request.getResultId()
                        + (detail.isBlank() ? "" : " " + detail), true);
        mvp.dispatchWebhooks("tee.export." + action.toLowerCase().replace("tee_export_", "")
                        .replace("tee_result_", ""),
                Map.of("exportId", request.getUpk().getExportId(), "resultId", request.getResultId(),
                        "status", request.getStatus(), "stage", "EGRESS"));
    }
}
