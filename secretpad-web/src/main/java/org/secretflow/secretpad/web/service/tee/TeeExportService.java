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
import java.time.ZoneOffset;
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
                                String recipientCertPem, String exportUntil, String purpose) {
    }

    public record ActionRequest(String contractVersion, String action, String comment) {
    }

    public record CancelRequest(String contractVersion) {
    }

    public record ExportRequest(String contractVersion, String requestId, String recipientCertPem,
                                String exportId) {
    }

    public record VoteView(String ownerId, String status, String voter, String comment, String votedAt) {
    }

    public record RequestView(String contractVersion, String exportId, String resultId, String objectId,
                              String kind, String taskId, String ciphertextSha256, String keyId,
                              String keyVersion, String requesterOwnerId, String recipientCertSha256,
                              String status, String approvedAt, boolean canVote, boolean canCancel,
                              List<VoteView> votes, String resultName, String projectId, String projectName,
                              String sandboxId, String sandboxName, String taskName, String runId,
                              String createdAt, String viewUntil, String maxExportUntil,
                              String requestedAt, String exportUntil, String effectiveExportUntil,
                              String purpose, String accessStatus, boolean canDownload,
                              String disabledReason, String serverTime) {
    }

    public record ListResult(String contractVersion, List<RequestView> items, String serverTime) {
        public ListResult(String contractVersion, List<RequestView> items) {
            this(contractVersion, items, Instant.now().toString());
        }
    }

    public record ExportResult(String contractVersion, String objectId,
                               TeeKeyService.KeyEnvelope keyEnvelope, String expiresAt) {
    }

    public record ExportableView(String resultId, String objectId, String kind, String taskId,
                                 String ciphertextSha256, String keyId, String keyVersion,
                                 Long sizeBytes, List<String> contributors, String exportState,
                                 String latestExportId, String latestStatus, String latestAccessStatus,
                                 String resultName, String projectId, String projectName,
                                 String sandboxId, String sandboxName, String taskName, String runId,
                                 String createdAt, String viewUntil, String maxExportUntil,
                                 boolean canApply, String disabledReason, String serverTime) {
    }

    public record ExportableResult(String contractVersion, List<ExportableView> items, String serverTime) {
        public ExportableResult(String contractVersion, List<ExportableView> items) {
            this(contractVersion, items, Instant.now().toString());
        }
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
    private final TeeResultMetadataService metadata;

    public TeeExportService(TeeExportRequestRepository requests, TeeExportVoteRepository votes,
                            TeeObjectRepository objects, TeeRuntimeTaskRepository tasks,
                            TeeAssetService assets, TeePolicyService policies, TeeKeyService keys,
                            KeyAdapterClient adapter, TeeIdentityRegistry registry,
                            TeeIdempotency idempotency, DataSandboxMvpService mvp,
                            ObjectMapper mapper, TeeResultMetadataService metadata) {
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
        this.metadata = metadata;
    }

    /** 建单时冻结结果版本、贡献机构和接收者证书指纹；发起机构也必须投票。 */
    @Transactional
    public synchronized RequestView create(String ownerId, String actor, CreateRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String resultId = TeeGuard.requireText(request.resultId(), "resultId");
        TeeObjectDO object = resultObject(resultId);
        requireExportableKind(object.getKind());
        List<String> contributors = contributors(object);
        if (!contributors.contains(ownerId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "发起机构不是结果贡献方");
        }
        String exportUntil = TeeGuard.requireInstant(request.exportUntil(), "exportUntil").toString();
        String purpose = TeeGuard.requireText(request.purpose(), "purpose");
        if (purpose.length() > 1000) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "申请用途不能超过 1000 个字符");
        }
        X509Certificate recipient = registry.requireInstitutionCertificate(ownerId,
                request.recipientCertPem());
        String certSha256 = TeeCrypto.certificateSha256(recipient);
        TeeExportRequestDO existing = requests.findByRequestId(requestId).orElse(null);
        if (existing != null) {
            if (!sameFrozenRequest(existing, ownerId, object, certSha256)
                    || !exportUntil.equals(existing.getExportUntil()) || !purpose.equals(existing.getPurpose())) {
                throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT,
                        "requestId 已绑定其他导出内容");
            }
            return view(existing, ownerId);
        }
        requireSucceededResult(object);
        Deadline deadline = deadline(object);
        requireDeadline(deadline);
        Instant requestedUntil = Instant.parse(exportUntil);
        if (!Instant.now().isBefore(requestedUntil) || requestedUntil.isAfter(deadline.until())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "导出截止时间必须在当前时间之后且不超过授权上限");
        }
        if (activeRequest(ownerId, object) != null) {
            throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT, "该结果已有有效导出工单，请查看已有申请");
        }
        String exportId = "exp-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        TeeExportRequestDO created = TeeExportRequestDO.builder()
                .upk(new TeeExportRequestDO.UPK(exportId))
                .resultId(resultId).objectId(object.getUpk().getObjectId()).kind(object.getKind())
                .taskId(TeeGuard.requireText(object.getTaskId(), "taskId"))
                .ciphertextSha256(object.getCiphertextSha256())
                .keyId(object.getKeyId()).keyVersion(object.getKeyVersion())
                .requesterOwnerId(ownerId).recipientCertSha256(certSha256)
                .requestId(requestId).status(PENDING).approvedAt("")
                .exportUntil(exportUntil).purpose(purpose).build();
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
        return catalog(ownerId, false);
    }

    /** 中心端只读查看自己调度任务的产出，不获取数据方工单或解密能力。 */
    public ExportableResult catalog(String ownerId) {
        return catalog(ownerId, true);
    }

    private ExportableResult catalog(String ownerId, boolean centerReadOnly) {
        TeeGuard.requireText(ownerId, "ownerId");
        List<ExportableView> items = new ArrayList<>();
        for (TeeObjectDO object : objects.findByKindInOrderByGmtCreateDesc(EXPORTABLE_KINDS)) {
            List<String> contributors;
            try {
                contributors = contributors(object);
                if (!succeededResult(object) || (centerReadOnly
                        ? !ownsTask(ownerId, object.getTaskId()) : !contributors.contains(ownerId))) {
                    continue;
                }
            } catch (TeeException damaged) {
                // 损坏记录不阻断其他结果，所有写入口仍会重新核对权属和授权。
                continue;
            }
            List<TeeExportRequestDO> owned = centerReadOnly ? List.of() : requests
                    .findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc(object.getResultId(), ownerId);
            TeeExportRequestDO latest = owned.isEmpty() ? null : owned.get(0);
            Deadline limit = deadline(object);
            TeeResultMetadataService.Metadata source = metadata.resolve(object);
            boolean active = limit.available() && Instant.now().isBefore(limit.until());
            boolean hasRequest = owned.stream().anyMatch(item -> activeRequest(item, limit));
            String reason = centerReadOnly ? "请由贡献机构客户端申请导出" : !active ? limit.reason()
                    : hasRequest ? "已有有效导出工单，请查看已有申请" : "";
            items.add(new ExportableView(object.getResultId(), object.getUpk().getObjectId(),
                    object.getKind(), object.getTaskId(), object.getCiphertextSha256(),
                    object.getKeyId(), object.getKeyVersion(), object.getSizeBytes(), contributors,
                    object.getExportState(), latest == null ? "" : latest.getUpk().getExportId(),
                    latest == null ? "" : latest.getStatus(), latest == null ? "" : accessStatus(latest, limit),
                    source.resultName(), source.projectId(), source.projectName(), source.sandboxId(),
                    source.sandboxName(), source.taskName(), source.runId(), source.createdAt(),
                    limit.viewText(), limit.text(),
                    !centerReadOnly && active && !hasRequest, reason, Instant.now().toString()));
        }
        return new ExportableResult(TeeContract.VERSION, items);
    }

    private boolean ownsTask(String ownerId, String taskId) {
        TeeRuntimeTaskDO task = tasks.findById(new TeeRuntimeTaskDO.UPK(taskId)).orElse(null);
        if (task == null) return false;
        String issuer = taskSpec(task.getTaskJws()).issuer();
        String canonical = registry.canonicalInstitutionId(issuer);
        return ownerId.equals(issuer) || ownerId.equals(canonical);
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
                .map(item -> view(item, ownerId))
                .filter(item -> "ACTIVE".equals(item.accessStatus())).toList();
        return new ListResult(TeeContract.VERSION, items);
    }

    /** 已投票工单和不再可处理的工单保留在审批记录中。 */
    public ListResult history(String ownerId) {
        List<RequestView> items = votes.findByUpkVoterOwnerIdOrderByGmtCreateDesc(ownerId).stream()
                .map(vote -> requests.findById(new TeeExportRequestDO.UPK(vote.getUpk().getExportId()))
                        .map(item -> view(item, ownerId)).orElse(null))
                .filter(item -> item != null && (!PENDING.equals(item.status())
                        || !"ACTIVE".equals(item.accessStatus()) || item.votes().stream().anyMatch(vote ->
                        ownerId.equals(vote.ownerId()) && !VOTE_PENDING.equals(vote.status())))).toList();
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
        requireRequestActive(request);
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
        requireRequestActive(request);
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
        TeeExportRequestDO request = approvedRequest(ownerId, resultId, export.exportId());
        X509Certificate recipient = registry.requireInstitutionCertificate(ownerId,
                export.recipientCertPem());
        String recipientSha256 = TeeCrypto.certificateSha256(recipient);
        if (!request.getRecipientCertSha256().equals(recipientSha256)) {
            throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH,
                    "接收者证书与审批记录不符");
        }
        // 幂等命中也必须重新判定业务期限、原授权及密钥状态。
        Instant businessUntil = requireRequestActive(request);
        requireFrozenAndActive(request);
        String fingerprint = TeeIdempotency.fingerprint(List.of(request.getUpk().getExportId(),
                request.getCiphertextSha256(), recipientSha256, request.getExportUntil()));
        ExportResult issued = idempotency.execute(ownerId, "results/export", requestId, fingerprint,
                ExportResult.class, () -> issueEnvelope(ownerId, actor, request, recipient),
                value -> value == null ? null : value.expiresAt());
        Instant effectiveUntil = earlier(TeeGuard.requireInstant(issued.expiresAt(), "expiresAt"),
                earlier(businessUntil, requireRequestActive(request)));
        if (!Instant.now().isBefore(effectiveUntil)) {
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "导出信封或业务授权已过期");
        }
        return new ExportResult(issued.contractVersion(), issued.objectId(), issued.keyEnvelope(),
                effectiveUntil.toString());
    }

    private ExportResult issueEnvelope(String ownerId, String actor, TeeExportRequestDO request,
                                       X509Certificate recipient) {
        Instant businessUntil = requireRequestActive(request);
        TeeKeyDO key = requireFrozenAndActive(request);
        JsonNode sealed = adapter.call("/v1/keys/escrow-seal", Map.of(
                "resourceUri", key.getResourceUri(),
                "recipientCertPemB64", TeeKeyService.encodeCertificate(recipient)));
        keys.countClaim(key);
        String expiresAt = earlier(Instant.now().plusSeconds(TeeContract.EXPORT_TTL_SECONDS),
                earlier(businessUntil, requireRequestActive(request))).toString();
        event(actor, "TEE_RESULT_EGRESS", request, "expiresAt=" + expiresAt);
        return new ExportResult(TeeContract.VERSION, request.getObjectId(), keys.envelope(key, sealed), expiresAt);
    }

    private TeeKeyDO requireFrozenAndActive(TeeExportRequestDO request) {
        TeeObjectDO object = resultObject(request.getResultId());
        if (!sameFrozenResult(request, object)) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "结果版本已变化");
        }
        TeeCrypto.EncryptedObject stored = assets.readObject(request.getRequesterOwnerId(), object.getUpk().getObjectId());
        if (!request.getCiphertextSha256().equals(stored.ciphertextSha256())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文对象摘要已变化");
        }
        requirePoliciesActive(object.getTaskId());
        TeeKeyDO key = keys.require(request.getKeyId(), request.getKeyVersion());
        keys.requireActive(key);
        if (!request.getResultId().equals(key.getAssetId()) || !"1".equals(key.getAssetVersion())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "结果密钥绑定已变化");
        }
        return key;
    }

    private TeeExportRequestDO approvedRequest(String ownerId, String resultId, String exportId) {
        TeeGuard.requireText(resultId, "resultId");
        if (exportId != null && !exportId.isBlank()) {
            TeeExportRequestDO exact = requireRequest(exportId);
            if (!ownerId.equals(exact.getRequesterOwnerId()) || !resultId.equals(exact.getResultId())) {
                throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "工单与结果或接收机构不匹配");
            }
            requireRequestActive(exact);
            if (PENDING.equals(exact.getStatus())) refreshStatus(exact);
            if (APPROVED.equals(exact.getStatus())) return exact;
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "导出工单尚未全票通过");
        }
        for (TeeExportRequestDO approved : requests
                .findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(resultId, ownerId, APPROVED)) {
            if ("ACTIVE".equals(accessStatus(approved, deadline(resultObject(resultId))))) return approved;
        }
        // 取回时仅归并仍有效的待审批工单，过期工单不能被全票状态重新激活。
        for (TeeExportRequestDO candidate : requests
                .findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(resultId, ownerId, PENDING)) {
            if (!"ACTIVE".equals(accessStatus(candidate, deadline(resultObject(resultId))))) continue;
            refreshStatus(candidate);
            if (APPROVED.equals(candidate.getStatus())) return candidate;
        }
        throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "没有仍在有效期内的已批准导出工单");
    }

    private void refreshStatus(TeeExportRequestDO request) {
        requireRequestActive(request);
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
            LinkedHashSet<String> normalized = new LinkedHashSet<>();
            for (String value : TeeGuard.requireGrantSet(values, "贡献方")) {
                String canonical = registry.canonicalInstitutionId(value);
                normalized.add(canonical == null || canonical.isBlank() ? value : canonical);
            }
            return List.copyOf(TeeGuard.requireGrantSet(new ArrayList<>(normalized), "贡献方"));
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
        TeeObjectDO object = objects.findById(new TeeObjectDO.UPK(request.getObjectId())).orElse(null);
        TeeResultMetadataService.Metadata source = metadata.resolve(object == null
                ? TeeObjectDO.builder().upk(new TeeObjectDO.UPK(request.getObjectId()))
                .resultId(request.getResultId()).kind(request.getKind()).taskId(request.getTaskId()).build()
                : object);
        Deadline limit = object == null ? new Deadline(null, "结果对象已不可用") : deadline(object);
        String accessStatus = accessStatus(request, limit);
        boolean active = "ACTIVE".equals(accessStatus);
        boolean canVote = active && PENDING.equals(request.getStatus()) && voteViews.stream()
                .anyMatch(vote -> ownerId.equals(vote.ownerId()) && VOTE_PENDING.equals(vote.status()));
        boolean canCancel = active && PENDING.equals(request.getStatus())
                && ownerId.equals(request.getRequesterOwnerId());
        boolean canDownload = active && APPROVED.equals(request.getStatus())
                && ownerId.equals(request.getRequesterOwnerId());
        String reason = active ? "" : "DEADLINE_REQUIRED".equals(accessStatus)
                ? "历史工单未约定导出期限，请重新申请" : "EXPIRED".equals(accessStatus)
                ? "已超过导出截止时间" : limit.reason();
        return new RequestView(TeeContract.VERSION, request.getUpk().getExportId(),
                request.getResultId(), request.getObjectId(), request.getKind(), request.getTaskId(),
                request.getCiphertextSha256(), request.getKeyId(), request.getKeyVersion(),
                request.getRequesterOwnerId(), request.getRecipientCertSha256(), request.getStatus(),
                request.getApprovedAt(), canVote, canCancel, voteViews,
                source.resultName(), source.projectId(), source.projectName(), source.sandboxId(),
                source.sandboxName(), source.taskName(), source.runId(), source.createdAt(),
                limit.viewText(), limit.text(),
                request.getGmtCreate() == null ? "" : request.getGmtCreate().toInstant(ZoneOffset.UTC).toString(),
                text(request.getExportUntil()), effectiveDeadline(request, limit), text(request.getPurpose()),
                accessStatus, canDownload, reason, Instant.now().toString());
    }

    private record Deadline(Instant until, String reason, Instant viewUntil) {
        Deadline(Instant until, String reason) { this(until, reason, until); }
        boolean available() { return until != null && reason.isBlank(); }
        String text() { return until == null ? "" : until.toString(); }
        String viewText() { return viewUntil == null ? "" : viewUntil.toString(); }
    }

    /** 原任务的授权期限与结果期限取交集，不把五分钟的任务执行凭据当作结果有效期。 */
    private Deadline deadline(TeeObjectDO object) {
        Instant until = null;
        Instant viewUntil = null;
        try {
            TeeResultMetadataService.Metadata source = metadata.resolve(object);
            until = source.maxExportUntil().isBlank() ? null
                    : TeeGuard.requireInstant(source.maxExportUntil(), "maxExportUntil");
            viewUntil = source.viewUntil().isBlank() ? null
                    : TeeGuard.requireInstant(source.viewUntil(), "viewUntil");
            TeeRuntimeTaskDO task = tasks.findById(new TeeRuntimeTaskDO.UPK(object.getTaskId()))
                    .orElseThrow(() -> TeeException.of(TeeContract.Error.POLICY_DENIED, "结果原任务不存在"));
            if (!"SUCCEEDED".equals(task.getStatus()) || !Boolean.TRUE.equals(task.getReceiptVerified())) {
                return new Deadline(until, "结果原任务尚未通过回执核验", viewUntil);
            }
            TeeTaskSpec spec = taskSpec(task.getTaskJws());
            if (spec.inputs() == null || spec.inputs().isEmpty()) {
                return new Deadline(until, "无法确认结果授权期限", viewUntil);
            }
            for (TeeTaskSpec.Input input : spec.inputs()) {
                TeePolicyDO policy = policies.require(input.policyId(), String.valueOf(input.policyVersion()));
                Instant policyUntil = TeeGuard.requireInstant(policy.getExpiresAt(), "policyExpiresAt");
                until = earlier(until, policyUntil);
                viewUntil = earlier(viewUntil, policyUntil);
                if (!TeeContract.STATE_ACTIVE.equals(policy.getState())) {
                    return new Deadline(until, "结果授权已撤销", viewUntil);
                }
                // 业务期限按截止时刻严格失效，不沿用任务凭据的时钟宽限。
                if (Instant.now().isBefore(policyUntil)) {
                    policies.requireAllows(policy, spec.columns(), spec.operatorId());
                }
            }
            if (until == null) return new Deadline(null, "无法确认结果授权期限", viewUntil);
            if (!Instant.now().isBefore(until)) return new Deadline(until, "已超过结果授权期限", viewUntil);
            keys.requireActive(keys.require(object.getKeyId(), object.getKeyVersion()));
            return new Deadline(until, "", viewUntil);
        } catch (TeeException invalid) {
            return new Deadline(until, "结果授权或密钥已失效，无法继续导出", viewUntil);
        }
    }

    private void requireDeadline(Deadline limit) {
        if (!limit.available() || !Instant.now().isBefore(limit.until())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                    limit.reason().isBlank() ? "结果授权已过期" : limit.reason());
        }
    }

    private Instant requireRequestActive(TeeExportRequestDO request) {
        Deadline limit = deadline(resultObject(request.getResultId()));
        if (!"ACTIVE".equals(accessStatus(request, limit))) {
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED,
                    text(request.getExportUntil()).isBlank() ? "历史工单未约定导出期限，请重新申请"
                            : "导出工单或结果授权已失效，请查看有效期");
        }
        return Instant.parse(effectiveDeadline(request, limit));
    }

    private static String effectiveDeadline(TeeExportRequestDO request, Deadline limit) {
        if (text(request.getExportUntil()).isBlank()) return "";
        try {
            return earlier(Instant.parse(request.getExportUntil()), limit.until()).toString();
        } catch (RuntimeException invalid) {
            return "";
        }
    }

    private static String accessStatus(TeeExportRequestDO request, Deadline limit) {
        if (text(request.getExportUntil()).isBlank()) return "DEADLINE_REQUIRED";
        String effective = effectiveDeadline(request, limit);
        if (effective.isBlank()) return "UNAVAILABLE";
        if (!Instant.now().isBefore(Instant.parse(effective))) return "EXPIRED";
        return limit.available() ? "ACTIVE" : "UNAVAILABLE";
    }

    private TeeExportRequestDO activeRequest(String ownerId, TeeObjectDO object) {
        Deadline limit = deadline(object);
        return requests.findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc(object.getResultId(), ownerId)
                .stream().filter(item -> activeRequest(item, limit)).findFirst().orElse(null);
    }

    private static boolean activeRequest(TeeExportRequestDO request, Deadline limit) {
        return (PENDING.equals(request.getStatus()) || APPROVED.equals(request.getStatus()))
                && "ACTIVE".equals(accessStatus(request, limit));
    }

    private static Instant earlier(Instant first, Instant second) {
        if (first == null) return second;
        if (second == null) return first;
        return first.isBefore(second) ? first : second;
    }

    private static String text(String value) { return value == null ? "" : value; }

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
