/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.common.util.EncryptUtils;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeNonceDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeNonceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 可信运行时的密钥放行与结果密钥。
 *
 * <p>顺序固定：验签、时效、去重 → 对象元数据与策略检查 → 环境与密钥放行。
 * 任一环节失败即终止，不会返回任何密钥信封。
 *
 * <p>发起方身份是仿真模式下的关键补偿控制：密钥服务本身不验签发起方，
 * 因此这里要求接收者证书必须是部署时登记的可信运行时证书——
 * 即便有人伪造任务里的身份字段，密封结果也只有登记私钥的持有者能解开。
 */
@Service
public class TeeRuntimeService {

    private final TeeNonceRepository nonces;
    private final TeeKeyService keyService;
    private final TeePolicyService policyService;
    private final TeeAssetService assetService;
    private final KeyAdapterClient adapter;
    private final TeeIdentityRegistry registry;
    private final TeeIdempotency idempotency;
    private final ObjectMapper mapper;

    public TeeRuntimeService(TeeNonceRepository nonces, TeeKeyService keyService, TeePolicyService policyService,
                             TeeAssetService assetService, KeyAdapterClient adapter,
                             TeeIdentityRegistry registry, TeeIdempotency idempotency, ObjectMapper mapper) {
        this.nonces = nonces;
        this.keyService = keyService;
        this.policyService = policyService;
        this.assetService = assetService;
        this.adapter = adapter;
        this.registry = registry;
        this.idempotency = idempotency;
        this.mapper = mapper;
    }

    public record ReleaseRequest(String contractVersion, String requestId, String taskJws,
                                 String attestationEvidence, String recipientCertPem) {
    }

    public record ReleaseResult(String contractVersion, String taskId, String runtimeMode,
                                boolean attestationVerified, List<TeeKeyService.KeyEnvelope> keyEnvelopes) {
    }

    public record OutputKeyRequest(String contractVersion, String requestId, String taskJws,
                                   String resultId, String resultKind, String recipientCertPem) {
    }

    public record OutputKeyResult(String contractVersion, TeeKeyService.KeyEnvelope keyEnvelope) {
    }

    @Transactional
    public ReleaseResult release(String callerId, ReleaseRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        X509Certificate recipient = requireWorkloadCertificate(request.recipientCertPem());
        TeeTaskSpec task = verify(request.taskJws());
        String fingerprint = TeeIdempotency.fingerprint(List.of(task.taskId(), task.nonce(),
                TeeCrypto.certificateSha256(recipient)));
        return idempotency.execute(callerId, "runtime/release", requestId, fingerprint,
                ReleaseResult.class, () -> {
            consumeNonce(task, requestId);
            requireEvidence(request.attestationEvidence());
            List<TeeKeyService.KeyEnvelope> envelopes = new ArrayList<>();
            long total = 0;
            for (TeeTaskSpec.Input input : requireInputs(task)) {
                total += input.plaintextBytes();
                TeeGuard.requireSize(total, TeeContract.MAX_TASK_PLAINTEXT_BYTES);
                envelopes.add(releaseOne(task, input, recipient));
            }
            return new ReleaseResult(TeeContract.VERSION, task.taskId(), "SIMULATION", false, envelopes);
        });
    }

    private TeeKeyService.KeyEnvelope releaseOne(TeeTaskSpec task, TeeTaskSpec.Input input,
                                                 X509Certificate recipient) {
        TeeAssetDO asset = assetService.requireAsset(input.assetId(), input.assetVersion());
        if (!asset.getObjectId().equals(TeeGuard.requireText(input.objectId(), "objectId"))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "任务引用的密文对象与登记不符");
        }
        TeeKeyDO key = keyService.require(input.keyId(), input.keyVersion());
        keyService.requireActive(key);
        if (!key.getAssetId().equals(input.assetId()) || !key.getAssetVersion().equals(input.assetVersion())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密钥与资产版本绑定不符");
        }
        TeeCrypto.EncryptedObject stored = assetService.readObject(asset.getOwnerId(), asset.getObjectId());
        if (!stored.ciphertextSha256().equals(TeeGuard.requireText(input.ciphertextSha256(), "ciphertextSha256"))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "任务声明的密文摘要与存储不符");
        }
        TeePolicyDO policy = policyService.require(input.policyId(), input.policyVersion());
        if (!policy.getAssetId().equals(input.assetId()) || !policy.getAssetVersion().equals(input.assetVersion())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则与资产版本不符");
        }
        if (!policy.getSandboxId().equals(task.sandboxId())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则未覆盖该沙箱");
        }
        // 平台先按登记规则复核一次，密钥服务放行时再按同一规则校验一次。
        policyService.requireAllows(policy, task.columns(), task.operatorId());
        JsonNode sealed = adapter.call("/v1/keys/release-seal", Map.of(
                "resourceUri", key.getResourceUri(),
                "scope", policy.getUpk().getPolicyId(),
                "operator", task.operatorId(),
                "columns", task.columns(),
                "initiatorCertPemB64", TeeCrypto.encode(
                        registry.workloadCertificatePem().getBytes(StandardCharsets.UTF_8)),
                "recipientCertPemB64", TeeKeyService.encodeCertificate(recipient)));
        keyService.countRelease(key);
        return keyService.envelope(key, sealed);
    }

    /** 结果密钥独立签发；结果标识首次申领时与任务原子绑定，已绑定其他任务即拒绝。 */
    @Transactional
    public OutputKeyResult outputKey(String callerId, OutputKeyRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String resultId = TeeGuard.requireText(request.resultId(), "resultId");
        String resultKind = TeeGuard.requireText(request.resultKind(), "resultKind");
        if (!TeeContract.RESULT_KINDS.contains(resultKind) || "REPORT".equals(resultKind)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "只有 DATA 与 MODEL 需要结果密钥");
        }
        X509Certificate recipient = requireWorkloadCertificate(request.recipientCertPem());
        TeeTaskSpec task = verify(request.taskJws());
        String fingerprint = TeeIdempotency.fingerprint(List.of(task.taskId(), resultId, resultKind));
        return idempotency.execute(callerId, "runtime/output-key", requestId, fingerprint,
                OutputKeyResult.class, () -> {
            assetService.taskObjects(task.taskId()).stream()
                    .filter(item -> resultId.equals(item.getResultId()))
                    .findFirst().ifPresent(item -> {
                        if (!task.taskId().equals(item.getTaskId())) {
                            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "结果标识已绑定其他任务");
                        }
                    });
            String assetId = "result-" + resultId;
            TeeKeyService.IssueResult issued = keyService.issue(callerId, new TeeKeyService.IssueRequest(
                    TeeContract.VERSION, requestId + ":result", assetId, task.taskId()));
            TeeKeyDO key = keyService.require(issued.keyId(), issued.keyVersion());
            JsonNode sealed = adapter.call("/v1/keys/escrow-seal", Map.of(
                    "resourceUri", key.getResourceUri(),
                    "recipientCertPemB64", TeeKeyService.encodeCertificate(recipient)));
            keyService.countRelease(key);
            return new OutputKeyResult(TeeContract.VERSION, keyService.envelope(key, sealed));
        });
    }

    /**
     * JWS Compact 验签。
     *
     * <p>签名输入是原始两段 Base64URL 字节拼接，验证时不重新序列化 payload；
     * 未知 kid 或非 RS256 一律拒绝。
     */
    TeeTaskSpec verify(String compact) {
        String[] parts = TeeGuard.requireText(compact, "taskJws").split("\\.");
        if (parts.length != 3) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "任务签名格式不是 JWS Compact");
        }
        JsonNode header;
        try {
            header = mapper.readTree(TeeCrypto.decodeUrl(parts[0]));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "JWS 头无法解析");
        }
        if (!"RS256".equals(header.path("alg").asText())) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "只接受 RS256 签名");
        }
        String signerCertificate = registry.taskSigningCertificate(header.path("kid").asText());
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        boolean valid;
        try {
            // 现有工具接收标准 Base64 签名，这里把 JWS 的无填充 Base64URL 转换回来。
            valid = EncryptUtils.verifySHA256withRSA(signingInput, signerCertificate,
                    TeeCrypto.encode(TeeCrypto.decodeUrl(parts[2])));
        } catch (Exception failure) {
            valid = false;
        }
        if (!valid) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "任务签名校验失败");
        }
        byte[] payload = TeeCrypto.decodeUrl(parts[1]);
        TeeGuard.requireSize(payload.length, TeeContract.MAX_TASK_JSON_BYTES);
        TeeTaskSpec task;
        try {
            task = mapper.readValue(payload, TeeTaskSpec.class);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务载荷不符合契约结构");
        }
        requireTiming(task);
        return task;
    }

    private void requireTiming(TeeTaskSpec task) {
        TeeGuard.requireVersion(task.contractVersion());
        TeeGuard.requireText(task.taskId(), "taskId");
        TeeGuard.requireText(task.issuer(), "issuer");
        TeeGuard.requireText(task.audience(), "audience");
        TeeGuard.requireText(task.sandboxId(), "sandboxId");
        TeeGuard.requireText(task.operatorId(), "operatorId");
        TeeGuard.requireText(task.nonce(), "nonce");
        TeeGuard.requireGrantSet(task.columns(), "列");
        Instant issuedAt = TeeGuard.requireInstant(task.issuedAt(), "issuedAt");
        Instant expiresAt = TeeGuard.requireInstant(task.expiresAt(), "expiresAt");
        if (expiresAt.isAfter(issuedAt.plusSeconds(TeeContract.MAX_TASK_LIFETIME_SECONDS))) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务有效期超过契约上限");
        }
        TeeGuard.requireNotExpired(expiresAt, TeeContract.Error.TASK_EXPIRED, "签名任务已过期");
        if (Instant.now().plusSeconds(TeeContract.CLOCK_SKEW_SECONDS).isBefore(issuedAt)) {
            throw TeeException.of(TeeContract.Error.TASK_EXPIRED, "任务签发时间超出时钟容差");
        }
        TeeGuard.requireText(task.runtimeImageDigest(), "runtimeImageDigest");
        requireOutputPolicy(task);
    }

    private void requireOutputPolicy(TeeTaskSpec task) {
        TeeTaskSpec.OutputPolicy policy = task.outputPolicy();
        if (policy == null || !policy.encryptData() || !policy.encryptModel()
                || !policy.exportRequiresAllContributors()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "出域策略不符合契约固定取值");
        }
        TeeGuard.requireReportKinds(policy.reportKinds());
    }

    private List<TeeTaskSpec.Input> requireInputs(TeeTaskSpec task) {
        List<TeeTaskSpec.Input> inputs = Optional.ofNullable(task.inputs()).orElse(List.of());
        if (inputs.isEmpty()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务没有输入");
        }
        return inputs;
    }

    /** 证据为空只能进入显式配置的 SIMULATION，绝不作为 HARDWARE 失败后的回退。 */
    private void requireEvidence(String attestationEvidence) {
        if (attestationEvidence != null && !attestationEvidence.isBlank()) {
            throw TeeException.of(TeeContract.Error.REAL_MODE_UNAVAILABLE,
                    "当前部署为仿真模式，不接受硬件证明；具备硬件后按部署切换");
        }
    }

    /** 接收者必须是部署时登记的可信运行时；这是仿真模式下发起方身份的唯一实质约束。 */
    private X509Certificate requireWorkloadCertificate(String pem) {
        X509Certificate certificate = TeeCrypto.certificate(TeeGuard.requireText(pem, "recipientCertPem"));
        if (!TeeCrypto.certificateSha256(certificate).equals(registry.workloadFingerprint())) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "接收者不是已登记的可信运行时");
        }
        return certificate;
    }

    /** nonce 按签发方全局去重；同一 requestId 的已接受重试由幂等层先行返回原结果。 */
    private void consumeNonce(TeeTaskSpec task, String requestId) {
        TeeNonceDO.UPK upk = new TeeNonceDO.UPK(task.issuer(), task.nonce());
        Optional<TeeNonceDO> existing = nonces.findById(upk);
        if (existing.isPresent() && !existing.get().getRequestId().equals(requestId)) {
            throw TeeException.of(TeeContract.Error.TASK_REPLAYED, "新请求复用了已消费的 nonce");
        }
        if (existing.isEmpty()) {
            nonces.save(TeeNonceDO.builder().upk(upk).taskId(task.taskId()).requestId(requestId)
                    .expiresAt(Instant.parse(task.expiresAt())
                            .plusSeconds(TeeContract.RETENTION_SECONDS).toString())
                    .build());
        }
    }
}
