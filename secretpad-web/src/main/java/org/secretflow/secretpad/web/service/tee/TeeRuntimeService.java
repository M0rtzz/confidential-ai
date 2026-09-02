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
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeNonceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

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
    private final TeeRuntimeGrantService grants;
    private final ObjectMapper mapper;

    public TeeRuntimeService(TeeNonceRepository nonces, TeeKeyService keyService, TeePolicyService policyService,
                             TeeAssetService assetService, KeyAdapterClient adapter,
                             TeeIdentityRegistry registry, TeeIdempotency idempotency,
                             TeeRuntimeGrantService grants, ObjectMapper mapper) {
        this.nonces = nonces;
        this.keyService = keyService;
        this.policyService = policyService;
        this.assetService = assetService;
        this.adapter = adapter;
        this.registry = registry;
        this.idempotency = idempotency;
        this.grants = grants;
        this.mapper = mapper;
    }

    public record ReleaseRequest(String contractVersion, String requestId, String taskJws,
                                 String attestationEvidence, String recipientCertPem) {
    }

    public record ReleaseResult(String contractVersion, String taskId, String runtimeMode,
                                boolean attestationVerified, List<TeeKeyService.KeyEnvelope> keyEnvelopes,
                                List<String> contributors) {
    }

    public record OutputKeyRequest(String contractVersion, String requestId, String taskJws,
                                   String resultId, String resultKind, String recipientCertPem) {
    }

    public record OutputKeyResult(String contractVersion, TeeKeyService.KeyEnvelope keyEnvelope) {
    }

    public record ReceiptRequest(String contractVersion, String requestId, String receiptJws) {
    }

    public record ReceiptResult(String contractVersion, String taskId, String receiptJws,
                                boolean signatureVerified) {
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
            List<String> contributors = grants.accept(callerId, task, request.taskJws(),
                    TeeCrypto.certificateSha256(recipient));
            return new ReleaseResult(TeeContract.VERSION, task.taskId(), "SIMULATION", false,
                    envelopes, contributors);
        });
    }

    private TeeKeyService.KeyEnvelope releaseOne(TeeTaskSpec task, TeeTaskSpec.Input input,
                                                 X509Certificate recipient) {
        if (input.assetVersion() <= 0 || input.keyVersion() <= 0
                || input.policyVersion() <= 0 || input.plaintextBytes() < 0) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID,
                    "输入版本必须为正整数且明文大小不得为负");
        }
        TeeGuard.requireText(input.assetId(), "assetId");
        TeeGuard.requireText(input.keyId(), "keyId");
        TeeGuard.requireText(input.policyId(), "policyId");
        String assetVersion = String.valueOf(input.assetVersion());
        String keyVersion = String.valueOf(input.keyVersion());
        String policyVersion = String.valueOf(input.policyVersion());
        TeeAssetDO asset = assetService.requireAsset(input.assetId(), assetVersion);
        if (!asset.getObjectId().equals(TeeGuard.requireText(input.objectId(), "objectId"))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "任务引用的密文对象与登记不符");
        }
        TeeKeyDO key = keyService.require(input.keyId(), keyVersion);
        keyService.requireActive(key);
        if (!key.getAssetId().equals(input.assetId()) || !key.getAssetVersion().equals(assetVersion)) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密钥与资产版本绑定不符");
        }
        TeeCrypto.EncryptedObject stored = assetService.readObject(asset.getOwnerId(), asset.getObjectId());
        if (!stored.ciphertextSha256().equals(TeeGuard.requireText(input.ciphertextSha256(), "ciphertextSha256"))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "任务声明的密文摘要与存储不符");
        }
        TeePolicyDO policy = policyService.require(input.policyId(), policyVersion);
        if (!policy.getAssetId().equals(input.assetId()) || !policy.getAssetVersion().equals(assetVersion)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则与资产版本不符");
        }
        if (!policy.getSandboxId().equals(task.sandboxId())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则未覆盖该沙箱");
        }
        // 平台先按登记规则复核一次，密钥服务放行时再按同一规则校验一次。
        policyService.requireAllows(policy, task.columns(), task.operatorId());
        // 空集合表示任务不申请任何明文报告，是合法且最小权限的请求；只有非空请求
        // 才需要与输入策略的报告白名单求交并校验。
        if (!task.outputPolicy().reportKinds().isEmpty()) {
            TeeGuard.requireSubset(task.outputPolicy().reportKinds(),
                    policyService.reportKinds(policy), "报告类型");
        }
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
        TeeTaskSpec task = verifyAccepted(callerId, request.taskJws());
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
            String assetId = resultId;
            TeeKeyService.IssueResult issued = keyService.issue(callerId, new TeeKeyService.IssueRequest(
                    TeeContract.VERSION, requestId + ":result", assetId, "1"));
            TeeKeyDO key = keyService.require(issued.keyId(), issued.keyVersion());
            JsonNode sealed = adapter.call("/v1/keys/escrow-seal", Map.of(
                    "resourceUri", key.getResourceUri(),
                    "recipientCertPemB64", TeeKeyService.encodeCertificate(recipient)));
            keyService.countRelease(key);
            grants.bindResult(callerId, task.taskId(), resultId, resultKind,
                    key.getUpk().getKeyId(), key.getUpk().getKeyVersion());
            return new OutputKeyResult(TeeContract.VERSION, keyService.envelope(key, sealed));
        });
    }

    /** 验证并保存工作负载证书私钥签发的执行回执。 */
    @Transactional
    public ReceiptResult receipt(String callerId, String taskId, ReceiptRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String pathTaskId = TeeGuard.requireText(taskId, "taskId");
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String receiptJws = TeeGuard.requireText(request.receiptJws(), "receiptJws");
        String fingerprint = TeeIdempotency.fingerprint(List.of(pathTaskId, receiptJws));
        return idempotency.execute(callerId, "tasks/receipt", requestId, fingerprint,
                ReceiptResult.class, () -> {
            TeeRuntimeTaskDO accepted = grants.requireTask(callerId, pathTaskId);
            JsonNode payload = verifyReceiptSignature(accepted, receiptJws);
            validateReceipt(accepted, payload);
            grants.saveReceipt(callerId, pathTaskId, receiptJws, payload.path("status").asText());
            return new ReceiptResult(TeeContract.VERSION, pathTaskId, receiptJws, true);
        });
    }

    public ReceiptResult receipt(String callerId, String taskId) {
        TeeRuntimeTaskDO task = grants.receipt(callerId, taskId);
        return new ReceiptResult(TeeContract.VERSION, task.getUpk().getTaskId(),
                task.getReceiptJws(), true);
    }

    private JsonNode verifyReceiptSignature(TeeRuntimeTaskDO accepted, String compact) {
        String[] parts = compact.split("\\.");
        if (parts.length != 3) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "回执格式不是 JWS Compact");
        }
        try {
            JsonNode header = mapper.readTree(TeeCrypto.decodeUrl(parts[0]));
            if (!"RS256".equals(header.path("alg").asText())
                    || !"JWS".equals(header.path("typ").asText())
                    || !accepted.getWorkloadCertSha256().equals(header.path("kid").asText())) {
                throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID,
                        "回执签名算法、类型或工作负载身份不匹配");
            }
            X509Certificate certificate = TeeCrypto.certificate(registry.workloadCertificatePem());
            if (!accepted.getWorkloadCertSha256().equals(TeeCrypto.certificateSha256(certificate))) {
                throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID,
                        "回执证书不是任务放行时绑定的工作负载证书");
            }
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(TeeCrypto.decodeUrl(parts[2]))) {
                throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "回执签名校验失败");
            }
            byte[] body = TeeCrypto.decodeUrl(parts[1]);
            TeeGuard.requireSize(body.length, TeeContract.MAX_TASK_JSON_BYTES);
            return mapper.readTree(body);
        } catch (TeeException rejected) {
            throw rejected;
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "回执签名或载荷无法解析");
        }
    }

    private void validateReceipt(TeeRuntimeTaskDO accepted, JsonNode receipt) {
        TeeGuard.requireVersion(receipt.path("contractVersion").asText());
        String taskId = accepted.getUpk().getTaskId();
        if (!taskId.equals(receipt.path("taskId").asText())
                || !accepted.getRequestId().equals(receipt.path("requestId").asText())) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执未绑定已接受的任务请求");
        }
        String status = receipt.path("status").asText();
        if (!Set.of("SUCCEEDED", "FAILED", "CANCELLED").contains(status)
                || !"SIMULATION".equals(receipt.path("runtimeMode").asText())
                || receipt.path("attestationVerified").asBoolean(true)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执状态或运行模式不符合部署事实");
        }
        Instant startedAt = TeeGuard.requireInstant(receipt.path("startedAt").asText(), "startedAt");
        Instant finishedAt = TeeGuard.requireInstant(receipt.path("finishedAt").asText(), "finishedAt");
        if (finishedAt.isBefore(startedAt)
                || finishedAt.isAfter(Instant.now().plusSeconds(TeeContract.CLOCK_SKEW_SECONDS))) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执时间范围无效");
        }
        TeeTaskSpec task = storedTask(accepted.getTaskJws());
        if (receipt.path("keyReleaseCount").asInt(-1) != task.inputs().size()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执输入密钥放行数与任务不符");
        }
        requirePolicyVersion(task, receipt.get("policyVersion"));
        JsonNode outputs = receipt.path("outputs");
        if (!outputs.isArray()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执 outputs 必须是数组");
        }
        JsonNode errorCode = receipt.get("errorCode");
        if (!"SUCCEEDED".equals(status)) {
            if (!outputs.isEmpty() || errorCode == null || !errorCode.isTextual()
                    || errorCode.asText().isBlank()) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID,
                        "失败或取消回执必须无输出并给出错误码");
            }
            return;
        }
        if (errorCode != null && !errorCode.isNull()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "成功回执不得携带错误码");
        }
        validateSucceededOutputs(accepted.getCallerId(), task, outputs);
    }

    private TeeTaskSpec storedTask(String taskJws) {
        try {
            String[] parts = taskJws.split("\\.");
            return mapper.readValue(TeeCrypto.decodeUrl(parts[1]), TeeTaskSpec.class);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "已接受任务记录损坏");
        }
    }

    private void requirePolicyVersion(TeeTaskSpec task, JsonNode actual) {
        Set<Long> versions = task.inputs().stream().map(TeeTaskSpec.Input::policyVersion)
                .collect(Collectors.toSet());
        if (versions.size() == 1) {
            if (actual == null || !actual.isIntegralNumber()
                    || actual.asLong() != versions.iterator().next()) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执规则版本摘要不符");
            }
        } else if (actual != null && !actual.isNull()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "多规则版本任务的摘要字段必须为空");
        }
    }

    private void validateSucceededOutputs(String callerId, TeeTaskSpec task, JsonNode outputs) {
        Map<String, org.secretflow.secretpad.persistence.entity.TeeObjectDO> stored =
                assetService.taskObjects(task.taskId()).stream().collect(Collectors.toMap(
                        org.secretflow.secretpad.persistence.entity.TeeObjectDO::getResultId,
                        Function.identity()));
        Map<String, TeeRuntimeGrantService.ResultBinding> bindings =
                grants.resultBindings(callerId, task.taskId());
        Set<String> seen = new HashSet<>();
        List<String> contributors = grants.contributors(callerId, task.taskId());
        for (JsonNode output : outputs) {
            String kind = output.path("kind").asText();
            if ("REPORT".equals(kind)) {
                validateReport(task, output);
                continue;
            }
            if (!Set.of("DATA", "MODEL").contains(kind) || !output.path("encrypted").asBoolean(false)) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执包含未知或未加密结果类型");
            }
            String resultId = TeeGuard.requireText(output.path("resultId").asText(), "resultId");
            if (!seen.add(resultId)) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "回执重复引用结果标识");
            }
            TeeRuntimeGrantService.ResultBinding binding = bindings.get(resultId);
            org.secretflow.secretpad.persistence.entity.TeeObjectDO object = stored.get(resultId);
            if (binding == null || object == null || !kind.equals(binding.kind())
                    || !kind.equals(object.getKind())
                    || !object.getUpk().getObjectId().equals(output.path("objectId").asText())
                    || !binding.keyId().equals(output.path("keyId").asText())
                    || !binding.keyVersion().equals(output.path("keyVersion").asText())
                    || !object.getCiphertextSha256().equals(output.path("ciphertextSha256").asText())
                    || !TeeContract.EXPORT_PENDING.equals(output.path("exportState").asText())
                    || !new LinkedHashSet<>(contributors).equals(jsonStrings(output.path("contributors")))) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED,
                        "回执结果与服务端绑定的密文对象不一致");
            }
        }
        if (!seen.equals(bindings.keySet())) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "成功回执未覆盖全部已申领结果");
        }
    }

    private void validateReport(TeeTaskSpec task, JsonNode output) {
        String reportKind = output.path("reportKind").asText();
        JsonNode content = output.get("content");
        if (!task.outputPolicy().reportKinds().contains(reportKind)
                || !TeeContract.REPORT_KINDS.contains(reportKind)
                || output.path("encrypted").asBoolean(true) || content == null || !content.isObject()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "报告类型或结构不在签名白名单内");
        }
        try {
            TeeGuard.requireSize(mapper.writeValueAsBytes(content).length, TeeContract.MAX_REPORT_BYTES);
        } catch (TeeException rejected) {
            throw rejected;
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "报告内容无法序列化");
        }
    }

    private LinkedHashSet<String> jsonStrings(JsonNode values) {
        if (!values.isArray() || values.isEmpty()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "贡献方列表为空或结构错误");
        }
        LinkedHashSet<String> result = new LinkedHashSet<>();
        values.forEach(value -> result.add(TeeGuard.requireText(value.asText(), "contributor")));
        return result;
    }

    /**
     * JWS Compact 验签。
     *
     * <p>签名输入是原始两段 Base64URL 字节拼接，验证时不重新序列化 payload；
     * 未知 kid 或非 RS256 一律拒绝。
     */
    TeeTaskSpec verify(String compact) {
        TeeTaskSpec task = verifySignature(compact);
        requireTiming(task);
        return task;
    }

    private TeeTaskSpec verifyAccepted(String callerId, String compact) {
        TeeTaskSpec task = verifySignature(compact);
        TeeRuntimeTaskDO accepted = grants.requireActiveTask(callerId, task.taskId());
        if (!compact.equals(accepted.getTaskJws())) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID,
                    "结果密钥请求不是放行时接受的原始签名任务");
        }
        // bindResult 会再次检查已接受任务的 30 分钟执行授权窗口。
        return task;
    }

    private TeeTaskSpec verifySignature(String compact) {
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
        registry.requireRuntimeImageDigest(task.runtimeImageDigest());
        requireProgram(task.program());
        requireOutputPolicy(task);
    }

    /**
     * 程序引用的契约结构校验。
     *
     * <p>BUILTIN 的 objectId 为空，其摘要指镜像内算子资源；其余模式必须给出程序对象标识，
     * 由运行时另取程序字节并核对摘要。程序对象不含数据行或数据密钥。
     */
    private void requireProgram(TeeTaskSpec.Program program) {
        if (program == null) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务缺少程序引用");
        }
        String kind = TeeGuard.requireText(program.kind(), "program.kind");
        if (!TeeContract.PROGRAM_KINDS.contains(kind)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "程序类型不在契约白名单内");
        }
        TeeGuard.requireText(program.sha256(), "program.sha256");
        boolean builtin = "BUILTIN".equals(kind);
        boolean hasObject = program.objectId() != null && !program.objectId().isBlank();
        if (builtin == hasObject) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID,
                    builtin ? "BUILTIN 程序不得携带程序对象" : "非 BUILTIN 程序必须给出程序对象");
        }
    }

    private void requireOutputPolicy(TeeTaskSpec task) {
        TeeTaskSpec.OutputPolicy policy = task.outputPolicy();
        if (policy == null || !policy.encryptData() || !policy.encryptModel()
                || !policy.exportRequiresAllContributors()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "出域策略不符合契约固定取值");
        }
        TeeGuard.requireRequestedReportKinds(policy.reportKinds());
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
