package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Orchestrates ciphertext and signed metadata. It deliberately has no AES or HPKE decryption API. */
@Service
public class ConfidentialComputeService {
    private final ConfidentialMetadataStore store;
    private final CipherGpuClient cipherGpu;
    private final ObjectMapper mapper;
    private final String simulationRootPublicKey;
    private final String workloadDigest;
    private final String policyDigest;
    private final String tlsPublicKeyHash;

    public ConfidentialComputeService(ConfidentialMetadataStore store, CipherGpuClient cipherGpu,
            ObjectMapper mapper,
            @Value("${CIPHERGPU_SIM_ROOT_PUBLIC_KEY:}") String simulationRootPublicKey,
            @Value("${CIPHERGPU_WORKLOAD_DIGEST:sha256:builtin-digest-v1}") String workloadDigest,
            @Value("${CIPHERGPU_POLICY_DIGEST:sha256:a100-sim-policy-v1}") String policyDigest,
            @Value("${CIPHERGPU_TLS_PUBLIC_KEY_HASH:simulation-unbound}") String tlsPublicKeyHash) {
        this.store = store;
        this.cipherGpu = cipherGpu;
        this.mapper = mapper;
        this.simulationRootPublicKey = simulationRootPublicKey;
        this.workloadDigest = workloadDigest;
        this.policyDigest = policyDigest;
        this.tlsPublicKeyHash = tlsPublicKeyHash;
    }

    public record IdentityRequest(String kid, String encryptionPublicKey, String signingPublicKey,
                                  String proofOfPossession) {
    }

    public record CreateTaskRequest(String domainId, String purpose, String workloadId,
                                    List<String> assetVersionIds, List<String> outputRecipients,
                                    String securityProfile, String runtimeSecurityRequirement) {
    }

    public record AttestationRequest(String taskId, String clientNonce, String expectedSecurityProfile) {
    }

    public record GrantRequest(String taskId, String sessionId, JsonNode grant,
                               JsonNode sealedDeks, JsonNode encryptedInputs,
                               JsonNode outputRecipients, String scenario) {
    }

    public Map<String, Object> registerIdentity(String ownerId, IdentityRequest request) {
        requireText(request.kid(), "kid");
        requireRawKey(request.encryptionPublicKey(), "X25519");
        requireRawKey(request.signingPublicKey(), "Ed25519");
        Map<String, String> proof = Map.of("kid", request.kid(),
                "encryptionPublicKey", request.encryptionPublicKey(),
                "signingPublicKey", request.signingPublicKey());
        ConfidentialCanonical.verifyEd25519(request.signingPublicKey(), request.proofOfPossession(), proof);
        store.saveIdentity(ownerId, request.kid(), request.encryptionPublicKey(), request.signingPublicKey());
        JsonNode detail = mapper.valueToTree(Map.of("kid", request.kid(), "algorithm", "X25519+Ed25519"));
        store.audit(ownerId, "CRYPTO_IDENTITY_REGISTERED", request.kid(), detail);
        return Map.of("kid", request.kid(), "status", "ACTIVE", "algorithm", "X25519+Ed25519");
    }

    public List<Map<String, Object>> domains() {
        return List.of(
                domain("a100-domain-a", "可信域A", "active", "trusted"),
                domain("a100-domain-b", "可信域B", "active", "trusted"));
    }

    public Map<String, Object> domain(String domainId) {
        return domains().stream().filter(item -> domainId.equals(item.get("id"))).findFirst()
                .orElseThrow(() -> TeeException.of(TeeContract.Error.CONTRACT_INVALID, "可信域不存在"));
    }

    /**
     * Returns a domain only when it is currently usable for data operations.
     * Keeping this check in the control-plane service prevents callers from
     * bypassing the UI's trusted-domain filter with a crafted request.
     */
    public Map<String, Object> requireUsableDomain(String domainId) {
        Map<String, Object> value = domain(domainId);
        if (!"active".equals(value.get("status")) || !"trusted".equals(value.get("trustStatus"))) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "可信域当前处于 Blocked 或 Offline 状态");
        }
        return value;
    }

    public Map<String, Object> verifyDomain(String ownerId, String domainId) {
        Map<String, Object> domain = requireUsableDomain(domainId);
        JsonNode health = cipherGpu.health();
        requireSimulationIdentity(health);
        store.audit(ownerId, "A100_SIMULATION_DOMAIN_VERIFIED", domainId, health);
        return Map.of("domain", domain, "runtime", health,
                "warning", "A100 模拟环境不提供 GPU CC 硬件隔离，宿主高权限人员理论上可读取运行时明文");
    }

    public Map<String, Object> createTask(String ownerId, CreateTaskRequest request) {
        requireUsableDomain(request.domainId());
        requireSimulationProfile(request.securityProfile(), request.runtimeSecurityRequirement());
        if (request.assetVersionIds() == null || request.assetVersionIds().isEmpty()
                || request.outputRecipients() == null || request.outputRecipients().isEmpty()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务必须包含输入版本和输出接收人");
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);
        String taskId = id("task");
        ObjectNode spec = mapper.createObjectNode();
        spec.put("contractVersion", ConfidentialContract.VERSION);
        spec.put("taskId", taskId);
        spec.put("domainId", request.domainId());
        spec.put("securityProfile", ConfidentialContract.SIM_PROFILE);
        spec.put("evidenceType", ConfidentialContract.SIM_EVIDENCE);
        spec.put("simulated", true);
        spec.put("hardwareModel", ConfidentialContract.SIM_HARDWARE);
        spec.put("runtimeSecurityRequirement", request.runtimeSecurityRequirement());
        spec.put("purpose", request.purpose() == null ? "verify" : request.purpose());
        spec.put("workloadId", request.workloadId() == null ? "builtin.digest/v1" : request.workloadId());
        spec.set("assetVersionIds", mapper.valueToTree(request.assetVersionIds()));
        spec.set("outputRecipients", mapper.valueToTree(request.outputRecipients()));
        spec.put("attestationPolicyId", ConfidentialContract.SIM_POLICY);
        spec.put("workloadDigest", workloadDigest);
        spec.put("policyDigest", policyDigest);
        spec.put("egressPolicy", "deny-all");
        spec.put("issuedAt", issuedAt.toString());
        spec.put("expiresAt", expiresAt.toString());
        String digest = ConfidentialCanonical.sha256(spec);
        store.saveTask(ownerId, taskId, spec, digest, ConfidentialContract.SIM_PROFILE,
                request.runtimeSecurityRequirement(), expiresAt.toString());
        store.audit(ownerId, "CONFIDENTIAL_TASK_CREATED", taskId,
                mapper.valueToTree(Map.of("taskSpecDigest", digest, "securityProfile", ConfidentialContract.SIM_PROFILE,
                        "simulated", true, "runtimeSecurityRequirement", request.runtimeSecurityRequirement())));
        return Map.of("taskSpec", spec, "taskSpecDigest", digest);
    }

    public JsonNode createAttestation(String ownerId, AttestationRequest request) {
        ConfidentialMetadataStore.TaskRow task = store.task(ownerId, request.taskId());
        if (!task.securityProfile().equals(request.expectedSecurityProfile())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "期望安全档位与任务不一致");
        }
        ObjectNode payload = mapper.createObjectNode();
        payload.put("domainId", task.spec().path("domainId").asText());
        payload.put("clientNonce", requireText(request.clientNonce(), "clientNonce"));
        payload.put("taskSpecDigest", task.digest());
        payload.put("expectedSecurityProfile", request.expectedSecurityProfile());
        payload.put("runtimeSecurityRequirement", task.runtimeSecurityRequirement());
        payload.put("workloadDigest", workloadDigest);
        payload.put("policyDigest", policyDigest);
        long ttlSeconds = Duration.between(Instant.now(), Instant.parse(task.expiresAt())).getSeconds();
        if (ttlSeconds < 30) {
            throw TeeException.of(TeeContract.Error.TASK_EXPIRED, "任务剩余有效期不足以创建证明会话");
        }
        payload.put("ttlSeconds", Math.min(300, ttlSeconds));
        JsonNode response = cipherGpu.createSession(payload);
        requireSimulationIdentity(response);
        verifyEvidence(response, request.clientNonce(), task);
        store.saveSession(request.taskId(), response, request.clientNonce());
        store.audit(ownerId, "A100_SIMULATED_ATTESTATION_ISSUED", response.path("sessionId").asText(),
                mapper.valueToTree(Map.of("taskId", request.taskId(), "evidenceHash",
                        ConfidentialCanonical.sha256(response.path("evidence")), "simulated", true)));
        return response;
    }

    public Map<String, Object> saveGrant(String ownerId, GrantRequest request) {
        ConfidentialMetadataStore.TaskRow task = store.task(ownerId, request.taskId());
        JsonNode signedGrant = requiredObject(request.grant(), "grant");
        JsonNode claims = requiredObject(signedGrant.path("claims"), "grant.claims");
        String signingKey = requireText(signedGrant.path("signingPublicKey").asText(), "signingPublicKey");
        store.requireSigningIdentity(ownerId, signingKey);
        ConfidentialCanonical.verifyEd25519(signingKey,
                requireText(signedGrant.path("signature").asText(), "grant.signature"), claims);
        requireClaim(claims, "contractVersion", ConfidentialContract.VERSION);
        requireClaim(claims, "taskSpecDigest", task.digest());
        requireClaim(claims, "teeSessionId", request.sessionId());
        requireClaim(claims, "securityProfile", ConfidentialContract.SIM_PROFILE);
        requireClaim(claims, "evidenceType", ConfidentialContract.SIM_EVIDENCE);
        requireClaim(claims, "hardwareModel", ConfidentialContract.SIM_HARDWARE);
        requireClaim(claims, "runtimeSecurityRequirement", task.runtimeSecurityRequirement());
        if (!claims.path("simulated").asBoolean(false) || claims.path("maxUses").asInt() != 1) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "grant 必须明确批准一次 A100 模拟执行");
        }
        Instant expiry = Instant.parse(requireText(claims.path("exp").asText(), "grant.exp"));
        if (!expiry.isAfter(Instant.now()) || expiry.isAfter(Instant.parse(task.expiresAt()))) {
            throw TeeException.of(TeeContract.Error.TASK_EXPIRED, "grant 已过期或超出任务有效期");
        }
        String grantId = requireText(claims.path("grantId").asText(), "grantId");
        ObjectNode stored = mapper.createObjectNode();
        stored.set("grant", signedGrant);
        stored.set("sealedDeks", request.sealedDeks());
        stored.set("encryptedInputs", request.encryptedInputs());
        stored.set("outputRecipients", request.outputRecipients());
        stored.put("scenario", request.scenario() == null ? "NORMAL" : request.scenario());
        store.saveGrant(ownerId, grantId, request.taskId(), request.sessionId(),
                requireText(claims.path("jti").asText(), "jti"), claims, stored,
                ConfidentialContract.SIM_PROFILE, expiry.toString());
        store.audit(ownerId, "A100_SIMULATED_GRANT_STORED", grantId,
                mapper.valueToTree(Map.of("taskId", request.taskId(), "sessionId", request.sessionId(),
                        "riskAccepted", true, "simulated", true)));
        return Map.of("grantId", grantId, "status", "READY", "maxUses", 1);
    }

    public JsonNode start(String ownerId, String taskId, String grantId) {
        ConfidentialMetadataStore.TaskRow task = store.task(ownerId, taskId);
        ConfidentialMetadataStore.GrantRow grant = store.consumeGrant(ownerId, grantId);
        if (!taskId.equals(grant.taskId()) || !ConfidentialContract.SIM_PROFILE.equals(grant.securityProfile())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "grant 与任务或安全档位不匹配");
        }
        ObjectNode execution = mapper.createObjectNode();
        execution.set("taskSpec", task.spec());
        execution.put("taskSpecDigest", task.digest());
        execution.put("sessionId", grant.sessionId());
        execution.set("grant", grant.payload().path("grant"));
        execution.set("sealedDeks", grant.payload().path("sealedDeks"));
        execution.set("encryptedInputs", grant.payload().path("encryptedInputs"));
        execution.set("outputRecipients", grant.payload().path("outputRecipients"));
        execution.put("scenario", grant.payload().path("scenario").asText("NORMAL"));
        JsonNode response = cipherGpu.execute(execution);
        verifyExecutionReceipt(response, task, grant);
        store.saveExecution(taskId, grantId, grant.sessionId(), response);
        store.audit(ownerId, "A100_SIMULATED_EXECUTION_COMPLETED", response.path("executionId").asText(),
                mapper.valueToTree(Map.of("taskId", taskId, "outputCiphertextSha256",
                        response.path("encryptedOutput").path("ciphertextSha256").asText(), "simulated", true)));
        return response;
    }

    public JsonNode output(String ownerId, String taskId) {
        return store.latestOutput(ownerId, taskId);
    }

    public List<JsonNode> audits(String ownerId) {
        return store.auditEvents(ownerId);
    }

    private void verifyEvidence(JsonNode response, String nonce, ConfidentialMetadataStore.TaskRow task) {
        if (simulationRootPublicKey.isBlank()) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "未配置独立 A100 模拟证明信任根");
        }
        if (!simulationRootPublicKey.equals(response.path("evidenceSigningPublicKey").asText())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "模拟证明签名根不可信");
        }
        JsonNode evidence = response.path("evidence");
        ConfidentialCanonical.verifyEd25519(simulationRootPublicKey,
                response.path("evidenceSignature").asText(), evidence);
        requireClaim(evidence, "clientNonce", nonce);
        requireClaim(evidence, "taskSpecDigest", task.digest());
        requireClaim(evidence, "securityProfile", ConfidentialContract.SIM_PROFILE);
        requireClaim(evidence, "evidenceType", ConfidentialContract.SIM_EVIDENCE);
        requireClaim(evidence, "hardwareModel", ConfidentialContract.SIM_HARDWARE);
        requireClaim(evidence, "workloadDigest", workloadDigest);
        requireClaim(evidence, "policyDigest", policyDigest);
        requireClaim(evidence, "tlsPublicKeyHash", tlsPublicKeyHash);
        requireClaim(evidence, "sessionId", response.path("sessionId").asText());
        requireClaim(evidence, "expiresAt", response.path("expiresAt").asText());
        String teePublicKey = requireText(response.path("teeEphemeralPublicKey").asText(),
                "teeEphemeralPublicKey");
        try {
            byte[] rawTeePublicKey = ConfidentialCanonical.decode(teePublicKey);
            if (rawTeePublicKey.length != 32) {
                throw new IllegalArgumentException("invalid X25519 key length");
            }
            requireClaim(evidence, "teeEphemeralPublicKeyHash",
                    ConfidentialCanonical.sha256Bytes(rawTeePublicKey));
        } catch (TeeException rejected) {
            throw rejected;
        } catch (RuntimeException invalidKey) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "证明中的一次性 TEK 公钥无效");
        }
        requireFreshEvidence(evidence, task);
        if (!evidence.path("simulated").asBoolean(false) || evidence.path("attestationVerified").asBoolean(true)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "证明不得伪装为硬件证明");
        }
    }

    private void verifyExecutionReceipt(JsonNode response, ConfidentialMetadataStore.TaskRow task,
                                        ConfidentialMetadataStore.GrantRow grant) {
        if (simulationRootPublicKey.isBlank()) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "未配置独立 A100 模拟证明信任根");
        }
        JsonNode receipt = requiredObject(response.path("receipt"), "receipt");
        String signature = requireText(receipt.path("signature").asText(), "receipt.signature");
        ObjectNode signedPayload = ((ObjectNode) receipt).deepCopy();
        signedPayload.remove("signature");
        ConfidentialCanonical.verifyEd25519(simulationRootPublicKey, signature, signedPayload);

        requireClaim(signedPayload, "contractVersion", ConfidentialContract.VERSION);
        requireClaim(signedPayload, "runtimeMode", "SIMULATION");
        requireClaim(signedPayload, "securityProfile", ConfidentialContract.SIM_PROFILE);
        requireClaim(signedPayload, "evidenceType", ConfidentialContract.SIM_EVIDENCE);
        requireClaim(signedPayload, "hardwareModel", ConfidentialContract.SIM_HARDWARE);
        requireClaim(signedPayload, "executionId", requireText(response.path("executionId").asText(), "executionId"));
        requireClaim(signedPayload, "taskId", requireText(task.spec().path("taskId").asText(), "taskSpec.taskId"));
        requireClaim(signedPayload, "taskSpecDigest", task.digest());
        requireClaim(signedPayload, "sessionId", grant.sessionId());
        requireClaim(signedPayload, "outputCiphertextSha256",
                requireText(response.path("encryptedOutput").path("ciphertextSha256").asText(),
                        "encryptedOutput.ciphertextSha256"));
        if (!signedPayload.path("simulated").asBoolean(false)
                || signedPayload.path("attestationVerified").asBoolean(true)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "执行回执不得伪装为硬件证明");
        }
        try {
            Instant completedAt = Instant.parse(requireText(signedPayload.path("completedAt").asText(),
                    "receipt.completedAt"));
            if (completedAt.isAfter(Instant.now().plusSeconds(30))
                    || completedAt.isAfter(Instant.parse(task.expiresAt()))) {
                throw TeeException.of(TeeContract.Error.TASK_EXPIRED, "执行回执时间超出任务有效期");
            }
        } catch (DateTimeParseException invalidTime) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "执行回执时间格式无效");
        }
    }

    private void requireSimulationIdentity(JsonNode value) {
        requireClaim(value, "contractVersion", ConfidentialContract.VERSION);
        requireClaim(value, "runtimeMode", "SIMULATION");
        requireClaim(value, "securityProfile", ConfidentialContract.SIM_PROFILE);
        requireClaim(value, "evidenceType", ConfidentialContract.SIM_EVIDENCE);
        requireClaim(value, "hardwareModel", ConfidentialContract.SIM_HARDWARE);
        if (!value.path("simulated").asBoolean(false) || value.path("attestationVerified").asBoolean(true)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "运行时未明确标记为 A100 模拟环境");
        }
    }

    private static void requireFreshEvidence(JsonNode evidence, ConfidentialMetadataStore.TaskRow task) {
        try {
            Instant now = Instant.now();
            Instant issuedAt = Instant.parse(requireText(evidence.path("issuedAt").asText(), "issuedAt"));
            Instant expiresAt = Instant.parse(requireText(evidence.path("expiresAt").asText(), "expiresAt"));
            if (issuedAt.isBefore(now.minusSeconds(60)) || issuedAt.isAfter(now.plusSeconds(30))
                    || !expiresAt.isAfter(now) || expiresAt.isAfter(Instant.parse(task.expiresAt()))) {
                throw TeeException.of(TeeContract.Error.TASK_EXPIRED, "模拟证明已过期或超出任务有效期");
            }
        } catch (DateTimeParseException invalidTime) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "模拟证明时间格式无效");
        }
    }

    private void requireSimulationProfile(String profile, String requirement) {
        if (!ConfidentialContract.SIM_PROFILE.equals(profile)) {
            throw TeeException.of(TeeContract.Error.REAL_MODE_UNAVAILABLE, "当前 A100 环境不支持 gpu-cc-prod");
        }
        if (requirement == null || !ConfidentialContract.RUNTIME_REQUIREMENTS.contains(requirement)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "未知运行时安全要求");
        }
        if ("gpu-cc".equals(requirement)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "gpu-cc 资产禁止降级到 A100 模拟环境");
        }
    }

    private static void requireRawKey(String value, String algorithm) {
        try {
            if (ConfidentialCanonical.decode(value).length != 32) {
                throw new IllegalArgumentException();
            }
        } catch (RuntimeException failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, algorithm + " 公钥必须为 32 字节 Base64URL");
        }
    }

    private static JsonNode requiredObject(JsonNode value, String field) {
        if (value == null || !value.isObject()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, field + " 必须是对象");
        }
        return value;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "缺少 " + field);
        }
        return value;
    }

    private static void requireClaim(JsonNode value, String field, String expected) {
        if (!expected.equals(value.path(field).asText())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, field + " 与已批准任务不匹配");
        }
    }

    private static String id(String prefix) {
        return prefix + "_" + UUID.randomUUID().toString().replace("-", "");
    }

    private static Map<String, Object> domain(String id, String name, String status, String trustStatus) {
        return Map.ofEntries(
                Map.entry("id", id), Map.entry("name", name), Map.entry("status", status),
                Map.entry("trustStatus", trustStatus), Map.entry("securityProfile", ConfidentialContract.SIM_PROFILE),
                Map.entry("evidenceType", ConfidentialContract.SIM_EVIDENCE), Map.entry("simulated", true),
                Map.entry("hardwareModel", ConfidentialContract.SIM_HARDWARE),
                Map.entry("policyId", ConfidentialContract.SIM_POLICY),
                Map.entry("purpose", "mixed"),
                Map.entry("warning", "无 GPU CC 硬件隔离；仅用于开发、联调、演示和已降级批准的数据"));
    }
}
