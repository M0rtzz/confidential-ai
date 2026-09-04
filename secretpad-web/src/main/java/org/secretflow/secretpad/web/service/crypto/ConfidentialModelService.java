package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Ciphertext-only registry for local weights and OpenAI-compatible model endpoints. */
@Service
public class ConfidentialModelService {
    public static final String LOCAL_WEIGHTS = "LOCAL_WEIGHTS";
    public static final String OPENAI_COMPATIBLE = "OPENAI_COMPATIBLE";
    private static final int MAX_CIPHER_CHUNK_BYTES = 16 * 1024 * 1024 + 64;
    private static final Set<String> ALGORITHMS = Set.of(
            "AES-256-GCM", "AES-256-GCM-SIV", "CHACHA20-POLY1305",
            "XCHACHA20-POLY1305", "AES-256-SIV");

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final MinioAssetStorage storage;
    private final ConfidentialMetadataStore audit;
    private final ConfidentialComputeService compute;
    private final CipherGpuClient cipherGpu;

    public ConfidentialModelService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
            MinioAssetStorage storage, ConfidentialMetadataStore audit, ConfidentialComputeService compute,
            CipherGpuClient cipherGpu) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.storage = storage;
        this.audit = audit;
        this.compute = compute;
        this.cipherGpu = cipherGpu;
    }

    public record UploadSessionRequest(String modelName, String originalFileName, long originalSize,
                                       String domainId, String contentEncryptionAlgorithm,
                                       int expectedChunks) {
    }

    public record WeightVersionRequest(String uploadSessionId, String modelId, String name,
                                       String description, JsonNode manifest, String manifestHash,
                                       String ownerSigningPublicKey, String ownerSignature, JsonNode runtimeConfig,
                                       String runtimeSecurityRequirement) {
    }

    public record OpenAiVersionRequest(String modelId, String name, String description, String domainId,
                                       String baseUrl, String upstreamModelId, JsonNode encryptedCredential,
                                       JsonNode runtimeConfig, String runtimeSecurityRequirement) {
    }

    public record ReviewRequest(String action, String comment) {
    }

    public record DeploymentRequest(String versionId) {
    }

    public record AuthorizeDeploymentRequest(String taskId, String grantId) {
    }

    public Map<String, Object> capabilities() {
        List<Map<String, Object>> values = new ArrayList<>();
        values.add(capability("AES-256-GCM", 32, 12, true));
        values.add(capability("AES-256-GCM-SIV", 32, 12, false));
        values.add(capability("CHACHA20-POLY1305", 32, 12, false));
        values.add(capability("XCHACHA20-POLY1305", 32, 24, false));
        values.add(capability("AES-256-SIV", 64, 16, false));
        return Map.of("format", "ds-envelope/v2", "defaultAlgorithm", "AES-256-GCM",
                "chunkSize", 8 * 1024 * 1024, "contentEncryptionAlgorithms", values);
    }

    @Transactional
    public Map<String, Object> createUploadSession(String ownerId, UploadSessionRequest request) {
        requireText(request.modelName(), "modelName");
        requireText(request.originalFileName(), "originalFileName");
        compute.requireUsableDomain(requireText(request.domainId(), "domainId"));
        requireAlgorithm(request.contentEncryptionAlgorithm());
        if (request.originalSize() <= 0 || request.expectedChunks() <= 0) {
            throw invalid("文件大小和分块数必须为正数");
        }
        String sessionId = id("upload");
        Instant now = Instant.now();
        Instant expires = now.plus(2, ChronoUnit.HOURS);
        jdbc.update("insert into ds_confidential_upload_session(upload_session_id,owner_id,model_name,"
                        + "original_file_name,original_size,domain_id,content_encryption_algorithm,expected_chunks,"
                        + "received_chunks,status,created_at,expires_at) values(?,?,?,?,?,?,?,?,0,'UPLOADING',?,?)",
                sessionId, ownerId, request.modelName(), request.originalFileName(), request.originalSize(),
                request.domainId(), request.contentEncryptionAlgorithm(), request.expectedChunks(),
                now.toString(), expires.toString());
        audit.audit(ownerId, "MODEL_CIPHER_UPLOAD_STARTED", sessionId,
                mapper.valueToTree(Map.of("algorithm", request.contentEncryptionAlgorithm(),
                        "expectedChunks", request.expectedChunks(), "simulated", true)));
        return Map.of("uploadSessionId", sessionId, "status", "UPLOADING", "expiresAt", expires.toString());
    }

    @Transactional
    public Map<String, Object> uploadChunk(String ownerId, String sessionId, int index, byte[] ciphertext,
                                           String expectedHash) {
        Map<String, Object> session = uploadSession(ownerId, sessionId);
        if (!"UPLOADING".equals(text(session.get("status"))) || Instant.parse(text(session.get("expires_at"))).isBefore(Instant.now())) {
            throw invalid("上传会话已过期或不可写");
        }
        int expectedChunks = number(session.get("expected_chunks"));
        if (index < 0 || index >= expectedChunks || ciphertext.length == 0
                || ciphertext.length > MAX_CIPHER_CHUNK_BYTES) {
            throw invalid("密文分块索引或大小不合法");
        }
        String actualHash = ConfidentialCanonical.sha256Bytes(ciphertext);
        if (!actualHash.equals(requireHash(expectedHash, "X-Cipher-SHA256"))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文分块 Hash 不匹配");
        }
        String objectKey = "cipher/" + safe(ownerId) + "/models/" + sessionId + "/"
                + String.format("%08d", index);
        String uri = storage.put(objectKey, new ByteArrayInputStream(ciphertext), ciphertext.length,
                "application/octet-stream", actualHash);
        int existing = jdbc.queryForObject("select count(1) from ds_confidential_upload_chunk "
                + "where upload_session_id=? and chunk_index=?", Integer.class, sessionId, index);
        if (existing == 0) {
            jdbc.update("insert into ds_confidential_upload_chunk(upload_session_id,chunk_index,object_uri,"
                            + "cipher_hash,cipher_size,created_at) values(?,?,?,?,?,?)",
                    sessionId, index, uri, actualHash, ciphertext.length, Instant.now().toString());
            jdbc.update("update ds_confidential_upload_session set received_chunks=received_chunks+1 "
                    + "where upload_session_id=?", sessionId);
        } else {
            jdbc.update("update ds_confidential_upload_chunk set object_uri=?,cipher_hash=?,cipher_size=?,created_at=? "
                            + "where upload_session_id=? and chunk_index=?",
                    uri, actualHash, ciphertext.length, Instant.now().toString(), sessionId, index);
        }
        return Map.of("index", index, "cipherHash", actualHash, "status", "STORED");
    }

    @Transactional
    public Map<String, Object> commitWeights(String ownerId, WeightVersionRequest request) {
        Map<String, Object> session = uploadSession(ownerId, requireText(request.uploadSessionId(), "uploadSessionId"));
        if (!"UPLOADING".equals(text(session.get("status")))) throw invalid("上传会话不能提交");
        compute.requireUsableDomain(text(session.get("domain_id")));
        int expected = number(session.get("expected_chunks"));
        int received = number(session.get("received_chunks"));
        if (received != expected) throw invalid("密文分块尚未全部上传");
        JsonNode manifest = requireManifest(request.manifest(), text(session.get("content_encryption_algorithm")), expected);
        List<Map<String, Object>> storedChunks = jdbc.queryForList(
                "select chunk_index,object_uri,cipher_hash,cipher_size from ds_confidential_upload_chunk "
                        + "where upload_session_id=? order by chunk_index", request.uploadSessionId());
        for (int i = 0; i < expected; i++) {
            Map<String, Object> stored = storedChunks.get(i);
            JsonNode declared = manifest.path("chunks").get(i);
            if (declared.has("ciphertext") || declared.path("index").asInt(-1) != i
                    || !text(stored.get("cipher_hash")).equals(declared.path("sha256").asText())) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "manifest 分块声明不匹配");
            }
        }
        String manifestHash = requireHash(request.manifestHash(), "manifestHash");
        if (!manifestHash.equals(ConfidentialCanonical.sha256(manifest))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "manifest Hash 不匹配");
        }
        String signature = requireText(request.ownerSignature(), "ownerSignature");
        String signingKey = requireText(request.ownerSigningPublicKey(), "ownerSigningPublicKey");
        audit.requireSigningIdentity(ownerId, signingKey);
        ConfidentialCanonical.verifyEd25519(signingKey, signature, manifest);
        String modelId = modelForVersion(ownerId, request.modelId(), request.name(), request.description(), LOCAL_WEIGHTS);
        int version = nextVersion(modelId);
        String versionId = id("modelv");
        String assetVersionId = modelId + "@v" + version;
        byte[] canonicalManifest = ConfidentialCanonical.bytes(manifest);
        String manifestJson = new String(canonicalManifest, StandardCharsets.UTF_8);
        String manifestUri = storage.put("cipher-manifests/" + safe(ownerId) + "/" + assetVersionId + ".json",
                new ByteArrayInputStream(canonicalManifest), canonicalManifest.length, "application/json", manifestHash);
        JsonNode envelope = manifest.path("keyEnvelope");
        requireObject(envelope, "manifest.keyEnvelope");
        String recipientKid = requireText(envelope.path("recipientKid").asText(),
                "manifest.keyEnvelope.recipientKid");
        if (!recipientKid.equals(manifest.path("publicKeyId").asText())) {
            throw invalid("权重 DEK envelope 接收人和 manifest 公钥不一致");
        }
        audit.requireEncryptionIdentity(ownerId, recipientKid);
        jdbc.update("insert into ds_crypto_asset_version(asset_version_id,asset_id,version_id,owner_id,"
                        + "manifest_uri,manifest_hash,owner_signature,algorithm,runtime_security_requirement,"
                        + "retention_policy,created_at) values(?,?,?,?,?,?,?,?,?,'MODEL',?)",
                assetVersionId, modelId, "v" + version, ownerId, manifestUri, manifestHash, signature,
                text(session.get("content_encryption_algorithm")), requirement(request.runtimeSecurityRequirement()),
                Instant.now().toString());
        jdbc.update("insert into ds_crypto_key_envelope(envelope_id,asset_version_id,recipient_kid,envelope_blob,"
                        + "aad_hash,created_at) values(?,?,?,?,?,?)", id("kenv"), assetVersionId,
                recipientKid, write(envelope), envelope.path("aadHash").asText(),
                Instant.now().toString());
        insertVersion(ownerId, modelId, versionId, version, LOCAL_WEIGHTS, text(session.get("domain_id")),
                text(session.get("content_encryption_algorithm")), assetVersionId, manifestJson, manifestHash,
                null, null, null, request.runtimeConfig(), requirement(request.runtimeSecurityRequirement()));
        jdbc.update("update ds_confidential_upload_session set status='COMMITTED' where upload_session_id=?",
                request.uploadSessionId());
        updateLatest(modelId, version, "IMPORTED");
        audit.audit(ownerId, "ENCRYPTED_MODEL_IMPORTED", versionId,
                mapper.valueToTree(Map.of("modelId", modelId, "algorithm", text(session.get("content_encryption_algorithm")),
                        "manifestHash", manifestHash, "securityProfile", "a100-sim", "simulated", true)));
        return modelDetail(ownerId, modelId);
    }

    @Transactional
    public Map<String, Object> createOpenAiVersion(String ownerId, OpenAiVersionRequest request) {
        URI baseUri = validateRemoteBaseUrl(request.baseUrl());
        requireText(request.upstreamModelId(), "upstreamModelId");
        JsonNode credential = requireEncryptedCredential(request.encryptedCredential());
        String recipientKid = requireText(credential.path("keyEnvelope").path("recipientKid").asText(),
                "encryptedCredential.keyEnvelope.recipientKid");
        if (!recipientKid.equals(credential.path("publicKeyId").asText())) {
            throw invalid("API Key DEK envelope 接收人和凭据公钥不一致");
        }
        audit.requireEncryptionIdentity(ownerId, recipientKid);
        compute.requireUsableDomain(requireText(request.domainId(), "domainId"));
        String modelId = modelForVersion(ownerId, request.modelId(), request.name(), request.description(),
                OPENAI_COMPATIBLE);
        int version = nextVersion(modelId);
        String versionId = id("modelv");
        String credentialId = id("cred");
        jdbc.update("insert into ds_model_credential(credential_id,owner_id,key_id,encrypted_credential_json,"
                        + "cipher_hash,status,created_at) values(?,?,?,?,?,'ACTIVE',?)",
                credentialId, ownerId, credential.path("publicKeyId").asText(), write(credential),
                credential.path("cipherHash").asText(), Instant.now().toString());
        insertVersion(ownerId, modelId, versionId, version, OPENAI_COMPATIBLE, request.domainId(),
                "AES-256-GCM", null, null, credential.path("cipherHash").asText(), baseUri.toString(),
                request.upstreamModelId(), credentialId, request.runtimeConfig(),
                requirement(request.runtimeSecurityRequirement()));
        updateLatest(modelId, version, "IMPORTED");
        audit.audit(ownerId, "OPENAI_COMPATIBLE_MODEL_IMPORTED", versionId,
                mapper.valueToTree(Map.of("modelId", modelId, "baseUrl", baseUri.toString(),
                        "credentialCipherHash", credential.path("cipherHash").asText(),
                        "securityProfile", "a100-sim", "simulated", true)));
        return modelDetail(ownerId, modelId);
    }

    public List<Map<String, Object>> models(String ownerId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select m.*,v.version_id,v.domain_id,"
                        + "v.content_encryption_algorithm,v.runtime_security_requirement from ds_confidential_model m "
                        + "left join ds_confidential_model_version v on v.model_id=m.model_id "
                        + "and v.version_number=m.latest_version where m.owner_id=? order by m.updated_at desc",
                ownerId);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, Object> row : rows) result.add(modelView(row));
        return result;
    }

    public Map<String, Object> modelDetail(String ownerId, String modelId) {
        Map<String, Object> model = model(ownerId, modelId);
        Map<String, Object> result = modelView(model);
        List<Map<String, Object>> versions = jdbc.queryForList(
                "select * from ds_confidential_model_version where owner_id=? and model_id=? order by version_number desc",
                ownerId, modelId);
        result.put("versions", versions.stream().map(this::versionView).toList());
        result.put("deployments", jdbc.queryForList("select deployment_id deploymentId,version_id versionId,"
                        + "deployment_type deploymentType,security_profile securityProfile,status,endpoint_path endpointPath,"
                        + "authorization_session_id authorizationSessionId,error_code errorCode,created_at createdAt,"
                        + "updated_at updatedAt from ds_model_deployment where owner_id=? and model_id=? order by updated_at desc",
                ownerId, modelId));
        return result;
    }

    @Transactional
    public Map<String, Object> review(String ownerId, String modelId, String versionId, ReviewRequest request) {
        Map<String, Object> version = version(ownerId, modelId, versionId);
        String action = requireText(request.action(), "action").toUpperCase(Locale.ROOT);
        String current = text(version.get("status"));
        String next;
        if ("SUBMIT".equals(action) && Set.of("IMPORTED", "REJECTED").contains(current)) next = "PENDING_REVIEW";
        else if ("APPROVE".equals(action) && "PENDING_REVIEW".equals(current)) next = "APPROVED";
        else if ("REJECT".equals(action) && "PENDING_REVIEW".equals(current)) next = "REJECTED";
        else throw invalid("当前模型版本不允许该审核动作");
        String approvalId = text(version.get("approval_id"));
        String now = Instant.now().toString();
        if (approvalId.isBlank()) {
            approvalId = id("approval");
            jdbc.update("insert into ds_model_approval(id,model_id,model_name,project_id,version,status,current_stage,"
                            + "description,submitter,submitted_at,updated_at,artifact_id,artifact_version_id,test_evidence) "
                            + "values(?,?,?,'',?,'MODEL_REVIEW','MODEL_REVIEW',?,?,?,?,'','','')",
                    approvalId, modelId, text(model(ownerId, modelId).get("name")), number(version.get("version_number")),
                    request.comment() == null ? "" : request.comment(), ownerId, now, now);
            jdbc.update("update ds_confidential_model_version set approval_id=? where version_id=?", approvalId, versionId);
        }
        jdbc.update("update ds_confidential_model_version set status=? where version_id=?", next, versionId);
        jdbc.update("update ds_confidential_model set status=?,updated_at=? where model_id=?", next, now, modelId);
        jdbc.update("update ds_model_approval set status=?,current_stage=?,reviewer=?,review_comment=?,updated_at=?,"
                        + "published_at=case when ?='APPROVED' then ? else published_at end where id=?",
                next, next, ownerId, request.comment() == null ? "" : request.comment(), now, next, now, approvalId);
        jdbc.update("insert into ds_model_approval_history(approval_id,action,from_status,to_status,operator,comment,"
                        + "created_at) values(?,?,?,?,?,?,?)", approvalId, action, current, next, ownerId,
                request.comment() == null ? "" : request.comment(), now);
        audit.audit(ownerId, "CONFIDENTIAL_MODEL_" + next, versionId,
                mapper.valueToTree(Map.of("modelId", modelId, "approvalId", approvalId, "simulated", true)));
        return modelDetail(ownerId, modelId);
    }

    @Transactional
    public synchronized Map<String, Object> deploy(String ownerId, String modelId, DeploymentRequest request) {
        Map<String, Object> version = version(ownerId, modelId, requireText(request.versionId(), "versionId"));
        if (!"APPROVED".equals(text(version.get("status")))) throw invalid("仅已批准版本可以部署");
        List<Map<String, Object>> pending = jdbc.queryForList(
                "select * from ds_model_deployment where owner_id=? and model_id=? and version_id=? "
                        + "and status='AUTHORIZATION_REQUIRED' order by updated_at desc limit 1",
                ownerId, modelId, request.versionId());
        String deploymentId = pending.isEmpty() ? id("deploy") : text(pending.get(0).get("deployment_id"));
        String now = Instant.now().toString();
        Map<String, Object> registration = new LinkedHashMap<>();
        registration.put("deploymentId", deploymentId);
        registration.put("sourceType", version.get("source_type"));
        registration.put("baseUrl", version.get("base_url"));
        registration.put("upstreamModelId", OPENAI_COMPATIBLE.equals(text(version.get("source_type")))
                ? version.get("upstream_model_id")
                : runtimeModelName(version.get("runtime_config_json"), modelId));
        registration.put("timeoutSeconds", runtimeTimeout(version.get("runtime_config_json")));
        registration.put("securityProfile", "a100-sim");
        registration.put("simulated", true);
        JsonNode registered = cipherGpu.registerModelDeployment(registration);
        if (!"AUTHORIZATION_REQUIRED".equals(registered.path("status").asText())) {
            throw invalid("CipherGPU 未进入等待授权状态");
        }
        if (pending.isEmpty()) {
            jdbc.update("insert into ds_model_deployment(deployment_id,model_id,version_id,owner_id,deployment_type,"
                            + "security_profile,status,endpoint_path,created_at,updated_at) values(?,?,?,?,?,"
                            + "'a100-sim','AUTHORIZATION_REQUIRED',?,?,?)", deploymentId, modelId, request.versionId(), ownerId,
                    text(version.get("source_type")), "/api/v1alpha1/confidential-inference/chat/completions", now, now);
        } else {
            jdbc.update("update ds_model_deployment set updated_at=? where deployment_id=?", now, deploymentId);
        }
        jdbc.update("update ds_confidential_model set status='PUBLISHING',updated_at=? where model_id=?", now, modelId);
        audit.audit(ownerId, "MODEL_DEPLOYMENT_AUTHORIZATION_REQUIRED", deploymentId,
                mapper.valueToTree(Map.of("modelId", modelId, "versionId", request.versionId(),
                        "securityProfile", "a100-sim", "simulated", true)));
        return deploymentView(deployment(ownerId, deploymentId));
    }

    @Transactional
    public Map<String, Object> authorizeDeployment(String ownerId, String deploymentId,
                                                   AuthorizeDeploymentRequest request) {
        Map<String, Object> deployment = deployment(ownerId, deploymentId);
        if (!"AUTHORIZATION_REQUIRED".equals(text(deployment.get("status")))) {
            throw invalid("部署当前不需要授权");
        }
        JsonNode execution = compute.start(ownerId, requireText(request.taskId(), "taskId"),
                requireText(request.grantId(), "grantId"));
        if (!"SUCCEEDED".equals(execution.path("status").asText())) throw invalid("授权执行未成功");
        String sessionId = execution.path("receipt").path("sessionId").asText();
        String runtimeStatus = execution.path("receipt").path("modelDeploymentStatus").asText();
        if (!Set.of("ONLINE", "RUNTIME_REQUIRED").contains(runtimeStatus)) {
            throw invalid("任务 workloadId 未绑定该模型部署");
        }
        String now = Instant.now().toString();
        jdbc.update("update ds_model_deployment set status=?,authorization_session_id=?,error_code=?,updated_at=? "
                + "where deployment_id=?", runtimeStatus, sessionId,
                "RUNTIME_REQUIRED".equals(runtimeStatus) ? "VLLM_ENDPOINT_NOT_CONFIGURED" : null, now, deploymentId);
        jdbc.update("update ds_confidential_model set status=?,updated_at=? where model_id=?", runtimeStatus, now,
                text(deployment.get("model_id")));
        audit.audit(ownerId, "A100_SIMULATED_MODEL_ONLINE", deploymentId,
                mapper.valueToTree(Map.of("sessionId", sessionId, "simulated", true)));
        return deploymentView(deployment(ownerId, deploymentId));
    }

    @Transactional
    public Map<String, Object> offline(String ownerId, String deploymentId) {
        Map<String, Object> deployment = deployment(ownerId, deploymentId);
        cipherGpu.offlineModelDeployment(deploymentId);
        String now = Instant.now().toString();
        boolean cancelledBeforeAuthorization = "AUTHORIZATION_REQUIRED".equals(text(deployment.get("status")));
        jdbc.update("update ds_model_deployment set status='OFFLINE',authorization_session_id=null,updated_at=? "
                        + "where deployment_id=?", now, deploymentId);
        String modelStatus = cancelledBeforeAuthorization ? "APPROVED" : "OFFLINE";
        jdbc.update("update ds_confidential_model set status=?,updated_at=? where model_id=?", modelStatus, now,
                text(deployment.get("model_id")));
        audit.audit(ownerId, cancelledBeforeAuthorization
                        ? "MODEL_DEPLOYMENT_AUTHORIZATION_CANCELLED" : "CONFIDENTIAL_MODEL_OFFLINE",
                deploymentId, mapper.valueToTree(Map.of("sessionKeysDestroyed", true,
                        "authorizationConsumed", !cancelledBeforeAuthorization, "simulated", true)));
        return deploymentView(deployment(ownerId, deploymentId));
    }

    public JsonNode infer(String ownerId, JsonNode request) {
        JsonNode body = requireObject(request, "request");
        String deploymentId = requireText(body.path("deploymentId").asText(), "deploymentId");
        Map<String, Object> deployment = deployment(ownerId, deploymentId);
        if (!"ONLINE".equals(text(deployment.get("status")))) throw invalid("模型部署未上线或需要重新授权");
        JsonNode result = cipherGpu.infer(body);
        audit.audit(ownerId, "CONFIDENTIAL_MODEL_INFERENCE", deploymentId,
                mapper.valueToTree(Map.of("requestCipherHash",
                        body.path("encryptedRequest").path("cipherHash").asText(),
                        "securityProfile", "a100-sim", "simulated", true)));
        return result;
    }

    private Map<String, Object> capability(String algorithm, int keySize, int nonceSize, boolean recommended) {
        return Map.of("algorithm", algorithm, "keySize", keySize, "nonceSize", nonceSize, "tagSize", 16,
                "keyDerivation", "HKDF-SHA256", "implementationVersion", "1", "enabled", true,
                "recommended", recommended);
    }

    private String modelForVersion(String ownerId, String requestedId, String name, String description,
                                   String sourceType) {
        if (requestedId != null && !requestedId.isBlank()) {
            Map<String, Object> existing = model(ownerId, requestedId);
            if (!sourceType.equals(text(existing.get("source_type")))) throw invalid("模型来源类型不可变更");
            return requestedId;
        }
        String modelId = id("cmodel");
        String now = Instant.now().toString();
        jdbc.update("insert into ds_confidential_model(model_id,owner_id,name,description,source_type,status,"
                        + "latest_version,created_at,updated_at) values(?,?,?,?,?,'DRAFT',0,?,?)",
                modelId, ownerId, requireText(name, "name"), description == null ? "" : description,
                sourceType, now, now);
        return modelId;
    }

    private void insertVersion(String ownerId, String modelId, String versionId, int version, String sourceType,
                               String domainId, String algorithm, String assetVersionId, String manifestJson,
                               String manifestHash, String baseUrl, String upstreamModelId, String credentialId,
                               JsonNode runtimeConfig, String requirement) {
        jdbc.update("insert into ds_confidential_model_version(version_id,model_id,owner_id,version_number,source_type,"
                        + "domain_id,security_profile,runtime_security_requirement,content_encryption_algorithm,"
                        + "asset_version_id,manifest_json,manifest_hash,base_url,upstream_model_id,credential_id,"
                        + "runtime_config_json,status,created_at) values(?,?,?,?,?,?,'a100-sim',?,?,?,?,?,?,?,?,?,"
                        + "'IMPORTED',?)", versionId, modelId, ownerId, version, sourceType,
                requireText(domainId, "domainId"), requirement, algorithm, assetVersionId, manifestJson, manifestHash,
                baseUrl, upstreamModelId, credentialId, write(runtimeConfig == null ? mapper.createObjectNode() : runtimeConfig),
                Instant.now().toString());
    }

    private void updateLatest(String modelId, int version, String status) {
        jdbc.update("update ds_confidential_model set latest_version=?,status=?,updated_at=? where model_id=?",
                version, status, Instant.now().toString(), modelId);
    }

    private int nextVersion(String modelId) {
        Integer value = jdbc.queryForObject("select max(version_number) from ds_confidential_model_version where model_id=?",
                Integer.class, modelId);
        return value == null ? 1 : value + 1;
    }

    private JsonNode requireManifest(JsonNode manifest, String algorithm, int expectedChunks) {
        JsonNode value = requireObject(manifest, "manifest");
        if (!"ds-envelope/v2".equals(value.path("format").asText())
                || !algorithm.equals(value.path("algorithm").asText())
                || !algorithm.equals(value.path("contentEncryption").path("algorithm").asText())
                || value.path("chunks").size() != expectedChunks) {
            throw invalid("manifest 格式、算法或分块数不匹配");
        }
        return value.deepCopy();
    }

    private JsonNode requireEncryptedCredential(JsonNode credential) {
        JsonNode value = requireObject(credential, "encryptedCredential");
        if (!"ds-envelope/v1".equals(value.path("format").asText())
                || !"AES-256-GCM".equals(value.path("algorithm").asText())
                || !value.hasNonNull("ciphertext") || !value.hasNonNull("nonce")
                || !value.path("keyEnvelope").isObject()) {
            throw invalid("API Key 必须使用浏览器 AES-256-GCM 加密后提交");
        }
        requireHash(value.path("cipherHash").asText(), "credential.cipherHash");
        if (value.has("apiKey") || value.has("plaintext") || value.has("privateKey")) {
            throw invalid("凭据请求包含禁止的明文字段");
        }
        return value;
    }

    private URI validateRemoteBaseUrl(String value) {
        try {
            URI uri = URI.create(requireText(value, "baseUrl"));
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getUserInfo() != null || uri.getFragment() != null) {
                throw invalid("Base URL 必须是无用户信息的 HTTPS 地址");
            }
            for (InetAddress address : InetAddress.getAllByName(uri.getHost())) {
                if (isPrivate(address)) throw invalid("Base URL 禁止访问本机、内网或云元数据地址");
            }
            String normalized = uri.toString();
            return URI.create(normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized);
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw invalid("Base URL 无法安全解析");
        }
    }

    private boolean isPrivate(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) return true;
        byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = Byte.toUnsignedInt(raw[0]);
            int second = Byte.toUnsignedInt(raw[1]);
            return (first == 100 && second >= 64 && second <= 127) || first == 0;
        }
        return address instanceof Inet6Address && (raw[0] & 0xfe) == 0xfc;
    }

    private Map<String, Object> modelView(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("modelId", row.get("model_id"));
        value.put("name", row.get("name"));
        value.put("description", row.get("description"));
        value.put("sourceType", row.get("source_type"));
        value.put("status", row.get("status"));
        value.put("latestVersion", row.get("latest_version"));
        value.put("versionId", row.get("version_id"));
        value.put("domainId", row.get("domain_id"));
        value.put("contentEncryptionAlgorithm", row.get("content_encryption_algorithm"));
        value.put("runtimeSecurityRequirement", row.get("runtime_security_requirement"));
        value.put("securityProfile", "a100-sim");
        value.put("simulated", true);
        value.put("createdAt", row.get("created_at"));
        value.put("updatedAt", row.get("updated_at"));
        return value;
    }

    private Map<String, Object> versionView(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("versionId", row.get("version_id"));
        value.put("version", row.get("version_number"));
        value.put("sourceType", row.get("source_type"));
        value.put("domainId", row.get("domain_id"));
        value.put("securityProfile", row.get("security_profile"));
        value.put("runtimeSecurityRequirement", row.get("runtime_security_requirement"));
        value.put("contentEncryptionAlgorithm", row.get("content_encryption_algorithm"));
        value.put("assetVersionId", row.get("asset_version_id"));
        value.put("manifestHash", row.get("manifest_hash"));
        value.put("baseUrl", row.get("base_url"));
        value.put("upstreamModelId", row.get("upstream_model_id"));
        value.put("credentialId", row.get("credential_id"));
        value.put("credentialMasked", row.get("credential_id") == null ? null : "sk-****encrypted");
        value.put("status", row.get("status"));
        value.put("approvalId", row.get("approval_id"));
        value.put("createdAt", row.get("created_at"));
        return value;
    }

    private Map<String, Object> deploymentView(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("deploymentId", row.get("deployment_id"));
        value.put("versionId", row.get("version_id"));
        value.put("deploymentType", row.get("deployment_type"));
        value.put("securityProfile", row.get("security_profile"));
        value.put("status", row.get("status"));
        value.put("endpointPath", row.get("endpoint_path"));
        value.put("authorizationSessionId", row.get("authorization_session_id"));
        value.put("errorCode", row.get("error_code"));
        return value;
    }

    private int runtimeTimeout(Object json) {
        if (json == null) return 60;
        int value = ConfidentialCanonical.parse(mapper, text(json)).path("timeoutSeconds").asInt(60);
        return Math.max(5, Math.min(300, value));
    }

    private String runtimeModelName(Object json, String fallback) {
        if (json == null) return fallback;
        String value = ConfidentialCanonical.parse(mapper, text(json)).path("servedModelName").asText().trim();
        return value.isEmpty() ? fallback : requireText(value, "runtimeConfig.servedModelName");
    }

    private Map<String, Object> model(String ownerId, String modelId) {
        try {
            return jdbc.queryForMap("select * from ds_confidential_model where owner_id=? and model_id=?", ownerId, modelId);
        } catch (EmptyResultDataAccessException failure) {
            throw invalid("机密模型不存在");
        }
    }

    private Map<String, Object> version(String ownerId, String modelId, String versionId) {
        try {
            return jdbc.queryForMap("select * from ds_confidential_model_version where owner_id=? and model_id=? "
                    + "and version_id=?", ownerId, modelId, versionId);
        } catch (EmptyResultDataAccessException failure) {
            throw invalid("模型版本不存在");
        }
    }

    private Map<String, Object> deployment(String ownerId, String deploymentId) {
        try {
            return jdbc.queryForMap("select * from ds_model_deployment where owner_id=? and deployment_id=?",
                    ownerId, deploymentId);
        } catch (EmptyResultDataAccessException failure) {
            throw invalid("模型部署不存在");
        }
    }

    private Map<String, Object> uploadSession(String ownerId, String sessionId) {
        try {
            return jdbc.queryForMap("select * from ds_confidential_upload_session where owner_id=? "
                    + "and upload_session_id=?", ownerId, sessionId);
        } catch (EmptyResultDataAccessException failure) {
            throw invalid("上传会话不存在");
        }
    }

    private String requirement(String value) {
        String result = value == null || value.isBlank() ? "controlled-sim-ok" : value;
        if (!Set.of("controlled-sim-ok", "public").contains(result)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "A100 模拟环境禁止 gpu-cc 资产降级");
        }
        return result;
    }

    private void requireAlgorithm(String algorithm) {
        if (!ALGORITHMS.contains(algorithm)) throw invalid("不支持或未启用的内容加密算法");
    }

    private JsonNode requireObject(JsonNode value, String field) {
        if (value == null || !value.isObject()) throw invalid(field + " 必须是对象");
        return value;
    }

    private String requireHash(String value, String field) {
        if (value == null || !value.matches("^[0-9a-f]{64}$")) throw invalid(field + " 必须是 SHA-256");
        return value;
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 1024) throw invalid(field + " 不能为空");
        return value.trim();
    }

    private String write(JsonNode value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception failure) {
            throw invalid("JSON 序列化失败");
        }
    }

    private static String id(String prefix) {
        return prefix + "_" + UUID.randomUUID().toString().replace("-", "");
    }

    private static String safe(String value) {
        return value.replaceAll("[^a-zA-Z0-9_-]", "_");
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static int number(Object value) {
        return value instanceof Number number ? number.intValue() : Integer.parseInt(text(value));
    }

    private static TeeException invalid(String message) {
        return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message);
    }
}
