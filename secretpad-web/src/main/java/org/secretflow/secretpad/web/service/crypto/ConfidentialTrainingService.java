package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Persistent control plane for approval-gated CipherGPU training. */
@Service
public class ConfidentialTrainingService {
    private static final Set<String> TERMINAL = Set.of("COMPLETED", "FAILED", "REJECTED", "CANCELLED");
    private static final Set<String> ADAPTERS = Set.of(
            "hf-sequence-classification-v1", "hf-causal-lm-sft-lora-v1");
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ConfidentialAssetService assets;
    private final ConfidentialMetadataStore audit;
    private final ConfidentialComputeService compute;
    private final CipherGpuClient cipherGpu;
    private final MinioAssetStorage storage;

    public ConfidentialTrainingService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc,
            ObjectMapper mapper, ConfidentialAssetService assets, ConfidentialMetadataStore audit,
            ConfidentialComputeService compute, CipherGpuClient cipherGpu, MinioAssetStorage storage) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.assets = assets;
        this.audit = audit;
        this.compute = compute;
        this.cipherGpu = cipherGpu;
        this.storage = storage;
    }

    public record CreateTaskRequest(String taskName, String purpose, String computeNode,
            String dataAssetVersionId, String modelAssetVersionId, int epochs, double learningRate,
            String adapterId, JsonNode trainingConfig, String outputRecipientKid) {}
    public record PrepareRequest(String clientNonce) {}
    public record KeyReleaseRequest(JsonNode grant, JsonNode sealedDeks) {}
    public record ProgressRequest(int epoch, int progress, JsonNode metrics) {}
    public record CompleteRequest(String resultDataAssetId, String resultModelAssetId, JsonNode metrics) {}
    public record FailRequest(String reason) {}
    public record ProviderRequest(String providerName, String baseUrl, String modelId,
            JsonNode encryptedCredential, boolean defaultProvider) {}

    @Transactional
    public Map<String, Object> create(String ownerId, CreateTaskRequest request) {
        String taskId = id("train");
        String taskName = required(request.taskName(), "taskName");
        String purpose = required(request.purpose(), "purpose");
        String node = required(request.computeNode(), "computeNode");
        String adapter = request.adapterId() == null || request.adapterId().isBlank()
                ? "hf-sequence-classification-v1" : request.adapterId();
        if (!ADAPTERS.contains(adapter)) throw invalid("训练适配器不受信任");
        Map<String, Object> data = ownedVersion(ownerId, request.dataAssetVersionId(), "DATA");
        Map<String, Object> model = ownedVersion(ownerId, request.modelAssetVersionId(), "MODEL");
        if (!text(data.get("domain_id")).equals(text(model.get("domain_id")))) {
            throw invalid("数据和模型必须属于同一可信域");
        }
        JsonNode requestedConfig = request.trainingConfig() == null || !request.trainingConfig().isObject()
                ? defaultConfig(adapter, request.epochs(), request.learningRate()) : request.trainingConfig();
        validateConfig(adapter, requestedConfig);
        JsonNode config = normalizeTrainingConfig(requestedConfig);
        String dataRecipient = parse(text(data.get("manifest_json"))).path("publicKeyId").asText();
        String modelRecipient = parse(text(model.get("manifest_json"))).path("publicKeyId").asText();
        if (!dataRecipient.equals(modelRecipient) || dataRecipient.isBlank()) {
            throw invalid("数据和模型必须由同一客户密钥管理后才能创建训练任务");
        }
        String outputKid = request.outputRecipientKid() == null || request.outputRecipientKid().isBlank()
                ? dataRecipient : request.outputRecipientKid();
        if (!outputKid.equals(dataRecipient)) throw invalid("结果接收密钥必须属于输入资产客户");
        compute.encryptionIdentity(ownerId, outputKid);
        Map<String, Object> authorization = assets.authorize(ownerId,
                new ConfidentialAssetService.GatewayRequest(taskId, taskName, node, purpose,
                        List.of(request.dataAssetVersionId(), request.modelAssetVersionId())));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> approvals = (List<Map<String, Object>>) authorization.get("requests");
        String now = Instant.now().toString();
        String configHash = ConfidentialCanonical.sha256(config);
        jdbc.update("insert into ds_confidential_training_task(task_id,owner_id,task_name,purpose,compute_node,"
                        + "data_asset_id,data_asset_version_id,model_asset_id,model_asset_version_id,data_request_id,"
                        + "model_request_id,epochs,learning_rate,status,progress,current_epoch,metrics_json,created_at,"
                        + "updated_at,node_id,created_by,adapter_id,training_config_json,training_config_hash,"
                        + "runtime_image_digest,output_recipient_kid,cleanup_status) values(?,?,?,?,?,?,?,?,?,?,?,?,?,"
                        + "'WAITING_APPROVAL',0,0,'{}',?,?,?,?,?,?,?,?,?,'NOT_STARTED')",
                taskId, ownerId, taskName, purpose, node, data.get("asset_id"), request.dataAssetVersionId(),
                model.get("asset_id"), request.modelAssetVersionId(),
                requestId(approvals, request.dataAssetVersionId()), requestId(approvals, request.modelAssetVersionId()),
                config.path("epochs").asInt(1), config.path("learningRate").asText(), now, now, node, ownerId,
                adapter, write(config), configHash, "sha256:builtin-training-v1", outputKid);
        insertInput(taskId, "train-data", data, requestId(approvals, request.dataAssetVersionId()), now);
        insertInput(taskId, "model", model, requestId(approvals, request.modelAssetVersionId()), now);
        audit.audit(ownerId, "CONFIDENTIAL_TRAINING_APPROVAL_REQUESTED", taskId,
                mapper.valueToTree(Map.of("adapterId", adapter, "trainingConfigHash", configHash,
                        "computeNode", node, "approvalCount", 2)));
        return task(ownerId, taskId);
    }

    public List<Map<String, Object>> list(String ownerId) {
        return jdbc.queryForList("select * from ds_confidential_training_task where owner_id=? order by updated_at desc",
                ownerId).stream().map(row -> view(sync(ownerId, refresh(ownerId, row)))).toList();
    }

    public Map<String, Object> task(String ownerId, String taskId) {
        Map<String, Object> row = sync(ownerId, refresh(ownerId, taskRow(ownerId, taskId)));
        Map<String, Object> result = view(row);
        result.put("inputs", inputViews(taskId));
        if ("WAITING_KEY_RELEASE".equals(text(row.get("status")))) {
            result.put("taskSpec", parse(text(row.get("task_spec_json"))));
            result.put("taskSpecDigest", row.get("task_spec_digest"));
            result.put("attestation", parse(text(row.get("attestation_json"))));
            result.put("inputManifests", inputManifests(inputRows(taskId)));
        }
        return result;
    }

    @Transactional
    public Map<String, Object> prepare(String ownerId, String taskId, PrepareRequest request) {
        Map<String, Object> row = refresh(ownerId, taskRow(ownerId, taskId));
        if (!"AUTHORIZED_WAITING_START".equals(text(row.get("status")))) {
            throw invalid("数据和模型必须全部审批通过后才能准备训练");
        }
        String adapter = text(row.get("adapter_id"));
        String configHash = text(row.get("training_config_hash"));
        String workload = "training/" + taskId + "/" + adapter + "/" + configHash;
        List<Map<String, Object>> inputs = inputRows(taskId);
        List<String> versions = inputs.stream().map(item -> text(item.get("asset_version_id"))).toList();
        String domainId = text(version(versions.get(0)).get("domain_id"));
        Map<String, Object> created = compute.createTask(ownerId,
                new ConfidentialComputeService.CreateTaskRequest(domainId, "train", workload, versions,
                        List.of(text(row.get("output_recipient_kid"))), "a100-sim", "controlled-sim-ok"));
        JsonNode taskSpec = (JsonNode) created.get("taskSpec");
        JsonNode attestation = compute.createAttestation(ownerId,
                new ConfidentialComputeService.AttestationRequest(taskSpec.path("taskId").asText(),
                        required(request.clientNonce(), "clientNonce"), "a100-sim"));
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='WAITING_KEY_RELEASE',task_spec_digest=?,"
                        + "task_spec_json=?,attestation_session_id=?,attestation_json=?,updated_at=? where task_id=?",
                created.get("taskSpecDigest"), write(taskSpec),
                attestation.path("sessionId").asText(), write(attestation), now, taskId);
        Map<String, Object> result = task(ownerId, taskId);
        result.put("taskSpec", taskSpec);
        result.put("taskSpecDigest", created.get("taskSpecDigest"));
        result.put("attestation", attestation);
        result.put("inputManifests", inputManifests(inputs));
        return result;
    }

    @Transactional
    public Map<String, Object> releaseKeys(String ownerId, String taskId, KeyReleaseRequest request) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (!"WAITING_KEY_RELEASE".equals(text(row.get("status")))) throw invalid("任务当前不接受密钥释放");
        JsonNode grant = object(request.grant(), "grant");
        JsonNode sealedDeks = array(request.sealedDeks(), "sealedDeks");
        String cryptoTaskId = parse(text(row.get("task_spec_json"))).path("taskId").asText();
        String sessionId = text(row.get("attestation_session_id"));
        Map<String, Object> stored = compute.saveGrant(ownerId,
                new ConfidentialComputeService.GrantRequest(cryptoTaskId, sessionId, grant, sealedDeks,
                        mapper.createArrayNode(), mapper.createArrayNode(), "NORMAL"));
        Set<String> expected = inputRows(taskId).stream()
                .map(item -> text(item.get("asset_version_id"))).collect(java.util.stream.Collectors.toSet());
        Set<String> supplied = new java.util.HashSet<>();
        for (JsonNode sealed : sealedDeks) supplied.add(sealed.path("assetVersionId").asText());
        if (!expected.equals(supplied)) throw invalid("模型和数据 DEK 必须同时为本次任务释放");
        String now = Instant.now().toString();
        for (JsonNode sealed : sealedDeks) {
            jdbc.update("update ds_confidential_training_input set grant_json=?,sealed_dek_json=?,"
                            + "key_release_status='RELEASED',updated_at=? where task_id=? and asset_version_id=?",
                    write(grant), write(sealed), now, taskId, sealed.path("assetVersionId").asText());
        }
        jdbc.update("update ds_confidential_training_task set status='READY_TO_STAGE',updated_at=? where task_id=?",
                now, taskId);
        audit.audit(ownerId, "CONFIDENTIAL_TRAINING_KEYS_RELEASED", taskId,
                mapper.valueToTree(Map.of("grantId", stored.get("grantId"), "inputCount", supplied.size())));
        return task(ownerId, taskId);
    }

    // staging 要把模型包与数据包的密文块逐块推给 CipherGPU，属分钟级 I/O。
    // SQLite 数据源只有一条连接，置于事务内会独占该连接使平台整体不可访问，故不加事务；
    // 失败分支已有 markFailed 收口。
    public Map<String, Object> start(String ownerId, String taskId) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (!"READY_TO_STAGE".equals(text(row.get("status")))) throw invalid("训练密钥尚未全部释放");
        List<Map<String, Object>> inputs = inputRows(taskId);
        JsonNode grant = parse(text(inputs.get(0).get("grant_json")));
        String grantId = grant.path("claims").path("grantId").asText();
        String cryptoTaskId = parse(text(row.get("task_spec_json"))).path("taskId").asText();
        JsonNode payload = compute.consumeTrainingGrant(ownerId, cryptoTaskId, grantId);
        JsonNode identity = mapper.valueToTree(compute.encryptionIdentity(ownerId,
                text(row.get("output_recipient_kid"))));
        ObjectNode request = mapper.createObjectNode();
        request.put("jobId", taskId);
        request.set("taskSpec", parse(text(row.get("task_spec_json"))));
        request.put("taskSpecDigest", text(row.get("task_spec_digest")));
        request.put("sessionId", text(row.get("attestation_session_id")));
        ArrayNode grants = request.putArray("grants");
        grants.add(payload.path("grant"));
        ArrayNode preparedInputs = request.putArray("inputs");
        for (Map<String, Object> input : inputs) {
            Map<String, Object> version = version(text(input.get("asset_version_id")));
            JsonNode manifest = parse(text(version.get("manifest_json")));
            ObjectNode item = preparedInputs.addObject();
            item.put("slot", input.get("slot").toString());
            item.put("assetVersionId", input.get("asset_version_id").toString());
            item.put("packageFormat", packageFormat(text(version.get("original_file_name"))));
            item.put("manifestHash", text(version.get("manifest_hash")));
            item.set("manifest", manifest);
            item.put("ownerSigningPublicKey", required(text(version.get("owner_signing_public_key")),
                    "ownerSigningPublicKey"));
            item.put("ownerSignature", required(text(version.get("owner_signature")), "ownerSignature"));
            item.set("sealedDek", parse(text(input.get("sealed_dek_json"))));
            item.set("chunks", normalizedChunks(manifest));
        }
        ObjectNode recipient = request.putObject("outputRecipient");
        recipient.put("kid", identity.path("kid").asText());
        recipient.put("encryptionPublicKey", identity.path("encryption_public_key").asText());
        request.put("adapterId", text(row.get("adapter_id")));
        request.set("trainingConfig", parse(text(row.get("training_config_json"))));
        request.put("trainingConfigHash", text(row.get("training_config_hash")));
        cipherGpu.prepareTrainingJob(request);
        try {
            for (Map<String, Object> input : inputs) stageInput(taskId, input);
            JsonNode started = cipherGpu.startTrainingJob(taskId);
            String now = Instant.now().toString();
            jdbc.update("update ds_confidential_training_task set status='RUNNING',progress=?,ciphergpu_job_id=?,"
                            + "started_at=?,queued_at=?,updated_at=?,cleanup_status='PENDING' where task_id=?",
                    started.path("progress").asInt(31), taskId, now, now, now, taskId);
            markRequests(ownerId, row, "RUNNING", "CIPHERGPU_TRAINING_STARTED");
            audit.audit(ownerId, "CONFIDENTIAL_GPU_TRAINING_STARTED", taskId,
                    mapper.valueToTree(Map.of("adapterId", row.get("adapter_id"), "ciphergpuJobId", taskId)));
            return task(ownerId, taskId);
        } catch (RuntimeException failure) {
            try { cipherGpu.cancelTrainingJob(taskId); } catch (RuntimeException ignored) { }
            markFailed(ownerId, taskId, failure.getMessage());
            throw failure;
        }
    }

    // 收集结果同样是流式 I/O：从 CipherGPU 取回结果密文并写入 MinIO，理由同 start。
    public Map<String, Object> collectOutputs(String ownerId, String taskId) {
        Map<String, Object> row = sync(ownerId, taskRow(ownerId, taskId));
        if (!"OUTPUT_READY".equals(text(row.get("status")))) throw invalid("训练结果尚未加密完成");
        JsonNode outputs = cipherGpu.trainingOutputs(taskId).path("outputs");
        Map<String, Object> resultModel = persistOutput(ownerId, row, taskId, "result-model",
                "RESULT_MODEL", outputs.path("result-model").path("manifest"));
        Map<String, Object> resultData = persistOutput(ownerId, row, taskId, "result-data",
                "RESULT_DATA", outputs.path("result-data").path("manifest"));
        cipherGpu.acknowledgeTrainingOutputs(taskId);
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='COMPLETED',progress=100,current_epoch=epochs,"
                        + "result_data_asset_id=?,result_model_asset_id=?,completed_at=?,updated_at=?,"
                        + "cleanup_status='COMPLETED' where task_id=?", resultData.get("assetId"),
                resultModel.get("assetId"), now, now, taskId);
        markRequests(ownerId, row, "COMPLETED", "CIPHERGPU_RESULTS_ENCRYPTED");
        return task(ownerId, taskId);
    }

    public Map<String, Object> logs(String ownerId, String taskId) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (text(row.get("ciphergpu_job_id")).isBlank()) return Map.of("taskId", taskId, "logs", "");
        JsonNode value = cipherGpu.trainingLogs(taskId);
        return Map.of("taskId", taskId, "status", value.path("status").asText(),
                "logs", value.path("logs").asText());
    }

    @Transactional
    public Map<String, Object> cancel(String ownerId, String taskId) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (TERMINAL.contains(text(row.get("status")))) return view(row);
        if (!text(row.get("ciphergpu_job_id")).isBlank()) cipherGpu.cancelTrainingJob(taskId);
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='CANCELLED',cancelled_at=?,completed_at=?,"
                        + "updated_at=?,cleanup_status='COMPLETED' where task_id=?", now, now, now, taskId);
        markRequests(ownerId, row, "FAILED", "TRAINING_CANCELLED");
        return task(ownerId, taskId);
    }

    public Map<String, Object> progress(String ownerId, String taskId, ProgressRequest request) {
        throw invalid("训练进度只能由 CipherGPU 更新");
    }

    public Map<String, Object> complete(String ownerId, String taskId, CompleteRequest request) {
        throw invalid("训练结果只能由 CipherGPU 生成并加密");
    }

    @Transactional
    public Map<String, Object> fail(String ownerId, String taskId, FailRequest request) {
        throw invalid("训练失败状态只能由 CipherGPU 同步，节点管理员可以取消任务");
    }

    private Map<String, Object> markFailed(String ownerId, String taskId, String reason) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (TERMINAL.contains(text(row.get("status")))) return view(row);
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='FAILED',failure_reason=?,completed_at=?,"
                        + "updated_at=?,cleanup_status='COMPLETED' where task_id=?",
                reason == null || reason.isBlank() ? "TRAINING_FAILED" : reason, now, now, taskId);
        markRequests(ownerId, row, "FAILED", "TRAINING_FAILED");
        return task(ownerId, taskId);
    }

    @Transactional
    public Map<String, Object> saveProvider(String ownerId, ProviderRequest request) {
        String baseUrl = required(request.baseUrl(), "baseUrl");
        if (!baseUrl.startsWith("https://") && !baseUrl.startsWith("http://host.docker.internal:"))
            throw invalid("模型 API Base URL 必须使用 HTTPS");
        JsonNode credential = request.encryptedCredential();
        if (credential != null && (!credential.isObject() || credential.has("apiKey")
                || !credential.hasNonNull("cipherHash") || !credential.hasNonNull("keyEnvelope")))
            throw invalid("API Key 必须在浏览器加密后提交");
        if (request.defaultProvider()) jdbc.update(
                "update ds_confidential_llm_provider set is_default=0 where owner_id=?", ownerId);
        String providerId = id("provider");
        String now = Instant.now().toString();
        jdbc.update("insert into ds_confidential_llm_provider(provider_id,owner_id,provider_name,base_url,model_id,"
                        + "encrypted_credential_json,credential_cipher_hash,is_default,status,created_at,updated_at) "
                        + "values(?,?,?,?,?,?,?,?, 'ACTIVE',?,?)", providerId, ownerId,
                required(request.providerName(), "providerName"), baseUrl, required(request.modelId(), "modelId"),
                credential == null ? null : write(credential),
                credential == null ? null : credential.path("cipherHash").asText(),
                request.defaultProvider() ? 1 : 0, now, now);
        return providerView(providerRow(ownerId, providerId), false);
    }

    public List<Map<String, Object>> providers(String ownerId) {
        List<Map<String, Object>> values = new ArrayList<>();
        values.add(Map.of("providerId", "platform-model-api", "providerName", "平台默认模型 API",
                "baseUrl", "部署配置", "modelId", "自动发现", "defaultProvider", true,
                "status", "ACTIVE", "credentialConfigured", false, "credentialMasked", "无需密钥"));
        values.addAll(jdbc.queryForList("select * from ds_confidential_llm_provider where owner_id=? "
                        + "and status='ACTIVE' order by is_default desc,updated_at desc", ownerId)
                .stream().map(row -> providerView(row, false)).toList());
        return values;
    }

    public Map<String, Object> providerCredential(String ownerId, String providerId) {
        return providerView(providerRow(ownerId, providerId), true);
    }

    private void stageInput(String taskId, Map<String, Object> input) {
        String slot = text(input.get("slot"));
        Map<String, Object> version = version(text(input.get("asset_version_id")));
        List<Map<String, Object>> chunks = jdbc.queryForList("select chunk_index,object_uri from "
                        + "ds_confidential_asset_chunk where upload_session_id=? order by chunk_index",
                version.get("upload_session_id"));
        int index = 0;
        for (Map<String, Object> chunk : chunks) {
            try (InputStream stream = storage.open(text(chunk.get("object_uri")))) {
                cipherGpu.uploadTrainingInputChunk(taskId, slot, index, stream);
            } catch (java.io.IOException failure) {
                throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "读取训练输入密文失败");
            }
            index++;
        }
        cipherGpu.finalizeTrainingInput(taskId, slot);
        jdbc.update("update ds_confidential_training_input set staged_chunks=?,expected_chunks=?,"
                        + "key_release_status='STAGED',updated_at=? where task_id=? and slot=?",
                index, index, Instant.now().toString(), taskId, slot);
    }

    private Map<String, Object> persistOutput(String ownerId, Map<String, Object> task, String taskId,
            String slot, String assetType, JsonNode manifest) {
        compute.verifyTrainingOutput(manifest, taskId, text(task.get("output_recipient_kid")));
        List<String> uris = new ArrayList<>();
        for (int index = 0; index < manifest.path("chunks").size(); index++) {
            JsonNode chunk = manifest.path("chunks").get(index);
            try (InputStream input = cipherGpu.openTrainingOutputChunk(taskId, slot, index)) {
                String key = "cipher/" + safe(ownerId) + "/training-results/" + taskId + "/" + slot
                        + "/" + String.format("%08d", index);
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                DigestInputStream verified = new DigestInputStream(input, digest);
                String expectedHash = chunk.path("sha256").asText();
                String uri = storage.put(key, verified, chunk.path("plaintextLength").asLong() + 16,
                        "application/octet-stream", expectedHash);
                if (!expectedHash.equals(HexFormat.of().formatHex(digest.digest()))) {
                    storage.delete(uri);
                    throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "训练结果密文 Hash 不匹配");
                }
                uris.add(uri);
            } catch (TeeException rejected) {
                throw rejected;
            } catch (Exception failure) {
                throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "保存训练结果密文失败");
            }
        }
        return assets.registerRuntimeOutput(ownerId, new ConfidentialAssetService.RuntimeOutputRequest(assetType,
                text(task.get("task_name")) + ("RESULT_MODEL".equals(assetType) ? " · 结果模型" : " · 结果数据"),
                "CipherGPU 训练任务 " + taskId + " 的加密结果", assetName(text(task.get("data_asset_id"))),
                assetName(text(task.get("model_asset_id"))), taskId, text(task.get("compute_node")),
                manifest, uris, mapper.valueToTree(Map.of("taskSpecDigest", task.get("task_spec_digest"),
                        "runtimeImageDigest", task.get("runtime_image_digest")))));
    }

    private Map<String, Object> sync(String ownerId, Map<String, Object> row) {
        String status = text(row.get("status"));
        if (!Set.of("RUNNING", "ENCRYPTING_OUTPUTS", "OUTPUT_READY").contains(status)
                || text(row.get("ciphergpu_job_id")).isBlank()) return row;
        try {
            JsonNode actual = cipherGpu.trainingJob(text(row.get("ciphergpu_job_id")));
            String runtimeStatus = actual.path("status").asText();
            String mapped = switch (runtimeStatus) {
                case "ENCRYPTING_OUTPUTS" -> "ENCRYPTING_OUTPUTS";
                case "OUTPUT_READY" -> "OUTPUT_READY";
                case "FAILED" -> "FAILED";
                case "CANCELLED" -> "CANCELLED";
                default -> "RUNNING";
            };
            jdbc.update("update ds_confidential_training_task set status=?,progress=?,current_epoch=?,metrics_json=?,"
                            + "failure_reason=?,updated_at=?,cleanup_status=? where task_id=?", mapped,
                    actual.path("progress").asInt(), actual.path("currentEpoch").asDouble(),
                    write(actual.path("metrics")), actual.path("errorCode").asText(null), Instant.now().toString(),
                    actual.path("plaintextCleaned").asBoolean(false) ? "INPUTS_CLEANED" : "PENDING",
                    row.get("task_id"));
            return taskRow(ownerId, text(row.get("task_id")));
        } catch (RuntimeException missing) {
            jdbc.update("update ds_confidential_training_task set status='FAILED',failure_reason='RUNTIME_NOT_FOUND',"
                            + "cleanup_status='UNKNOWN',updated_at=? where task_id=?",
                    Instant.now().toString(), row.get("task_id"));
            return taskRow(ownerId, text(row.get("task_id")));
        }
    }

    private Map<String, Object> refresh(String ownerId, Map<String, Object> row) {
        String status = text(row.get("status"));
        if (!Set.of("WAITING_APPROVAL", "AUTHORIZED_WAITING_START").contains(status)) return row;
        String dataStatus = requestStatus(text(row.get("data_request_id")));
        String modelStatus = requestStatus(text(row.get("model_request_id")));
        String next = "WAITING_APPROVAL";
        if ("REJECTED".equals(dataStatus) || "REJECTED".equals(modelStatus)) next = "REJECTED";
        else if ("EXPIRED".equals(dataStatus) || "EXPIRED".equals(modelStatus)) next = "EXPIRED";
        else if ("APPROVED".equals(dataStatus) && "APPROVED".equals(modelStatus)) next = "AUTHORIZED_WAITING_START";
        if (!next.equals(status)) {
            String now = Instant.now().toString();
            jdbc.update("update ds_confidential_training_task set status=?,authorized_at=case when "
                            + "?='AUTHORIZED_WAITING_START' then ? else authorized_at end,updated_at=? where task_id=?",
                    next, next, now, now, row.get("task_id"));
            row = taskRow(ownerId, text(row.get("task_id")));
        }
        return row;
    }

    private Map<String, Object> view(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        row.forEach((key, item) -> value.put(camel(key), item));
        value.put("metrics", parse(text(row.get("metrics_json"))));
        value.put("trainingConfig", parse(text(row.get("training_config_json"))));
        value.remove("metricsJson"); value.remove("trainingConfigJson");
        value.remove("taskSpecJson"); value.remove("attestationJson");
        value.put("dataApprovalStatus", requestStatus(text(row.get("data_request_id"))));
        value.put("modelApprovalStatus", requestStatus(text(row.get("model_request_id"))));
        value.put("dataAssetName", assetName(text(row.get("data_asset_id"))));
        value.put("modelAssetName", assetName(text(row.get("model_asset_id"))));
        return value;
    }

    private void insertInput(String taskId, String slot, Map<String, Object> version, String requestId, String now) {
        jdbc.update("insert into ds_confidential_training_input(task_id,slot,asset_id,asset_version_id,"
                        + "asset_owner_id,request_id,key_release_status,created_at,updated_at) values(?,?,?,?,?,?,"
                        + "'WAITING_APPROVAL',?,?)", taskId, slot, version.get("asset_id"),
                version.get("asset_version_id"), version.get("owner_id"), requestId, now, now);
    }

    private void markRequests(String ownerId, Map<String, Object> row, String status, String event) {
        for (String field : List.of("data_request_id", "model_request_id")) {
            assets.executionEvent(ownerId, text(row.get(field)),
                    new ConfidentialAssetService.ExecutionEventRequest(event, status, mapper.createObjectNode()));
        }
    }

    private List<Map<String, Object>> inputRows(String taskId) {
        return jdbc.queryForList("select * from ds_confidential_training_input where task_id=? order by slot", taskId);
    }

    private List<Map<String, Object>> inputViews(String taskId) {
        return inputRows(taskId).stream().map(row -> Map.<String, Object>of(
                "slot", row.get("slot"), "assetId", row.get("asset_id"),
                "assetVersionId", row.get("asset_version_id"), "requestId", row.get("request_id"),
                "keyReleaseStatus", row.get("key_release_status"),
                "stagedChunks", row.get("staged_chunks"), "expectedChunks", row.get("expected_chunks"))).toList();
    }

    private List<Map<String, Object>> inputManifests(List<Map<String, Object>> inputs) {
        return inputs.stream().map(input -> {
            Map<String, Object> version = version(text(input.get("asset_version_id")));
            return Map.<String, Object>of("slot", input.get("slot"),
                    "assetId", input.get("asset_id"), "assetVersionId", input.get("asset_version_id"),
                    "manifest", parse(text(version.get("manifest_json"))));
        }).toList();
    }

    private ArrayNode normalizedChunks(JsonNode manifest) {
        ArrayNode result = mapper.createArrayNode();
        for (JsonNode chunk : manifest.path("chunks")) {
            ObjectNode item = result.addObject();
            item.put("index", chunk.path("index").asInt()); item.put("format", "ds-envelope/v2");
            item.put("envelopeId", manifest.path("envelopeId").asText());
            item.put("implementationVersion", manifest.path("contentEncryption").path("implementationVersion").asText("1"));
            item.put("algorithm", manifest.path("algorithm").asText()); item.put("nonce", chunk.path("nonce").asText());
            item.set("aad", chunk.path("aad")); item.put("ciphertextSha256", chunk.path("sha256").asText());
        }
        return result;
    }

    private JsonNode defaultConfig(String adapter, int epochs, double learningRate) {
        ObjectNode value = mapper.createObjectNode();
        value.put("epochs", Math.max(1, Math.min(epochs, 20)));
        value.put("learningRate", learningRate > 0 && learningRate <= 0.01 ? learningRate : 0.00002);
        value.put("trainBatchSize", adapter.startsWith("hf-causal") ? 1 : 16);
        value.put("evalBatchSize", adapter.startsWith("hf-causal") ? 1 : 32);
        value.put("mixedPrecision", "bf16"); value.put("seed", 42); value.put("maxRuntimeSeconds", 7200);
        if (adapter.startsWith("hf-causal")) {
            value.put("datasetFormat", "conversational"); value.put("messagesColumn", "messages");
            value.put("maxSequenceLength", 1024); value.put("gradientAccumulationSteps", 8);
            value.put("gradientCheckpointing", true); value.put("assistantOnlyLoss", true); value.put("packing", false);
            ObjectNode lora = value.putObject("lora"); lora.put("r", 16); lora.put("alpha", 32);
            lora.put("dropout", 0.05); lora.put("targetModules", "all-linear"); lora.put("bias", "none");
        } else {
            value.put("textColumn", "sentence"); value.put("labelColumn", "label"); value.put("numLabels", 2);
            value.put("maxLength", 256); value.put("weightDecay", 0.01); value.put("warmupRatio", 0.1);
        }
        return value;
    }

    private JsonNode normalizeTrainingConfig(JsonNode value) {
        if (value.isObject()) {
            ObjectNode result = mapper.createObjectNode();
            value.fields().forEachRemaining(field ->
                    result.set(field.getKey(), normalizeTrainingConfig(field.getValue())));
            return result;
        }
        if (value.isArray()) {
            ArrayNode result = mapper.createArrayNode();
            value.forEach(item -> result.add(normalizeTrainingConfig(item)));
            return result;
        }
        if (value.isFloatingPointNumber()) {
            return mapper.getNodeFactory().textNode(value.decimalValue().stripTrailingZeros().toPlainString());
        }
        return value.deepCopy();
    }

    private static void validateConfig(String adapter, JsonNode config) {
        if (!ADAPTERS.contains(adapter) || !config.isObject()) throw invalid("训练配置无效");
        Set<String> common = Set.of("epochs", "learningRate", "trainBatchSize", "evalBatchSize",
                "mixedPrecision", "seed", "maxRuntimeSeconds", "maxSteps");
        Set<String> specific = adapter.startsWith("hf-causal")
                ? Set.of("datasetFormat", "messagesColumn", "maxSequenceLength", "gradientAccumulationSteps",
                        "gradientCheckpointing", "assistantOnlyLoss", "packing", "lora")
                : Set.of("textColumn", "labelColumn", "numLabels", "maxLength", "weightDecay", "warmupRatio");
        config.fieldNames().forEachRemaining(field -> {
            if (!common.contains(field) && !specific.contains(field)) throw invalid("训练配置包含非白名单字段");
        });
        int epochs = config.path("epochs").asInt(); double rate = config.path("learningRate").asDouble();
        int batch = config.path("trainBatchSize").asInt(); int evalBatch = config.path("evalBatchSize").asInt(1);
        int timeout = config.path("maxRuntimeSeconds").asInt(7200);
        int maxSteps = config.path("maxSteps").asInt(-1);
        if (epochs < 1 || epochs > 20 || rate < 0.0000001 || rate > 0.01
                || batch < 1 || batch > 128 || evalBatch < 1 || evalBatch > 128
                || timeout < 60 || timeout > 86400 || (maxSteps != -1 && (maxSteps < 1 || maxSteps > 100000)))
            throw invalid("训练参数超出允许范围");
        if (!Set.of("bf16", "fp16").contains(config.path("mixedPrecision").asText("bf16")))
            throw invalid("训练精度不受支持");
        if (adapter.startsWith("hf-causal")) {
            if (!"conversational".equals(config.path("datasetFormat").asText())
                    || config.path("messagesColumn").asText().isBlank()
                    || config.path("maxSequenceLength").asInt() < 64
                    || config.path("maxSequenceLength").asInt() > 8192
                    || config.path("gradientAccumulationSteps").asInt() < 1
                    || config.path("gradientAccumulationSteps").asInt() > 128)
                throw invalid("LLM SFT 参数超出允许范围");
            JsonNode lora = config.path("lora");
            if (!lora.isObject() || lora.path("r").asInt() < 1 || lora.path("r").asInt() > 256
                    || lora.path("alpha").asInt() < 1 || lora.path("alpha").asInt() > 1024
                    || lora.path("dropout").asDouble() < 0 || lora.path("dropout").asDouble() > 1
                    || !"all-linear".equals(lora.path("targetModules").asText())
                    || !"none".equals(lora.path("bias").asText()))
                throw invalid("LoRA 参数超出允许范围");
        } else if (config.path("textColumn").asText().isBlank()
                || config.path("labelColumn").asText().isBlank()
                || config.path("numLabels").asInt() < 2 || config.path("numLabels").asInt() > 1000
                || config.path("maxLength").asInt() < 32 || config.path("maxLength").asInt() > 512
                || config.path("weightDecay").asDouble() < 0 || config.path("weightDecay").asDouble() > 1
                || config.path("warmupRatio").asDouble() < 0 || config.path("warmupRatio").asDouble() > 1) {
            throw invalid("小模型训练参数超出允许范围");
        }
    }

    private Map<String, Object> taskRow(String ownerId, String taskId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select * from ds_confidential_training_task where owner_id=? and task_id=?", ownerId, taskId);
        if (rows.size() != 1) throw invalid("训练任务不存在");
        return new LinkedHashMap<>(rows.get(0));
    }

    private Map<String, Object> ownedVersion(String ownerId, String versionId, String type) {
        Map<String, Object> row = version(required(versionId, type + "AssetVersionId"));
        if (!ownerId.equals(text(row.get("owner_id"))) || !type.equals(text(row.get("asset_type"))))
            throw invalid(type + " 资产版本不存在");
        return row;
    }

    private Map<String, Object> version(String versionId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select v.*,a.asset_type from "
                + "ds_confidential_asset_version v join ds_confidential_asset a on a.asset_id=v.asset_id "
                + "where v.asset_version_id=?", versionId);
        if (rows.size() != 1) throw invalid("资产版本不存在");
        return rows.get(0);
    }

    private String requestStatus(String requestId) {
        List<String> rows = jdbc.queryForList("select status from ds_confidential_use_request where request_id=?",
                String.class, requestId);
        return rows.isEmpty() ? "MISSING" : rows.get(0);
    }

    private String assetName(String assetId) {
        List<String> rows = jdbc.queryForList("select name from ds_confidential_asset where asset_id=?",
                String.class, assetId);
        return rows.isEmpty() ? "-" : rows.get(0);
    }

    private static String requestId(List<Map<String, Object>> approvals, String versionId) {
        return approvals.stream().filter(item -> versionId.equals(text(item.get("assetVersionId"))))
                .map(item -> text(item.get("requestId"))).findFirst()
                .orElseThrow(() -> invalid("未生成资产使用申请"));
    }

    private Map<String, Object> providerRow(String ownerId, String providerId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_llm_provider "
                + "where owner_id=? and provider_id=?", ownerId, providerId);
        if (rows.size() != 1) throw invalid("模型 API 配置不存在");
        return rows.get(0);
    }

    private Map<String, Object> providerView(Map<String, Object> row, boolean credential) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("providerId", row.get("provider_id")); value.put("providerName", row.get("provider_name"));
        value.put("baseUrl", row.get("base_url")); value.put("modelId", row.get("model_id"));
        value.put("defaultProvider", number(row.get("is_default")) == 1); value.put("status", row.get("status"));
        value.put("credentialConfigured", row.get("encrypted_credential_json") != null);
        value.put("credentialMasked", row.get("encrypted_credential_json") == null ? "无需密钥" : "sk-****（已加密）");
        if (credential && row.get("encrypted_credential_json") != null)
            value.put("encryptedCredential", parse(text(row.get("encrypted_credential_json"))));
        return value;
    }

    private String write(JsonNode value) {
        try { return mapper.writeValueAsString(value == null ? mapper.createObjectNode() : value); }
        catch (Exception failure) { throw invalid("JSON 序列化失败"); }
    }
    private JsonNode parse(String value) {
        try { return mapper.readTree(value == null || value.isBlank() ? "{}" : value); }
        catch (Exception failure) { throw invalid("JSON 内容损坏"); }
    }
    private static JsonNode object(JsonNode value, String field) {
        if (value == null || !value.isObject()) throw invalid(field + " 必须为对象"); return value;
    }
    private static JsonNode array(JsonNode value, String field) {
        if (value == null || !value.isArray() || value.isEmpty()) throw invalid(field + " 必须为非空数组"); return value;
    }
    private static String packageFormat(String name) {
        String lower = name.toLowerCase();
        if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "TAR_GZ";
        if (lower.endsWith(".tar")) return "TAR";
        if (lower.endsWith(".zip")) return "ZIP";
        throw invalid("训练输入必须是 ZIP、TAR 或 TAR.GZ 完整包");
    }
    private static String id(String prefix) { return prefix + "_" + UUID.randomUUID().toString().replace("-", ""); }
    private static String safe(String value) { return value.replaceAll("[^A-Za-z0-9._-]", "_"); }
    private static String text(Object value) { return value == null ? "" : String.valueOf(value); }
    private static int number(Object value) { return value instanceof Number ? ((Number) value).intValue() : Integer.parseInt(text(value)); }
    private static String required(String value, String field) { if (value == null || value.isBlank()) throw invalid(field + " 不能为空"); return value.trim(); }
    private static String camel(String value) { StringBuilder out = new StringBuilder(); boolean upper = false; for (char c : value.toCharArray()) { if (c == '_') upper = true; else { out.append(upper ? Character.toUpperCase(c) : c); upper = false; } } return out.toString(); }
    private static TeeException invalid(String message) { return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message); }
}
