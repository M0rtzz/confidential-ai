package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Persistent task gateway for approval-gated confidential training. */
@Service
public class ConfidentialTrainingService {
    private static final Set<String> TERMINAL = Set.of("COMPLETED", "FAILED", "REJECTED");
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ConfidentialAssetService assets;
    private final ConfidentialMetadataStore audit;

    public ConfidentialTrainingService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc,
            ObjectMapper mapper, ConfidentialAssetService assets, ConfidentialMetadataStore audit) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.assets = assets;
        this.audit = audit;
    }

    public record CreateTaskRequest(String taskName, String purpose, String computeNode,
            String dataAssetVersionId, String modelAssetVersionId, int epochs, double learningRate) {}
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
        Map<String, Object> data = ownedVersion(ownerId, request.dataAssetVersionId(), "DATA");
        Map<String, Object> model = ownedVersion(ownerId, request.modelAssetVersionId(), "MODEL");
        int epochs = Math.max(1, Math.min(request.epochs(), 500));
        double learningRate = request.learningRate() > 0 && request.learningRate() <= 1
                ? request.learningRate() : 0.03;
        Map<String, Object> authorization = assets.authorize(ownerId,
                new ConfidentialAssetService.GatewayRequest(taskId, taskName, node, purpose,
                        List.of(request.dataAssetVersionId(), request.modelAssetVersionId())));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> approvals = (List<Map<String, Object>>) authorization.get("requests");
        String dataRequest = requestId(approvals, request.dataAssetVersionId());
        String modelRequest = requestId(approvals, request.modelAssetVersionId());
        String now = Instant.now().toString();
        jdbc.update("insert into ds_confidential_training_task(task_id,owner_id,task_name,purpose,compute_node,"
                        + "data_asset_id,data_asset_version_id,model_asset_id,model_asset_version_id,data_request_id,"
                        + "model_request_id,epochs,learning_rate,status,progress,current_epoch,metrics_json,created_at,updated_at) "
                        + "values(?,?,?,?,?,?,?,?,?,?,?,?,?,'WAITING_APPROVAL',0,0,'{}',?,?)",
                taskId, ownerId, taskName, purpose, node, data.get("asset_id"), request.dataAssetVersionId(),
                model.get("asset_id"), request.modelAssetVersionId(), dataRequest, modelRequest, epochs,
                Double.toString(learningRate), now, now);
        audit.audit(ownerId, "CONFIDENTIAL_TRAINING_APPROVAL_REQUESTED", taskId,
                mapper.valueToTree(Map.of("dataRequestId", dataRequest, "modelRequestId", modelRequest,
                        "computeNode", node, "approvalCount", 2)));
        return task(ownerId, taskId);
    }

    public List<Map<String, Object>> list(String ownerId) {
        return jdbc.queryForList("select * from ds_confidential_training_task where owner_id=? order by updated_at desc",
                ownerId).stream().map(row -> view(refresh(ownerId, row))).toList();
    }

    public Map<String, Object> task(String ownerId, String taskId) {
        return view(refresh(ownerId, taskRow(ownerId, taskId)));
    }

    @Transactional
    public Map<String, Object> start(String ownerId, String taskId) {
        Map<String, Object> row = refresh(ownerId, taskRow(ownerId, taskId));
        if (!"AUTHORIZED_WAITING_START".equals(text(row.get("status")))) {
            throw invalid("数据和模型权重必须全部审批通过后才能启动");
        }
        List<String> versionIds = List.of(text(row.get("data_asset_version_id")),
                text(row.get("model_asset_version_id")));
        Map<String, Object> authorization = assets.authorize(ownerId,
                new ConfidentialAssetService.GatewayRequest(taskId, text(row.get("task_name")),
                        text(row.get("compute_node")), text(row.get("purpose")), versionIds));
        if (!Boolean.TRUE.equals(authorization.get("ready"))) throw invalid("执行授权状态已变化，请重新审批");
        @SuppressWarnings("unchecked")
        Map<String, Object> grant = (Map<String, Object>) authorization.get("executionGrant");
        assets.consumeGrant(ownerId, new ConfidentialAssetService.ConsumeGrantRequest(taskId,
                text(row.get("compute_node")), text(grant.get("token"))));
        markRequest(ownerId, text(row.get("data_request_id")), "RUNNING", "DATA_DECRYPTED_FOR_TRAINING");
        markRequest(ownerId, text(row.get("model_request_id")), "RUNNING", "MODEL_DECRYPTED_FOR_TRAINING");
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='RUNNING',progress=1,started_at=?,updated_at=? where task_id=?",
                now, now, taskId);
        audit.audit(ownerId, "CONFIDENTIAL_TRAINING_STARTED", taskId,
                mapper.valueToTree(Map.of("grantId", grant.get("grantId"), "singleUse", true,
                        "adapter", "browser-managed-mlp")));
        Map<String, Object> result = task(ownerId, taskId);
        result.put("executionGrantId", grant.get("grantId"));
        return result;
    }

    @Transactional
    public Map<String, Object> progress(String ownerId, String taskId, ProgressRequest request) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (!"RUNNING".equals(text(row.get("status")))) throw invalid("任务未处于运行状态");
        int epoch = Math.max(0, Math.min(request.epoch(), number(row.get("epochs"))));
        int progress = Math.max(1, Math.min(request.progress(), 99));
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set current_epoch=?,progress=?,metrics_json=?,updated_at=? where task_id=?",
                epoch, progress, write(request.metrics()), now, taskId);
        return task(ownerId, taskId);
    }

    @Transactional
    public Map<String, Object> complete(String ownerId, String taskId, CompleteRequest request) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (!"RUNNING".equals(text(row.get("status")))) throw invalid("任务未处于运行状态");
        requireResult(ownerId, request.resultDataAssetId(), "RESULT_DATA", taskId);
        requireResult(ownerId, request.resultModelAssetId(), "RESULT_MODEL", taskId);
        markRequest(ownerId, text(row.get("data_request_id")), "COMPLETED", "DATA_REENCRYPTED_AFTER_USE");
        markRequest(ownerId, text(row.get("model_request_id")), "COMPLETED", "MODEL_REENCRYPTED_AFTER_USE");
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='COMPLETED',progress=100,current_epoch=epochs,"
                        + "metrics_json=?,result_data_asset_id=?,result_model_asset_id=?,completed_at=?,updated_at=? where task_id=?",
                write(request.metrics()), request.resultDataAssetId(), request.resultModelAssetId(), now, now, taskId);
        audit.audit(ownerId, "CONFIDENTIAL_TRAINING_RESULTS_ENCRYPTED", taskId,
                mapper.valueToTree(Map.of("resultDataAssetId", request.resultDataAssetId(),
                        "resultModelAssetId", request.resultModelAssetId(), "inputsRemainEncrypted", true)));
        return task(ownerId, taskId);
    }

    @Transactional
    public Map<String, Object> fail(String ownerId, String taskId, FailRequest request) {
        Map<String, Object> row = taskRow(ownerId, taskId);
        if (TERMINAL.contains(text(row.get("status")))) return view(row);
        if ("RUNNING".equals(text(row.get("status")))) {
            markRequest(ownerId, text(row.get("data_request_id")), "FAILED", "TRAINING_FAILED");
            markRequest(ownerId, text(row.get("model_request_id")), "FAILED", "TRAINING_FAILED");
        }
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_training_task set status='FAILED',failure_reason=?,completed_at=?,updated_at=? where task_id=?",
                required(request.reason(), "reason"), now, now, taskId);
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
        if (request.defaultProvider()) jdbc.update("update ds_confidential_llm_provider set is_default=0 where owner_id=?", ownerId);
        String providerId = id("provider");
        String now = Instant.now().toString();
        jdbc.update("insert into ds_confidential_llm_provider(provider_id,owner_id,provider_name,base_url,model_id,"
                        + "encrypted_credential_json,credential_cipher_hash,is_default,status,created_at,updated_at) values(?,?,?,?,?,?,?,?, 'ACTIVE',?,?)",
                providerId, ownerId, required(request.providerName(), "providerName"), baseUrl,
                required(request.modelId(), "modelId"), credential == null ? null : write(credential),
                credential == null ? null : credential.path("cipherHash").asText(), request.defaultProvider() ? 1 : 0,
                now, now);
        return providerView(providerRow(ownerId, providerId), false);
    }

    public List<Map<String, Object>> providers(String ownerId) {
        List<Map<String, Object>> values = new java.util.ArrayList<>();
        values.add(Map.of("providerId", "platform-model-api", "providerName", "平台默认模型 API",
                "baseUrl", "部署配置", "modelId", "自动发现", "defaultProvider", true,
                "status", "ACTIVE", "credentialConfigured", false, "credentialMasked", "无需密钥"));
        values.addAll(jdbc.queryForList("select * from ds_confidential_llm_provider where owner_id=? and status='ACTIVE' order by is_default desc,updated_at desc",
                ownerId).stream().map(row -> providerView(row, false)).toList());
        return values;
    }

    public Map<String, Object> providerCredential(String ownerId, String providerId) {
        return providerView(providerRow(ownerId, providerId), true);
    }

    private Map<String, Object> refresh(String ownerId, Map<String, Object> row) {
        String status = text(row.get("status"));
        if (!"WAITING_APPROVAL".equals(status) && !"AUTHORIZED_WAITING_START".equals(status)) return row;
        String dataStatus = requestStatus(text(row.get("data_request_id")));
        String modelStatus = requestStatus(text(row.get("model_request_id")));
        String next = "WAITING_APPROVAL";
        if ("REJECTED".equals(dataStatus) || "REJECTED".equals(modelStatus)) next = "REJECTED";
        else if ("EXPIRED".equals(dataStatus) || "EXPIRED".equals(modelStatus)) next = "EXPIRED";
        else if ("APPROVED".equals(dataStatus) && "APPROVED".equals(modelStatus)) next = "AUTHORIZED_WAITING_START";
        if (!next.equals(status)) {
            String now = Instant.now().toString();
            jdbc.update("update ds_confidential_training_task set status=?,authorized_at=case when ?='AUTHORIZED_WAITING_START' then ? else authorized_at end,updated_at=? where task_id=?",
                    next, next, now, now, row.get("task_id"));
            row = taskRow(ownerId, text(row.get("task_id")));
        }
        return row;
    }

    private Map<String, Object> view(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        row.forEach((key, item) -> value.put(camel(key), item));
        value.put("metrics", parse(text(row.get("metrics_json"))));
        value.remove("metricsJson");
        value.put("dataApprovalStatus", requestStatus(text(row.get("data_request_id"))));
        value.put("modelApprovalStatus", requestStatus(text(row.get("model_request_id"))));
        value.put("dataAssetName", assetName(text(row.get("data_asset_id"))));
        value.put("modelAssetName", assetName(text(row.get("model_asset_id"))));
        return value;
    }

    private Map<String, Object> taskRow(String ownerId, String taskId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_training_task where owner_id=? and task_id=?", ownerId, taskId);
        if (rows.size() != 1) throw invalid("训练任务不存在");
        return new LinkedHashMap<>(rows.get(0));
    }

    private Map<String, Object> ownedVersion(String ownerId, String versionId, String type) {
        List<Map<String, Object>> rows = jdbc.queryForList("select v.*,a.asset_type from ds_confidential_asset_version v join ds_confidential_asset a on a.asset_id=v.asset_id where v.owner_id=? and v.asset_version_id=?",
                ownerId, required(versionId, type + "AssetVersionId"));
        if (rows.size() != 1 || !type.equals(text(rows.get(0).get("asset_type")))) throw invalid(type + " 资产版本不存在");
        return rows.get(0);
    }

    private void requireResult(String ownerId, String assetId, String type, String taskId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select a.asset_type,v.task_id from ds_confidential_asset a join ds_confidential_asset_version v on a.asset_id=v.asset_id and a.latest_version=v.version_number where a.owner_id=? and a.asset_id=?",
                ownerId, required(assetId, type));
        if (rows.size() != 1 || !type.equals(text(rows.get(0).get("asset_type")))
                || !taskId.equals(text(rows.get(0).get("task_id")))) throw invalid("结果资产未绑定当前训练任务");
    }

    private void markRequest(String ownerId, String requestId, String status, String event) {
        assets.executionEvent(ownerId, requestId,
                new ConfidentialAssetService.ExecutionEventRequest(event, status, mapper.createObjectNode()));
    }

    private String requestStatus(String requestId) {
        List<String> rows = jdbc.queryForList("select status from ds_confidential_use_request where request_id=?", String.class, requestId);
        return rows.isEmpty() ? "MISSING" : rows.get(0);
    }

    private String assetName(String assetId) {
        List<String> rows = jdbc.queryForList("select name from ds_confidential_asset where asset_id=?", String.class, assetId);
        return rows.isEmpty() ? "-" : rows.get(0);
    }

    private static String requestId(List<Map<String, Object>> approvals, String versionId) {
        return approvals.stream().filter(item -> versionId.equals(text(item.get("assetVersionId"))))
                .map(item -> text(item.get("requestId"))).findFirst().orElseThrow(() -> invalid("未生成资产使用申请"));
    }

    private Map<String, Object> providerRow(String ownerId, String providerId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_llm_provider where owner_id=? and provider_id=?", ownerId, providerId);
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
        value.put("createdAt", row.get("created_at")); value.put("updatedAt", row.get("updated_at"));
        if (credential && row.get("encrypted_credential_json") != null)
            value.put("encryptedCredential", parse(text(row.get("encrypted_credential_json"))));
        return value;
    }

    private String write(JsonNode value) { try { return mapper.writeValueAsString(value == null ? mapper.createObjectNode() : value); } catch (Exception e) { throw invalid("JSON 序列化失败"); } }
    private JsonNode parse(String value) { try { return mapper.readTree(value == null || value.isBlank() ? "{}" : value); } catch (Exception e) { return mapper.createObjectNode(); } }
    private static String id(String prefix) { return prefix + "_" + UUID.randomUUID().toString().replace("-", ""); }
    private static String text(Object value) { return value == null ? "" : String.valueOf(value); }
    private static int number(Object value) { return value instanceof Number ? ((Number) value).intValue() : Integer.parseInt(text(value)); }
    private static String required(String value, String field) { if (value == null || value.isBlank()) throw invalid(field + " 不能为空"); return value.trim(); }
    private static String camel(String value) { StringBuilder out = new StringBuilder(); boolean upper = false; for (char c : value.toCharArray()) { if (c == '_') upper = true; else { out.append(upper ? Character.toUpperCase(c) : c); upper = false; } } return out.toString(); }
    private static TeeException invalid(String message) { return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message); }
}
