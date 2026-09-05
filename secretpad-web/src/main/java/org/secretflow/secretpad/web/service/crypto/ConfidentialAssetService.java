package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Ciphertext-only registry shared by datasets, model weights and execution results. */
@Service
public class ConfidentialAssetService {
    private static final int MAX_CHUNK_BYTES = 16 * 1024 * 1024 + 64;
    private static final Set<String> TYPES = Set.of("DATA", "MODEL", "RESULT_DATA", "RESULT_MODEL");
    private static final Set<String> SOURCES = Set.of("UPLOAD", "AI_GENERATED", "COMPUTE_RESULT");
    private static final Set<String> ALGORITHMS = Set.of("AES-256-GCM", "AES-256-GCM-SIV",
            "CHACHA20-POLY1305", "XCHACHA20-POLY1305", "AES-256-SIV");

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final MinioAssetStorage storage;
    private final ConfidentialComputeService compute;
    private final ConfidentialMetadataStore audit;
    private final String defaultLlmUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public ConfidentialAssetService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
            MinioAssetStorage storage, ConfidentialComputeService compute, ConfidentialMetadataStore audit,
            @Value("${DATA_SANDBOX_DEV_VLLM_URL:http://host.docker.internal:39089/v1}") String defaultLlmUrl) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.storage = storage;
        this.compute = compute;
        this.audit = audit;
        this.defaultLlmUrl = defaultLlmUrl.replaceAll("/$", "");
    }

    public record CreateUploadRequest(String assetType, String sourceType, String name, String description,
            String originalFileName, long originalSize, String domainId, String algorithm, int expectedChunks) {}
    public record CommitRequest(JsonNode manifest, String manifestHash, String ownerSigningPublicKey,
            String ownerSignature, String sourceDataName, String sourceModelName, String taskId,
            String computeNode) {}
    public record UseRequest(String assetVersionId, String applicant, String computeNode, String taskId,
            String taskName, String purpose, String validUntil) {}
    public record DecisionRequest(String action, String comment) {}
    public record GatewayRequest(String taskId, String taskName, String computeNode, String purpose,
            List<String> assetVersionIds) {}
    public record ExecutionEventRequest(String eventType, String status, JsonNode detail) {}
    public record ExecutionOutputRequest(String uploadSessionId, CommitRequest asset) {}
    public record GenerateDataRequest(String providerId, String prompt, List<String> fields, int rowCount,
            String apiKey, String baseUrl, String modelId) {}
    public record ConsumeGrantRequest(String taskId, String computeNode, String token) {}
    public record ProtocolAuthorizationRequest(String scenario) {}

    /** Calls an OpenAI-compatible provider and keeps generated clear text in memory only. */
    public Map<String, Object> generateData(String ownerId, GenerateDataRequest request) {
        required(request.providerId(), "providerId");
        required(request.prompt(), "prompt");
        if (request.fields() == null || request.fields().isEmpty() || request.fields().size() > 64)
            throw invalid("CSV 字段数必须为 1 至 64");
        int rows = request.rowCount() <= 0 ? 20 : Math.min(request.rowCount(), 1000);
        String providerId = required(request.providerId(), "providerId");
        String baseUrl = defaultLlmUrl;
        String modelId = "";
        if (request.baseUrl() != null && !request.baseUrl().isBlank()) {
            baseUrl = validGeneratorUrl(request.baseUrl());
            modelId = request.modelId() == null ? "" : request.modelId().trim();
        } else if (!"platform-model-api".equals(providerId)) {
            List<Map<String, Object>> providers = jdbc.queryForList("select * from ds_confidential_llm_provider where owner_id=? and provider_id=? and status='ACTIVE'", ownerId, providerId);
            if (providers.size() != 1) throw invalid("大模型 API 配置不存在");
            baseUrl = text(providers.get(0).get("base_url")).replaceAll("/$", "");
            modelId = text(providers.get(0).get("model_id"));
            if (providers.get(0).get("encrypted_credential_json") != null && (request.apiKey() == null || request.apiKey().isBlank()))
                throw invalid("本次生成需要由浏览器解封 API Key");
        }
        String csv = callCsvGenerator(baseUrl, modelId, request.apiKey(), request.prompt(), request.fields(), rows);
        audit.audit(ownerId, "AI_DATA_GENERATED", id("generation"),
                mapper.valueToTree(Map.of("providerId", request.providerId(), "rowCount", rows,
                        "fieldCount", request.fields().size())));
        return Map.of("providerId", providerId, "format", "CSV", "rowCount", rows, "csv", csv);
    }

    private static String validGeneratorUrl(String value) {
        try {
            URI uri = URI.create(value.trim());
            String scheme = uri.getScheme();
            boolean developmentVllm = "http".equalsIgnoreCase(scheme)
                    && "host.docker.internal".equalsIgnoreCase(uri.getHost());
            if ((!"https".equalsIgnoreCase(scheme) && !developmentVllm) || uri.getHost() == null
                    || uri.getUserInfo() != null || uri.getFragment() != null) throw invalid("模型 API 地址必须是 HTTPS（本机 vLLM 可使用 host.docker.internal）");
            String result = uri.toString();
            return result.endsWith("/") ? result.substring(0, result.length() - 1) : result;
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw invalid("模型 API 地址格式无效");
        }
    }

    private String callCsvGenerator(String baseUrl, String configuredModel, String apiKey, String prompt,
            List<String> fields, int rows) {
        try {
            String model = configuredModel;
            if (model == null || model.isBlank()) {
                HttpRequest modelsRequest = HttpRequest.newBuilder(URI.create(baseUrl + "/models"))
                        .timeout(Duration.ofSeconds(20)).GET().build();
                JsonNode models = mapper.readTree(http.send(modelsRequest, HttpResponse.BodyHandlers.ofString()).body());
                model = models.path("data").path(0).path("id").asText();
            }
            if (model == null || model.isBlank()) throw invalid("模型 API 未返回可用 Model ID");
            String instruction = "只输出 RFC4180 CSV，不要 Markdown 代码块或解释。首行必须严格为："
                    + String.join(",", fields) + "。生成严格 " + rows + " 行数据（不含表头）。要求：" + prompt;
            JsonNode body = mapper.valueToTree(Map.of("model", model, "temperature", 0.3,
                    "messages", List.of(Map.of("role", "system", "content", "你是结构化测试数据生成器。"),
                            Map.of("role", "user", "content", instruction))));
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + "/chat/completions"))
                    .timeout(Duration.ofSeconds(90)).header("Content-Type", "application/json");
            if (apiKey != null && !apiKey.isBlank()) builder.header("Authorization", "Bearer " + apiKey.trim());
            HttpResponse<String> response = http.send(builder.POST(HttpRequest.BodyPublishers.ofString(write(body))).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300)
                throw invalid("模型 API 调用失败，HTTP " + response.statusCode());
            String value = mapper.readTree(response.body()).path("choices").path(0).path("message").path("content").asText().trim();
            if (value.startsWith("```")) value = value.replaceFirst("^```(?:csv)?\\s*", "").replaceFirst("\\s*```$", "");
            String[] lines = value.replace("\r", "").split("\n");
            if (lines.length != rows + 1 || !String.join(",", fields).equals(lines[0].trim()))
                throw invalid("模型返回内容未通过 CSV 字段或行数校验");
            return String.join("\n", lines) + "\n";
        } catch (TeeException failure) {
            throw failure;
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw invalid("模型 API 调用被中断");
        } catch (Exception failure) {
            throw invalid("模型 API 调用失败：" + failure.getMessage());
        }
    }

    @Transactional
    public Map<String, Object> createUpload(String ownerId, CreateUploadRequest request) {
        String type = member(request.assetType(), TYPES, "assetType");
        String source = member(request.sourceType(), SOURCES, "sourceType");
        String algorithm = member(request.algorithm(), ALGORITHMS, "algorithm");
        String name = required(request.name(), "name");
        String fileName = required(request.originalFileName(), "originalFileName");
        compute.requireUsableDomain(required(request.domainId(), "domainId"));
        if (request.originalSize() <= 0 || request.expectedChunks() <= 0) throw invalid("文件大小和分块数必须为正数");
        String id = id("aupload");
        Instant now = Instant.now();
        Instant expires = now.plus(2, ChronoUnit.HOURS);
        jdbc.update("insert into ds_confidential_asset_upload(upload_session_id,owner_id,asset_type,source_type,"
                        + "name,description,original_file_name,original_size,domain_id,algorithm,expected_chunks,"
                        + "received_chunks,status,created_at,expires_at) values(?,?,?,?,?,?,?,?,?,?,?,0,'UPLOADING',?,?)",
                id, ownerId, type, source, name, request.description() == null ? "" : request.description(),
                fileName, request.originalSize(), request.domainId(), algorithm, request.expectedChunks(),
                now.toString(), expires.toString());
        audit.audit(ownerId, "ASSET_CIPHER_UPLOAD_STARTED", id,
                mapper.valueToTree(Map.of("assetType", type, "algorithm", algorithm)));
        return Map.of("uploadSessionId", id, "status", "UPLOADING", "expiresAt", expires.toString());
    }

    @Transactional
    public Map<String, Object> uploadChunk(String ownerId, String sessionId, int index, byte[] ciphertext,
            String expectedHash) {
        Map<String, Object> session = upload(ownerId, sessionId);
        if (!"UPLOADING".equals(text(session.get("status")))
                || Instant.parse(text(session.get("expires_at"))).isBefore(Instant.now())) throw invalid("上传会话已过期或不可写");
        int expected = number(session.get("expected_chunks"));
        if (index < 0 || index >= expected || ciphertext.length == 0 || ciphertext.length > MAX_CHUNK_BYTES)
            throw invalid("密文分块索引或大小不合法");
        String actual = ConfidentialCanonical.sha256Bytes(ciphertext);
        if (!actual.equals(hash(expectedHash)))
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文分块 Hash 不匹配");
        String key = "cipher/" + safe(ownerId) + "/assets/" + sessionId + "/" + String.format("%08d", index);
        String uri = storage.put(key, new ByteArrayInputStream(ciphertext), ciphertext.length,
                "application/octet-stream", actual);
        int count = jdbc.queryForObject("select count(1) from ds_confidential_asset_chunk where upload_session_id=? and chunk_index=?",
                Integer.class, sessionId, index);
        if (count == 0) {
            jdbc.update("insert into ds_confidential_asset_chunk(upload_session_id,chunk_index,object_uri,cipher_hash,cipher_size,created_at) values(?,?,?,?,?,?)",
                    sessionId, index, uri, actual, ciphertext.length, Instant.now().toString());
            jdbc.update("update ds_confidential_asset_upload set received_chunks=received_chunks+1 where upload_session_id=?", sessionId);
        } else {
            jdbc.update("update ds_confidential_asset_chunk set object_uri=?,cipher_hash=?,cipher_size=?,created_at=? where upload_session_id=? and chunk_index=?",
                    uri, actual, ciphertext.length, Instant.now().toString(), sessionId, index);
        }
        return Map.of("index", index, "cipherHash", actual, "status", "STORED");
    }

    @Transactional
    public Map<String, Object> commit(String ownerId, String sessionId, CommitRequest request) {
        Map<String, Object> session = upload(ownerId, sessionId);
        if (!"UPLOADING".equals(text(session.get("status")))) throw invalid("上传会话不能提交");
        int expected = number(session.get("expected_chunks"));
        if (number(session.get("received_chunks")) != expected) throw invalid("密文分块尚未全部上传");
        JsonNode manifest = request.manifest();
        if (manifest == null || !manifest.isObject() || !"ds-envelope/v2".equals(manifest.path("format").asText())
                || !text(session.get("algorithm")).equals(manifest.path("algorithm").asText())
                || manifest.path("chunks").size() != expected) throw invalid("manifest 格式、算法或分块数不匹配");
        String manifestHash = hash(request.manifestHash());
        if (!manifestHash.equals(ConfidentialCanonical.sha256(manifest)))
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "manifest Hash 不匹配");
        List<Map<String, Object>> chunks = jdbc.queryForList("select * from ds_confidential_asset_chunk where upload_session_id=? order by chunk_index", sessionId);
        long cipherSize = 0;
        for (int i = 0; i < expected; i++) {
            JsonNode declared = manifest.path("chunks").get(i);
            if (declared.has("ciphertext") || declared.path("index").asInt(-1) != i
                    || !text(chunks.get(i).get("cipher_hash")).equals(declared.path("sha256").asText()))
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "manifest 分块声明不匹配");
            cipherSize += ((Number) chunks.get(i).get("cipher_size")).longValue();
        }
        String signingKey = required(request.ownerSigningPublicKey(), "ownerSigningPublicKey");
        audit.requireSigningIdentity(ownerId, signingKey);
        ConfidentialCanonical.verifyEd25519(signingKey, required(request.ownerSignature(), "ownerSignature"), manifest);
        String now = Instant.now().toString();
        String assetId = id("asset");
        String versionId = id("assetv");
        jdbc.update("insert into ds_confidential_asset(asset_id,owner_id,asset_type,source_type,name,description,latest_version,status,created_at,updated_at) values(?,?,?,?,?,?,1,'ENCRYPTED',?,?)",
                assetId, ownerId, session.get("asset_type"), session.get("source_type"), session.get("name"),
                session.get("description"), now, now);
        jdbc.update("insert into ds_confidential_asset_version(asset_version_id,asset_id,owner_id,upload_session_id,version_number,domain_id,algorithm,original_file_name,original_size,cipher_size,storage_node,manifest_json,manifest_hash,owner_signature,status,source_data_name,source_model_name,task_id,compute_node,created_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'ENCRYPTED',?,?,?,?,?)",
                versionId, assetId, ownerId, sessionId, 1, session.get("domain_id"), session.get("algorithm"),
                session.get("original_file_name"), session.get("original_size"), cipherSize, "受管密文存储节点",
                write(manifest), manifestHash, request.ownerSignature(), request.sourceDataName(),
                request.sourceModelName(), request.taskId(), request.computeNode(), now);
        jdbc.update("update ds_confidential_asset_upload set status='COMMITTED' where upload_session_id=?", sessionId);
        audit.audit(ownerId, "CONFIDENTIAL_ASSET_COMMITTED", versionId,
                mapper.valueToTree(Map.of("assetId", assetId, "manifestHash", manifestHash)));
        return asset(ownerId, assetId);
    }

    public List<Map<String, Object>> list(String ownerId, String assetType) {
        List<Map<String, Object>> rows = assetType == null || assetType.isBlank()
                ? jdbc.queryForList("select a.*,v.* from ds_confidential_asset a join ds_confidential_asset_version v on a.asset_id=v.asset_id and a.latest_version=v.version_number where a.owner_id=? order by a.updated_at desc", ownerId)
                : jdbc.queryForList("select a.*,v.* from ds_confidential_asset a join ds_confidential_asset_version v on a.asset_id=v.asset_id and a.latest_version=v.version_number where a.owner_id=? and a.asset_type=? order by a.updated_at desc", ownerId, member(assetType, TYPES, "assetType"));
        return rows.stream().map(this::view).toList();
    }

    public Map<String, Object> asset(String ownerId, String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select a.*,v.* from ds_confidential_asset a join ds_confidential_asset_version v on a.asset_id=v.asset_id and a.latest_version=v.version_number where a.owner_id=? and a.asset_id=?", ownerId, assetId);
        if (rows.size() != 1) throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "资产不存在或不属于当前用户");
        return view(rows.get(0));
    }

    public Map<String, Object> ciphertext(String ownerId, String assetId) {
        Map<String, Object> row = row(ownerId, assetId);
        String sessionId = text(row.get("upload_session_id"));
        List<Map<String, Object>> chunks = jdbc.queryForList("select * from ds_confidential_asset_chunk where upload_session_id=? order by chunk_index", sessionId);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, Object> chunk : chunks) {
            try (InputStream input = storage.open(text(chunk.get("object_uri")))) {
                result.add(Map.of("index", chunk.get("chunk_index"), "sha256", chunk.get("cipher_hash"),
                        "ciphertext", Base64.getUrlEncoder().withoutPadding().encodeToString(input.readAllBytes())));
            } catch (Exception failure) {
                throw invalid("密文分块不可读");
            }
        }
        return Map.of("manifest", parse(text(row.get("manifest_json"))), "chunks", result);
    }

    public Map<String, Object> previewSession(String ownerId, String assetId) {
        Map<String, Object> value = ciphertext(ownerId, assetId);
        return Map.of("previewSessionId", id("preview"), "expiresAt", Instant.now().plus(5, ChronoUnit.MINUTES).toString(),
                "ciphertextPackage", value);
    }

    @Transactional
    public Map<String, Object> requestUse(String ownerId, UseRequest request) {
        Map<String, Object> version = version(request.assetVersionId());
        String assetOwner = text(version.get("owner_id"));
        String id = id("use");
        Instant now = Instant.now();
        Instant validUntil = request.validUntil() == null || request.validUntil().isBlank()
                ? now.plus(24, ChronoUnit.HOURS) : Instant.parse(request.validUntil());
        jdbc.update("insert into ds_confidential_use_request(request_id,owner_id,asset_id,asset_version_id,applicant,compute_node,task_id,task_name,purpose,status,valid_until,requested_at) values(?,?,?,?,?,?,?,?,?,'PENDING',?,?)",
                id, assetOwner, version.get("asset_id"), request.assetVersionId(), required(request.applicant(), "applicant"),
                required(request.computeNode(), "computeNode"), required(request.taskId(), "taskId"),
                required(request.taskName(), "taskName"), required(request.purpose(), "purpose"), validUntil.toString(), now.toString());
        event(assetOwner, id, "REQUESTED", "PENDING", mapper.createObjectNode());
        return useRequest(assetOwner, id);
    }

    @Transactional
    public Map<String, Object> decide(String ownerId, String requestId, DecisionRequest request) {
        Map<String, Object> current = useRow(ownerId, requestId);
        if (!"PENDING".equals(text(current.get("status")))) throw invalid("该申请已处理");
        String next = "APPROVE".equalsIgnoreCase(request.action()) ? "APPROVED"
                : "REJECT".equalsIgnoreCase(request.action()) ? "REJECTED" : null;
        if (next == null) throw invalid("action 必须为 APPROVE 或 REJECT");
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_use_request set status=?,approval_comment=?,decided_at=? where request_id=?",
                next, request.comment() == null ? "" : request.comment(), now, requestId);
        event(ownerId, requestId, next, next, mapper.valueToTree(Map.of("comment", request.comment() == null ? "" : request.comment())));
        return useRequest(ownerId, requestId);
    }

    public List<Map<String, Object>> usage(String ownerId, String assetId) {
        asset(ownerId, assetId);
        return jdbc.queryForList("select * from ds_confidential_use_request where owner_id=? and asset_id=? order by requested_at desc", ownerId, assetId)
                .stream().map(this::useView).toList();
    }

    @Transactional
    public Map<String, Object> authorize(String requesterId, GatewayRequest request) {
        if (request.assetVersionIds() == null || request.assetVersionIds().isEmpty()) throw invalid("至少选择一个资产版本");
        List<Map<String, Object>> approvals = new ArrayList<>();
        boolean ready = true;
        for (String versionId : request.assetVersionIds()) {
            Map<String, Object> version = version(versionId);
            List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_use_request where asset_version_id=? and task_id=? and compute_node=? order by requested_at desc",
                    versionId, request.taskId(), request.computeNode());
            Map<String, Object> row;
            if (rows.isEmpty()) {
                row = requestUse(requesterId, new UseRequest(versionId, requesterId, request.computeNode(),
                        request.taskId(), request.taskName(), request.purpose(), null));
                ready = false;
            } else {
                row = useView(rows.get(0));
                ready &= "APPROVED".equals(row.get("status"))
                        && Instant.parse(text(row.get("validUntil"))).isAfter(Instant.now());
            }
            approvals.add(row);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("taskId", request.taskId());
        response.put("status", ready ? "READY" : "AUTHORIZATION_REQUIRED");
        response.put("ready", ready);
        response.put("requests", approvals);
        if (ready) response.put("executionGrant", issueGrant(requesterId, request.taskId(),
                request.computeNode(), request.assetVersionIds()));
        return response;
    }

    /** Atomically consumes the short-lived grant at the managed key-release boundary. */
    @Transactional
    public Map<String, Object> consumeGrant(String ownerId, ConsumeGrantRequest request) {
        String taskId = required(request.taskId(), "taskId");
        String computeNode = required(request.computeNode(), "computeNode");
        String tokenHash = tokenHash(required(request.token(), "token"));
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select * from ds_confidential_execution_grant where owner_id=? and task_id=? and compute_node=? and token_hash=?",
                ownerId, taskId, computeNode, tokenHash);
        if (rows.size() != 1) throw invalid("执行授权不存在、已失效或绑定条件不匹配");
        Map<String, Object> grant = rows.get(0);
        if (!"ACTIVE".equals(text(grant.get("status")))) throw invalid("一次性执行授权已被消费，禁止重放");
        if (!Instant.parse(text(grant.get("expires_at"))).isAfter(Instant.now())) {
            jdbc.update("update ds_confidential_execution_grant set status='EXPIRED' where grant_id=? and status='ACTIVE'",
                    grant.get("grant_id"));
            throw invalid("执行授权已过期");
        }
        String now = Instant.now().toString();
        int changed = jdbc.update("update ds_confidential_execution_grant set status='CONSUMED',consumed_at=? where grant_id=? and status='ACTIVE'",
                now, grant.get("grant_id"));
        if (changed != 1) throw invalid("一次性执行授权已被消费，禁止重放");
        audit.audit(ownerId, "EXECUTION_GRANT_CONSUMED", text(grant.get("grant_id")),
                mapper.valueToTree(Map.of("taskId", taskId, "computeNode", computeNode)));
        return Map.of("grantId", grant.get("grant_id"), "status", "CONSUMED",
                "taskId", taskId, "computeNode", computeNode, "consumedAt", now);
    }

    /** Runs authorization protocol scenarios through the same persisted one-time grant verifier. */
    @Transactional
    public Map<String, Object> validateAuthorizationProtocol(String ownerId,
            ProtocolAuthorizationRequest request) {
        String scenario = required(request.scenario(), "scenario").toUpperCase();
        String taskId = id("protocol_task");
        String node = "协议验证节点";
        if ("UNAUTHORIZED".equals(scenario)) {
            try {
                consumeGrant(ownerId, new ConsumeGrantRequest(taskId, node, id("missing")));
                return Map.of("passed", false, "actual", "未授权请求意外通过");
            } catch (TeeException expected) {
                return Map.of("passed", true, "actual", "授权服务未释放密钥：" + expected.getMessage());
            }
        }
        if ("REPLAYED".equals(scenario)) {
            Map<String, Object> grant = issueGrant(ownerId, taskId, node, List.of("protocol-test"));
            String token = text(grant.get("token"));
            consumeGrant(ownerId, new ConsumeGrantRequest(taskId, node, token));
            try {
                consumeGrant(ownerId, new ConsumeGrantRequest(taskId, node, token));
                return Map.of("passed", false, "actual", "同一执行授权被重复消费");
            } catch (TeeException expected) {
                return Map.of("passed", true, "actual", "首次消费成功，重放被阻断：" + expected.getMessage());
            }
        }
        throw invalid("仅支持 UNAUTHORIZED 或 REPLAYED 授权场景");
    }

    private Map<String, Object> issueGrant(String ownerId, String taskId, String computeNode,
            List<String> assetVersionIds) {
        String grantId = id("grant");
        String token = id("exec");
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);
        jdbc.update("insert into ds_confidential_execution_grant(grant_id,owner_id,task_id,compute_node,asset_versions_json,token_hash,status,issued_at,expires_at) values(?,?,?,?,?,?,'ACTIVE',?,?)",
                grantId, ownerId, required(taskId, "taskId"), required(computeNode, "computeNode"),
                write(mapper.valueToTree(assetVersionIds)), tokenHash(token), issuedAt.toString(), expiresAt.toString());
        audit.audit(ownerId, "EXECUTION_GRANT_ISSUED", grantId,
                mapper.valueToTree(Map.of("taskId", taskId, "computeNode", computeNode,
                        "assetVersionCount", assetVersionIds.size())));
        return Map.of("grantId", grantId, "token", token, "expiresAt", expiresAt.toString(),
                "singleUse", true, "taskId", taskId, "computeNode", computeNode);
    }

    private static String tokenHash(String token) {
        return ConfidentialCanonical.sha256Bytes(token.getBytes(StandardCharsets.UTF_8));
    }

    @Transactional
    public Map<String, Object> executionEvent(String ownerId, String requestId, ExecutionEventRequest request) {
        Map<String, Object> current = useRow(ownerId, requestId);
        String status = required(request.status(), "status");
        if (!Set.of("APPROVED", "RUNNING", "COMPLETED", "FAILED").contains(status)) throw invalid("执行状态不合法");
        if ("RUNNING".equals(status) && !"APPROVED".equals(current.get("status"))) throw invalid("资产尚未批准，执行已阻断");
        String now = Instant.now().toString();
        jdbc.update("update ds_confidential_use_request set status=?,started_at=case when ?='RUNNING' then ? else started_at end,completed_at=case when ? in ('COMPLETED','FAILED') then ? else completed_at end where request_id=?",
                status, status, now, status, now, requestId);
        event(ownerId, requestId, required(request.eventType(), "eventType"), status,
                request.detail() == null ? mapper.createObjectNode() : request.detail());
        return useRequest(ownerId, requestId);
    }

    public Map<String, Object> registerOutput(String ownerId, String executionId, ExecutionOutputRequest request) {
        if (request.asset() == null) throw invalid("结果资产不能为空");
        CommitRequest value = request.asset();
        CommitRequest bound = new CommitRequest(value.manifest(), value.manifestHash(),
                value.ownerSigningPublicKey(), value.ownerSignature(), value.sourceDataName(),
                value.sourceModelName(), executionId, value.computeNode());
        return commit(ownerId, required(request.uploadSessionId(), "uploadSessionId"), bound);
    }

    private void event(String ownerId, String requestId, String type, String status, JsonNode detail) {
        jdbc.update("insert into ds_confidential_usage_event(event_id,owner_id,request_id,event_type,status,detail_json,created_at) values(?,?,?,?,?,?,?)",
                id("uevent"), ownerId, requestId, type, status, write(detail), Instant.now().toString());
    }

    private Map<String, Object> upload(String ownerId, String id) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_asset_upload where owner_id=? and upload_session_id=?", ownerId, id);
        if (rows.size() != 1) throw invalid("上传会话不存在");
        return rows.get(0);
    }
    private Map<String, Object> row(String ownerId, String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select a.*,v.* from ds_confidential_asset a join ds_confidential_asset_version v on a.asset_id=v.asset_id and a.latest_version=v.version_number where a.owner_id=? and a.asset_id=?", ownerId, assetId);
        if (rows.size() != 1) throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "资产不存在或不属于当前用户");
        return rows.get(0);
    }
    private Map<String, Object> version(String id) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_asset_version where asset_version_id=?", id);
        if (rows.size() != 1) throw invalid("资产版本不存在");
        return rows.get(0);
    }
    private Map<String, Object> useRow(String ownerId, String id) {
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_confidential_use_request where owner_id=? and request_id=?", ownerId, id);
        if (rows.size() != 1) throw invalid("使用申请不存在");
        return rows.get(0);
    }
    private Map<String, Object> useRequest(String ownerId, String id) { return useView(useRow(ownerId, id)); }

    private Map<String, Object> view(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("assetId", row.get("asset_id")); value.put("assetVersionId", row.get("asset_version_id"));
        value.put("assetType", row.get("asset_type")); value.put("sourceType", row.get("source_type"));
        value.put("name", row.get("name")); value.put("description", row.get("description"));
        value.put("version", row.get("version_number")); value.put("domainId", row.get("domain_id"));
        value.put("algorithm", row.get("algorithm")); value.put("originalFileName", row.get("original_file_name"));
        value.put("originalSize", row.get("original_size")); value.put("cipherSize", row.get("cipher_size"));
        value.put("storageNode", row.get("storage_node")); value.put("manifestHash", row.get("manifest_hash"));
        value.put("status", row.get("status")); value.put("sourceDataName", row.get("source_data_name"));
        value.put("sourceModelName", row.get("source_model_name")); value.put("taskId", row.get("task_id"));
        value.put("computeNode", row.get("compute_node")); value.put("createdAt", row.get("created_at"));
        Integer pending = jdbc.queryForObject("select count(1) from ds_confidential_use_request where owner_id=? and asset_id=? and status='PENDING'",
                Integer.class, row.get("owner_id"), row.get("asset_id"));
        value.put("pendingRequestCount", pending == null ? 0 : pending);
        return value;
    }
    private Map<String, Object> useView(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("requestId", row.get("request_id")); value.put("assetId", row.get("asset_id"));
        value.put("assetVersionId", row.get("asset_version_id")); value.put("applicant", row.get("applicant"));
        value.put("computeNode", row.get("compute_node")); value.put("taskId", row.get("task_id"));
        value.put("taskName", row.get("task_name")); value.put("purpose", row.get("purpose"));
        value.put("status", row.get("status")); value.put("validUntil", row.get("valid_until"));
        value.put("approvalComment", row.get("approval_comment")); value.put("requestedAt", row.get("requested_at"));
        value.put("decidedAt", row.get("decided_at")); value.put("startedAt", row.get("started_at"));
        value.put("completedAt", row.get("completed_at"));
        return value;
    }
    private String write(JsonNode value) { try { return mapper.writeValueAsString(value); } catch (Exception e) { throw invalid("JSON 序列化失败"); } }
    private JsonNode parse(String value) { try { return mapper.readTree(value); } catch (Exception e) { throw invalid("资产清单损坏"); } }
    private static String id(String prefix) { return prefix + "_" + UUID.randomUUID().toString().replace("-", ""); }
    private static String safe(String value) { return value.replaceAll("[^A-Za-z0-9._-]", "_"); }
    private static String text(Object value) { return value == null ? "" : String.valueOf(value); }
    private static int number(Object value) { return value instanceof Number ? ((Number) value).intValue() : Integer.parseInt(text(value)); }
    private static String required(String value, String field) { if (value == null || value.isBlank()) throw invalid(field + " 不能为空"); return value.trim(); }
    private static String hash(String value) { String result = required(value, "hash").toLowerCase(); if (!result.matches("[0-9a-f]{64}")) throw invalid("Hash 格式无效"); return result; }
    private static String member(String value, Set<String> allowed, String field) { String result = required(value, field).toUpperCase(); if (!allowed.contains(result)) throw invalid(field + " 不支持"); return result; }
    private static TeeException invalid(String message) { return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message); }
}
