/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.dev;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.secretflow.secretpad.web.service.governance.CsvUtil;
import org.secretflow.secretpad.web.service.tee.TeeAssetService;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeCrypto;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.secretflow.secretpad.web.service.tee.TeePolicyService;
import org.secretflow.secretpad.web.service.tee.TeeTaskSpec;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** P6 计算任务到冻结 TEE 契约的唯一适配层。 */
@Component
public class TeeDevTaskDispatcher {

    private static final Map<String, String> DEFAULT_OPERATORS = Map.of(
            "SQL", "sql.query", "PYTHON", "python.execute", "FUNCTION", "python.function",
            "JAR", "jar.execute");
    private static final Map<String, String> REPORT_KINDS = Map.of(
            "ml.binary_classification", "EVALUATION_METRICS",
            "ml.regression_evaluation", "EVALUATION_METRICS",
            "report.feature_importance", "FEATURE_IMPORTANCE",
            "report.tree_structure", "TREE_STRUCTURE");

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final TeeAssetRepository assets;
    private final TeeObjectRepository objects;
    private final TeeRuntimeTaskRepository runtimeTasks;
    private final TeeAssetService assetService;
    private final TeePolicyService policyService;

    @Value("${secretpad.data-sandbox.tee.dispatch-enabled:false}")
    private boolean enabled;
    @Value("${TEE_END_ROLES:CLIENT}")
    private String endRoles;
    @Value("${secretpad.node-id:kuscia-system}")
    private String nodeId;
    @Value("${secretpad.data-sandbox.tee.runtime-app-image:}")
    private String runtimeAppImage;
    @Value("${secretpad.data-sandbox.tee.runtime-image-digest:}")
    private String runtimeImageDigest;
    @Value("${secretpad.data-sandbox.tee.runtime-audience:tee-a-runtime}")
    private String audience;
    @Value("${secretpad.data-sandbox.tee.task-signer-kid:center-1}")
    private String signerKid;
    @Value("${secretpad.data-sandbox.tee.task-signer-key:/app/tee-task-signer/client.key}")
    private String signerKey;
    @Value("${secretpad.data-sandbox.tee.builtin-sha256:}")
    private String builtinSha256;
    @Value("${secretpad.data-sandbox.tee.task-lifetime-seconds:240}")
    private long lifetimeSeconds;

    public TeeDevTaskDispatcher(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                                TeeAssetRepository assets, TeeObjectRepository objects,
                                TeeRuntimeTaskRepository runtimeTasks, TeeAssetService assetService,
                                TeePolicyService policyService) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.assets = assets;
        this.objects = objects;
        this.runtimeTasks = runtimeTasks;
        this.assetService = assetService;
        this.policyService = policyService;
    }

    public record Submission(String taskJws, String appImage, String nodeId) {
    }

    public record Receipt(String status, String errorCode, JsonNode outputs) {
    }

    public boolean enabled() {
        return enabled;
    }

    /** 构建、签名并在 ds_dev_task 中持久化；同一平台任务重试时复用原 JWS。 */
    @Transactional
    public Submission prepare(String taskId, String inputB64, String execType, String content,
                              Map<String, Object> params, List<String> allowedImports,
                              String channel, Map<String, Object> executionParameters) {
        requireCenterConfiguration();
        Map<String, Object> taskRow = one("select * from ds_dev_task where id=? and deleted=0", taskId);
        String stored = text(taskRow.get("tee_task_jws"));
        if (!stored.isBlank()) {
            return new Submission(stored, runtimeAppImage, nodeId);
        }

        String sandboxId = required(taskRow, "sandbox_id", "TEE 任务缺少沙箱标识");
        String assetId = resolveAssetId(taskRow, sandboxId);
        TeeAssetDO asset = latestAsset(assetId, taskRow, sandboxId);
        TeeObjectDO object = objects.findById(new TeeObjectDO.UPK(asset.getObjectId()))
                .orElseThrow(() -> contract("密文对象未登记"));
        if (!"ASSET".equals(object.getKind()) || object.getSizeBytes() == null || object.getSizeBytes() < 0) {
            throw contract("任务输入不是有效密文资产");
        }
        TeeCrypto.EncryptedObject encrypted = assetService.readObject(asset.getOwnerId(), asset.getObjectId());
        if (!assetId.equals(encrypted.assetId())
                || !asset.getUpk().getAssetVersion().equals(encrypted.assetVersion())
                || !asset.getKeyId().equals(encrypted.keyId())
                || !asset.getKeyVersion().equals(encrypted.keyVersion())
                || !object.getCiphertextSha256().equals(encrypted.ciphertextSha256())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文资产登记绑定不一致");
        }

        Map<String, Object> programParameters = new LinkedHashMap<>();
        if (params != null) {
            programParameters.putAll(params);
        }
        if (allowedImports != null && !allowedImports.isEmpty()) {
            programParameters.put("allowed_imports", List.copyOf(allowedImports));
        }
        if (executionParameters != null) {
            programParameters.putAll(executionParameters);
        }
        boolean builtin = "canvas".equals(channel);
        String operatorId = builtin
                ? required(programParameters, "op", "可视化建模任务缺少算子标识")
                : text(programParameters.getOrDefault("tee_operator", DEFAULT_OPERATORS.get(execType)));
        if (operatorId.isBlank()) {
            throw contract("TEE 任务缺少受控算子标识");
        }
        programParameters.remove("tee_operator");

        TeePolicyDO policy = policyService.require(asset.getPolicyId(), asset.getPolicyVersion());
        if (!assetId.equals(policy.getAssetId())
                || !asset.getUpk().getAssetVersion().equals(policy.getAssetVersion())
                || !sandboxId.equals(policy.getSandboxId())) {
            throw policyDenied("密文资产的授权规则未覆盖当前沙箱");
        }
        List<String> columns = selectedColumns(inputB64, asset.getSchemaJson(), policyService.columns(policy));
        policyService.requireAllows(policy, columns, operatorId);
        List<String> reportKinds = REPORT_KINDS.containsKey(operatorId)
                ? List.of(REPORT_KINDS.get(operatorId)) : List.of();
        if (!policyService.reportKinds(policy).containsAll(reportKinds)) {
            throw policyDenied("任务申请的报告类型未获授权");
        }

        TeeTaskSpec.Program program = builtin
                ? builtinProgram(programParameters)
                : objectProgram(execType, content, programParameters);
        Instant issuedAt = Instant.now();
        long lifetime = Math.min(Math.max(lifetimeSeconds, 1), TeeContract.MAX_TASK_LIFETIME_SECONDS);
        String requestId = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        TeeTaskSpec spec = new TeeTaskSpec(TeeContract.VERSION, taskId, requestId, nodeId, audience,
                sandboxId, operatorId, columns,
                List.of(new TeeTaskSpec.Input(assetId,
                        positive(asset.getUpk().getAssetVersion(), "assetVersion"), asset.getKeyId(),
                        positive(asset.getKeyVersion(), "keyVersion"), asset.getPolicyId(),
                        positive(asset.getPolicyVersion(), "policyVersion"), asset.getObjectId(),
                        object.getCiphertextSha256(), plaintextBytes(assetId))),
                program, issuedAt.toString(), issuedAt.plusSeconds(lifetime).toString(), nonce,
                new TeeTaskSpec.OutputPolicy(reportKinds, true, true, true), runtimeImageDigest);
        String compact = compactJws(mapper, spec, readPrivateKey(Path.of(signerKey)), signerKid);
        int updated = jdbc.update("update ds_dev_task set tee_task_jws=?,tee_request_id=?,tee_nonce=?,"
                        + "tee_runtime_image_digest=?,tee_dispatch_status='PREPARED',source_asset_id=?,updated_at=? "
                        + "where id=? and deleted=0 and coalesce(tee_task_jws,'')=''",
                compact, requestId, nonce, runtimeImageDigest, assetId, java.time.LocalDateTime.now().toString(), taskId);
        if (updated != 1) {
            String winner = text(one("select tee_task_jws from ds_dev_task where id=? and deleted=0", taskId)
                    .get("tee_task_jws"));
            if (winner.isBlank()) {
                throw contract("TEE 任务说明持久化失败");
            }
            compact = winner;
        }
        return new Submission(compact, runtimeAppImage, nodeId);
    }

    public void mark(String taskId, String state) {
        jdbc.update("update ds_dev_task set tee_dispatch_status=?,updated_at=? where id=? and deleted=0",
                state, java.time.LocalDateTime.now().toString(), taskId);
    }

    /** 只读取 P5 已验签并落库的回执，不信任 Kuscia 日志或容器输出。 */
    public Receipt receipt(String taskId) {
        TeeRuntimeTaskDO task = runtimeTasks.findById(new TeeRuntimeTaskDO.UPK(taskId)).orElse(null);
        if (task == null || !Boolean.TRUE.equals(task.getReceiptVerified()) || task.getReceiptJws() == null) {
            return null;
        }
        try {
            String[] parts = task.getReceiptJws().split("\\.");
            JsonNode payload = mapper.readTree(TeeCrypto.decodeUrl(parts[1]));
            return new Receipt(payload.path("status").asText(), payload.path("errorCode").asText(""),
                    payload.path("outputs"));
        } catch (Exception failure) {
            throw contract("已验签回执记录无法解析");
        }
    }

    private TeeTaskSpec.Program builtinProgram(Map<String, Object> parameters) {
        if (builtinSha256 == null || !builtinSha256.matches("[0-9a-f]{64}")) {
            throw contract("可信运行时内置算子摘要未配置");
        }
        return new TeeTaskSpec.Program("BUILTIN", null, builtinSha256,
                java.util.Collections.unmodifiableMap(new LinkedHashMap<>(parameters)));
    }

    private TeeTaskSpec.Program objectProgram(String execType, String content, Map<String, Object> parameters) {
        String kind = "FUNCTION".equals(execType) ? "PYTHON" : execType;
        if (!Set.of("SQL", "PYTHON", "JAR").contains(kind)) {
            throw contract("TEE 程序类型不受支持");
        }
        byte[] bytes;
        try {
            String source = requiredText(content, "程序内容为空");
            if ("SQL".equals(kind)) {
                source = adaptSql(source, text(parameters.get("input_table")));
            }
            bytes = "JAR".equals(kind) ? Base64.getDecoder().decode(source)
                    : source.getBytes(StandardCharsets.UTF_8);
        } catch (IllegalArgumentException failure) {
            throw contract("JAR 程序不是有效 Base64");
        }
        TeeAssetService.ProgramReference reference = assetService.registerProgram(nodeId, kind, bytes);
        return new TeeTaskSpec.Program(kind, reference.objectId(), reference.sha256(),
                java.util.Collections.unmodifiableMap(new LinkedHashMap<>(parameters)));
    }

    /** 当前 P5 SQL 运行时将首个输入固定建为 input_0；用签名 CTE 保持原表名兼容。 */
    static String adaptSql(String sql, String inputTable) {
        String source = requiredText(sql, "SQL 程序为空").trim();
        if (inputTable == null || inputTable.isBlank() || "input_0".equals(inputTable)) {
            return source;
        }
        if (!inputTable.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw contract("SQL 输入表名不符合安全标识符规则");
        }
        String alias = "\"" + inputTable + "\" AS (SELECT * FROM input_0)";
        if (source.regionMatches(true, 0, "WITH", 0, 4)) {
            return "WITH " + alias + ", " + source.substring(4).stripLeading();
        }
        return "WITH " + alias + " " + source;
    }

    private TeeAssetDO latestAsset(String assetId, Map<String, Object> taskRow, String sandboxId) {
        String requestedVersion = "";
        List<Map<String, Object>> mounts = jdbc.queryForList(
                "select asset_version from ds_sandbox_dataset_mount where sandbox_id=? and asset_id=? "
                        + "and deleted=0 and status='READY' order by updated_at desc limit 1", sandboxId, assetId);
        if (!mounts.isEmpty()) {
            requestedVersion = text(mounts.get(0).get("asset_version"));
        }
        if (!requestedVersion.isBlank()) {
            String version = requestedVersion;
            return assets.findById(new TeeAssetDO.UPK(assetId, version))
                    .orElseThrow(() -> contract("挂载版本未登记为密文资产"));
        }
        return assets.findByUpkAssetId(assetId).stream()
                .max(Comparator.comparingLong(item -> positive(item.getUpk().getAssetVersion(), "assetVersion")))
                .orElseThrow(() -> contract("输入资产未登记为密文资产"));
    }

    private String resolveAssetId(Map<String, Object> task, String sandboxId) {
        String assetId = text(task.get("source_asset_id"));
        if (!assetId.isBlank()) {
            return assetId;
        }
        String table = text(task.get("source_table_name"));
        if (!table.isBlank()) {
            List<Map<String, Object>> rows = jdbc.queryForList(
                    "select asset_id from ds_sandbox_data_dir where sandbox_id=? and table_name=? "
                            + "and kind='MOUNT' and deleted=0 limit 1", sandboxId, table);
            if (!rows.isEmpty()) {
                return text(rows.get(0).get("asset_id"));
            }
        }
        throw contract("TEE 任务无法解析已登记密文输入资产");
    }

    /**
     * 明文长度来自资产登记元数据；中心端无需也不得通过解密推断该字段。
     *
     * <p>供数方的资产行只存在于对方本地，中心端改读挂载时留存的项目侧资产快照，
     * 该快照与资产登记同源，同样不涉及解密。</p>
     */
    private long plaintextBytes(String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select metadata_json from ds_data_asset where id=? and deleted=0 and status='ACTIVE' limit 1",
                assetId);
        String metadataJson = rows.size() == 1 ? text(rows.get(0).get("metadata_json")) : snapshotMetadata(assetId);
        if (metadataJson.isBlank()) {
            throw contract("密文资产缺少明文长度登记");
        }
        try {
            JsonNode metadata = mapper.readTree(metadataJson);
            JsonNode value = metadata.get("plaintextBytes");
            if (value == null || !value.canConvertToLong() || value.longValue() <= 0) {
                throw new IllegalArgumentException("invalid plaintextBytes");
            }
            return value.longValue();
        } catch (Exception failure) {
            throw contract("密文资产明文长度登记无效");
        }
    }

    /** 项目侧留存的资产快照里的元数据，挂载时随授权一并写入。 */
    private String snapshotMetadata(String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select asset_json from ds_project_asset where asset_id=? and deleted=0 limit 1", assetId);
        if (rows.size() != 1) {
            return "";
        }
        try {
            JsonNode snapshot = mapper.readTree(text(rows.get(0).get("asset_json")));
            return snapshot.path("metadata_json").asText("");
        } catch (Exception failure) {
            return "";
        }
    }

    private List<String> selectedColumns(String inputB64, String schemaJson, List<String> policyColumns) {
        List<String> registered;
        try {
            registered = mapper.readerForListOf(String.class).readValue(schemaJson);
        } catch (Exception failure) {
            throw contract("密文资产表结构损坏");
        }
        // TEE 调度不依赖平台侧明文表头；默认使用审批规则中冻结的列范围。
        List<String> selected = new ArrayList<>(policyColumns);
        if (inputB64 != null && !inputB64.isBlank()) {
            try {
                List<List<String>> csv = CsvUtil.parse(new String(Base64.getDecoder().decode(inputB64),
                        StandardCharsets.UTF_8));
                if (!csv.isEmpty()) {
                    selected = new ArrayList<>(csv.get(0));
                }
            } catch (Exception failure) {
                throw contract("任务列范围无法解析");
            }
        }
        if (selected.isEmpty() || selected.contains("*")
                || !new LinkedHashSet<>(registered).containsAll(selected)) {
            throw policyDenied("任务列范围超出密文资产登记结构");
        }
        return List.copyOf(new LinkedHashSet<>(selected));
    }

    private void requireCenterConfiguration() {
        if (!enabled) {
            throw contract("TEE 任务下发未启用");
        }
        boolean center = java.util.Arrays.stream(endRoles.split(","))
                .map(String::trim).map(value -> value.toUpperCase(Locale.ROOT)).anyMatch("CENTER"::equals);
        if (!center) {
            throw policyDenied("TEE 计算任务只能由 CENTER 下发");
        }
        requiredText(runtimeAppImage, "可信运行时 AppImage 未配置");
        requiredText(runtimeImageDigest, "可信运行时镜像摘要未配置");
        if (lifetimeSeconds <= 0 || lifetimeSeconds > TeeContract.MAX_TASK_LIFETIME_SECONDS) {
            throw contract("TEE 任务有效期配置超出契约上限");
        }
    }

    static String compactJws(ObjectMapper mapper, TeeTaskSpec task, PrivateKey key, String kid) {
        try {
            Map<String, String> header = new LinkedHashMap<>();
            header.put("alg", "RS256");
            header.put("typ", "JWS");
            header.put("kid", requiredText(kid, "任务签名 kid 未配置"));
            String encodedHeader = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(header));
            String encodedPayload = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(task));
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update((encodedHeader + "." + encodedPayload).getBytes(StandardCharsets.US_ASCII));
            return encodedHeader + "." + encodedPayload + "." + TeeCrypto.encodeUrl(signature.sign());
        } catch (TeeException rejected) {
            throw rejected;
        } catch (Exception failure) {
            throw contract("TEE 任务签名失败");
        }
    }

    static PrivateKey readPrivateKey(Path path) {
        try {
            if (!Files.isRegularFile(path) || Files.size(path) > 32 * 1024) {
                throw new IllegalArgumentException("invalid key path");
            }
            String pem = Files.readString(path).replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            return KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        } catch (Exception failure) {
            throw contract("中心任务签名私钥不可用");
        }
    }

    private Map<String, Object> one(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        if (rows.size() != 1) {
            throw contract("TEE 任务记录不存在或不唯一");
        }
        return rows.get(0);
    }

    private static long positive(String value, String name) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed > 0) {
                return parsed;
            }
        } catch (Exception ignored) {
            // 统一返回契约错误，避免泄露内部解析细节。
        }
        throw contract(name + " 不是正整数");
    }

    private static String required(Map<String, Object> values, String key, String message) {
        return requiredText(text(values.get(key)), message);
    }

    private static String requiredText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw contract(message);
        }
        return value;
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static TeeException contract(String message) {
        return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message);
    }

    private static TeeException policyDenied(String message) {
        return TeeException.of(TeeContract.Error.POLICY_DENIED, message);
    }
}
