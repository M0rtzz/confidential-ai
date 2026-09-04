/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Builds the two encrypted inputs used by a model API TEE invocation. */
@Service
public class TeeModelApiAssets {

    public static final String OPERATOR = "model.predict";
    public static final String REPORT_KIND = "MODEL_API_PREDICTION";

    public record Prepared(String sandboxId, String modelKind, String taskType,
                           List<String> features, List<TeeTaskSpec.Input> inputs) {
    }

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final TeeAssetEncryptor encryptor;
    private final TeeAssetService assetService;
    private final TeeKeyService keyService;
    private final KeyAdapterClient adapter;
    private final TeeIdentityRegistry registry;
    private final TeePolicyRepository policies;
    private final TeeObjectRepository objects;
    private final String nodeId;

    public TeeModelApiAssets(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                             TeeAssetEncryptor encryptor, TeeAssetService assetService,
                             TeeKeyService keyService, KeyAdapterClient adapter,
                             TeeIdentityRegistry registry, TeePolicyRepository policies,
                             TeeObjectRepository objects,
                             @Value("${secretpad.node-id:kuscia-system}") String nodeId) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.encryptor = encryptor;
        this.assetService = assetService;
        this.keyService = keyService;
        this.adapter = adapter;
        this.registry = registry;
        this.policies = policies;
        this.objects = objects;
        this.nodeId = nodeId;
    }

    @Transactional
    public Prepared prepare(String taskId, String apiId, String modelId, byte[] inputCsv,
                            List<String> inputColumns) {
        Map<String, Object> api = one("select model_id,status from ds_model_api where id=? and deleted=0", apiId);
        if (!modelId.equals(text(api.get("model_id")))
                || !List.of("PENDING", "ENABLED").contains(text(api.get("status")))) {
            throw denied("模型 API 未处于可调用状态");
        }
        Map<String, Object> binding = one(
                "select * from ds_model_tee_binding where model_id=? and status='ACTIVE'", modelId);
        String objectId = required(binding, "object_id", "模型没有有效的 TEE 密文绑定");
        String resultId = required(binding, "result_id", "TEE 模型缺少结果标识");
        String sandboxId = required(binding, "sandbox_id", "TEE 模型缺少沙箱标识");
        List<String> features = strings(required(binding, "features_json", "TEE 模型缺少特征绑定"));
        if (features.isEmpty() || !inputColumns.containsAll(features)) {
            throw denied("调用输入不包含模型绑定的全部特征");
        }
        TeeObjectDO modelObject = objects.findById(new TeeObjectDO.UPK(objectId))
                .orElseThrow(() -> denied("TEE 模型密文对象不存在"));
        if (!"MODEL".equals(modelObject.getKind()) || !resultId.equals(modelObject.getResultId())
                || !required(binding, "key_id", "TEE 模型缺少密钥绑定").equals(modelObject.getKeyId())
                || !required(binding, "key_version", "TEE 模型缺少密钥版本").equals(modelObject.getKeyVersion())
                || !required(binding, "ciphertext_sha256", "TEE 模型缺少摘要绑定")
                .equals(modelObject.getCiphertextSha256())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "TEE 模型绑定与密文对象不一致");
        }

        String inputAssetId = "api-input-" + taskId;
        TeeAssetEncryptor.Sealed sealed = encryptor.seal(nodeId, inputAssetId, "1", inputCsv);
        TeeTaskSpec.Input requestInput = register(taskId + "-request", apiId, nodeId, sandboxId,
                inputColumns, features, sealed.object(), inputCsv.length);
        TeeCrypto.EncryptedObject modelCiphertext = assetService.readObject(modelObject.getOwnerId(), objectId);
        TeeTaskSpec.Input modelInput = register(taskId + "-model", apiId, modelObject.getOwnerId(), sandboxId,
                features, features, modelCiphertext, modelObject.getSizeBytes());
        return new Prepared(sandboxId, text(binding.get("model_kind")), text(binding.get("task_type")),
                features, List.of(requestInput, modelInput));
    }

    private TeeTaskSpec.Input register(String scopeSeed, String approvalId, String ownerId,
                                       String sandboxId, List<String> schema, List<String> grantedColumns,
                                       TeeCrypto.EncryptedObject ciphertext, long plaintextBytes) {
        TeeKeyDO key = keyService.require(ciphertext.keyId(), ciphertext.keyVersion());
        TeeGuard.requireOwner(key.getOwnerId(), ownerId);
        keyService.requireActive(key);
        String digest = TeeCrypto.sha256Hex(scopeSeed.getBytes(StandardCharsets.UTF_8)).substring(0, 20);
        String policyId = "pl-api-" + digest;
        String policyVersion = "1";
        adapter.call("/v1/policies/register", Map.of(
                "resourceUri", key.getResourceUri(), "scope", policyId,
                "rules", List.of(Map.of(
                        "granteeCertsB64", List.of(TeeCrypto.encode(
                                registry.workloadCertificatePem().getBytes(StandardCharsets.UTF_8))),
                        "columns", grantedColumns, "operators", List.of(OPERATOR)))));
        policies.save(TeePolicyDO.builder().approvalId(approvalId)
                .upk(new TeePolicyDO.UPK(policyId, policyVersion))
                .assetId(ciphertext.assetId()).assetVersion(ciphertext.assetVersion())
                .ownerId(ownerId).sandboxId(sandboxId).columnsJson(json(grantedColumns))
                .operatorsJson(json(List.of(OPERATOR))).reportKindsJson(json(List.of(REPORT_KIND)))
                .expiresAt(Instant.now().plusSeconds(TeeContract.MAX_TASK_LIFETIME_SECONDS).toString())
                .state(TeeContract.STATE_ACTIVE).build());
        TeeAssetService.RegisterResult registered = assetService.register(ownerId,
                new TeeAssetService.RegisterRequest(TeeContract.VERSION, "asset-" + digest, ownerId,
                        schema, ciphertext, policyId, policyVersion));
        TeeObjectDO stored = objects.findById(new TeeObjectDO.UPK(registered.objectId()))
                .orElseThrow(() -> denied("TEE API 输入登记失败"));
        return new TeeTaskSpec.Input(registered.assetId(), Long.parseLong(registered.assetVersion()),
                ciphertext.keyId(), Long.parseLong(ciphertext.keyVersion()), policyId, 1,
                registered.objectId(), stored.getCiphertextSha256(), plaintextBytes);
    }

    private Map<String, Object> one(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        if (rows.isEmpty()) {
            throw denied("TEE 模型或 API 绑定不存在");
        }
        return rows.get(0);
    }

    private List<String> strings(String value) {
        try {
            return mapper.readerForListOf(String.class).readValue(value);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "TEE 模型特征绑定损坏");
        }
    }

    private String json(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "TEE API 策略无法序列化");
        }
    }

    private static String required(Map<String, Object> row, String field, String message) {
        String value = text(row.get(field));
        if (value.isBlank()) {
            throw denied(message);
        }
        return value;
    }

    private static TeeException denied(String message) {
        return TeeException.of(TeeContract.Error.POLICY_DENIED, message);
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
