/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 密文资产与密文对象。
 *
 * <p>中心端只接收密文：登记时核对摘要与 AAD 绑定，存储与传输均为密文，
 * 任何接口都不会返回数据行。程序对象只含程序字节，不含数据或密钥。
 */
@Service
public class TeeAssetService {

    private final TeeAssetRepository assets;
    private final TeeObjectRepository objects;
    private final TeeObjectStore store;
    private final TeeKeyService keyService;
    private final TeePolicyService policyService;
    private final TeeIdempotency idempotency;
    private final TeeRuntimeGrantService grants;
    private final ObjectMapper mapper;

    public TeeAssetService(TeeAssetRepository assets, TeeObjectRepository objects, TeeObjectStore store,
                           TeeKeyService keyService, TeePolicyService policyService,
                           TeeIdempotency idempotency, TeeRuntimeGrantService grants,
                           ObjectMapper mapper) {
        this.assets = assets;
        this.objects = objects;
        this.store = store;
        this.keyService = keyService;
        this.policyService = policyService;
        this.idempotency = idempotency;
        this.grants = grants;
        this.mapper = mapper;
    }

    public record RegisterRequest(String contractVersion, String requestId, String ownerId,
                                  List<String> schema, TeeCrypto.EncryptedObject encryptedObject,
                                  String policyId, String policyVersion) {
    }

    public record RegisterResult(String contractVersion, String assetId, String assetVersion, String objectId) {
    }

    public record ObjectRequest(String contractVersion, String requestId, String taskId,
                                String resultId, String resultKind, List<String> contributors,
                                TeeCrypto.EncryptedObject encryptedObject) {
    }

    public record ObjectResult(String contractVersion, String objectId, String exportState) {
    }

    public record ProgramResult(String contractVersion, String kind, String sha256, String contentB64) {
    }

    /** 不可变程序对象引用；程序字节与密文对象共用受控对象目录，但不携带数据密钥。 */
    public record ProgramReference(String objectId, String sha256) {
    }

    /**
     * 登记 SQL、Python 或 JAR 程序。对象标识由类型和内容摘要确定，同内容重试复用原对象，
     * 同标识出现不同类型或摘要时直接拒绝。
     */
    @Transactional
    public ProgramReference registerProgram(String ownerId, String kind, byte[] content) {
        String normalizedOwner = TeeGuard.requireText(ownerId, "ownerId");
        String normalizedKind = TeeGuard.requireText(kind, "program.kind");
        if (!TeeContract.PROGRAM_KINDS.contains(normalizedKind) || "BUILTIN".equals(normalizedKind)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "程序对象类型不受支持");
        }
        if (content == null || content.length == 0) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "程序对象内容为空");
        }
        TeeGuard.requireSize(content.length, TeeContract.MAX_OBJECT_PLAINTEXT_BYTES);
        String digest = TeeCrypto.sha256Hex(content);
        String objectId = TeeCrypto.sha256Hex((normalizedKind + "\0" + digest)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 32);
        TeeObjectDO existing = objects.findById(new TeeObjectDO.UPK(objectId)).orElse(null);
        if (existing != null && (!normalizedKind.equals(existing.getKind())
                || !digest.equals(existing.getCiphertextSha256()))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "程序对象标识已绑定其他内容");
        }
        store.writeProgram(objectId, content);
        objects.save(TeeObjectDO.builder().upk(new TeeObjectDO.UPK(objectId))
                .kind(normalizedKind).ownerId(normalizedOwner).keyId("").keyVersion("")
                .ciphertextSha256(digest).sizeBytes((long) content.length)
                .contributorsJson(write(List.of(normalizedOwner)))
                .exportState(TeeContract.EXPORT_PENDING).build());
        return new ProgramReference(objectId, digest);
    }

    @Transactional
    public RegisterResult register(String ownerId, RegisterRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        TeeGuard.requireOwner(ownerId, TeeGuard.requireText(request.ownerId(), "ownerId"));
        TeeCrypto.EncryptedObject object = requireObject(request.encryptedObject());
        String assetId = TeeGuard.requireText(object.assetId(), "assetId");
        String assetVersion = TeeGuard.requireText(object.assetVersion(), "assetVersion");
        List<String> schema = TeeGuard.requireGrantSet(request.schema(), "表结构列");
        String policyId = TeeGuard.requireText(request.policyId(), "policyId");
        String policyVersion = TeeGuard.requireText(request.policyVersion(), "policyVersion");
        String fingerprint = TeeIdempotency.fingerprint(List.of(assetId, assetVersion,
                object.ciphertextSha256(), policyId, policyVersion, String.join(",", schema)));
        return idempotency.execute(ownerId, "assets/register", requestId, fingerprint,
                RegisterResult.class, () -> {
            TeeKeyDO key = keyService.require(object.keyId(), object.keyVersion());
            TeeGuard.requireOwner(key.getOwnerId(), ownerId);
            keyService.requireActive(key);
            if (!key.getAssetId().equals(assetId) || !key.getAssetVersion().equals(assetVersion)) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密钥与资产版本绑定不符");
            }
            TeePolicyDO policy = policyService.require(policyId, policyVersion);
            TeeGuard.requireOwner(policy.getOwnerId(), ownerId);
            // 授权列必须是已登记表结构的子集，避免授权指向不存在的列。
            TeeGuard.requireSubset(policyService.columns(policy), schema, "授权列");
            verifyIntegrity(object);

            // 同一资产版本重复登记复用已有密文对象，不新建对象标识。
            Optional<TeeAssetDO> existing = assets.findById(new TeeAssetDO.UPK(assetId, assetVersion));
            String objectId = existing.map(TeeAssetDO::getObjectId).orElseGet(TeeAssetService::newObjectId);
            store.write(objectId, object);
            objects.save(TeeObjectDO.builder()
                    .upk(new TeeObjectDO.UPK(objectId)).kind("ASSET").ownerId(ownerId).assetId(assetId)
                    .keyId(object.keyId()).keyVersion(object.keyVersion())
                    .ciphertextSha256(object.ciphertextSha256())
                    .sizeBytes((long) TeeCrypto.decode(object.ciphertextB64()).length)
                    .contributorsJson(write(List.of(ownerId)))
                    .exportState(TeeContract.EXPORT_PENDING).build());
            assets.save(TeeAssetDO.builder()
                    .upk(new TeeAssetDO.UPK(assetId, assetVersion)).ownerId(ownerId)
                    .schemaJson(write(schema)).objectId(objectId)
                    .policyId(policyId).policyVersion(policyVersion)
                    .keyId(object.keyId()).keyVersion(object.keyVersion()).build());
            return new RegisterResult(TeeContract.VERSION, assetId, assetVersion, objectId);
        });
    }

    /** 只允许任务对应的运行时写结果；结果标识首次申领时已与任务原子绑定。 */
    @Transactional
    public ObjectResult putObject(String ownerId, ObjectRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String taskId = TeeGuard.requireText(request.taskId(), "taskId");
        String resultId = TeeGuard.requireText(request.resultId(), "resultId");
        String submittedKind = request.resultKind() == null ? "" : request.resultKind();
        TeeCrypto.EncryptedObject object = requireObject(request.encryptedObject());
        String fingerprint = TeeIdempotency.fingerprint(
                List.of(taskId, resultId, submittedKind, object.ciphertextSha256()));
        return idempotency.execute(ownerId, "objects", requestId, fingerprint, ObjectResult.class, () -> {
            requireResultBoundToTask(resultId, taskId);
            TeeRuntimeGrantService.ResultBinding binding = grants.requireResult(ownerId, taskId, resultId);
            if (request.resultKind() != null && !request.resultKind().isBlank()
                    && !binding.kind().equals(request.resultKind())) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED, "结果类型与密钥申领绑定不符");
            }
            List<String> contributors = grants.contributors(ownerId, taskId);
            if (request.contributors() != null
                    && !new java.util.LinkedHashSet<>(contributors).equals(
                    new java.util.LinkedHashSet<>(TeeGuard.requireGrantSet(
                            request.contributors(), "贡献方")))) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                        "运行时提交的贡献方与服务端推导结果不符");
            }
            if (!resultId.equals(object.assetId()) || !"1".equals(object.assetVersion())
                    || !binding.keyId().equals(object.keyId())
                    || !binding.keyVersion().equals(object.keyVersion())) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED,
                        "密文结果未绑定任务申领的结果标识和密钥");
            }
            verifyIntegrity(object);
            String objectId = objects.findByResultId(resultId).stream().findFirst()
                    .map(item -> item.getUpk().getObjectId()).orElseGet(TeeAssetService::newObjectId);
            store.write(objectId, object);
            objects.save(TeeObjectDO.builder()
                    .upk(new TeeObjectDO.UPK(objectId)).kind(binding.kind()).ownerId(ownerId)
                    .taskId(taskId).resultId(resultId)
                    .keyId(object.keyId()).keyVersion(object.keyVersion())
                    .ciphertextSha256(object.ciphertextSha256())
                    .sizeBytes((long) TeeCrypto.decode(object.ciphertextB64()).length)
                    .contributorsJson(write(contributors))
                    .exportState(TeeContract.EXPORT_PENDING).build());
            return new ObjectResult(TeeContract.VERSION, objectId, TeeContract.EXPORT_PENDING);
        });
    }

    /** 按任务或资产权属鉴权，只返回密文；不做任何解密。 */
    public TeeCrypto.EncryptedObject readObject(String ownerId, String objectId) {
        return readObject(ownerId, objectId, null);
    }

    public TeeCrypto.EncryptedObject readObject(String ownerId, String objectId, String taskId) {
        TeeObjectDO record = objects.findById(new TeeObjectDO.UPK(TeeGuard.requireText(objectId, "objectId")))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "对象不存在或无权访问"));
        if (!record.getOwnerId().equals(ownerId) && !readList(record.getContributorsJson()).contains(ownerId)) {
            grants.requireObjectRead(ownerId, TeeGuard.requireText(taskId, "X-TEE-Task-Id"), objectId);
        }
        return store.read(objectId);
    }

    public ProgramResult readProgram(String objectId) {
        return readProgram(null, null, objectId);
    }

    public ProgramResult readProgram(String ownerId, String taskId, String objectId) {
        if (ownerId != null) {
            grants.requireProgramRead(ownerId, TeeGuard.requireText(taskId, "X-TEE-Task-Id"), objectId);
        }
        TeeObjectDO record = objects.findById(new TeeObjectDO.UPK(TeeGuard.requireText(objectId, "objectId")))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "程序对象不存在"));
        if (!TeeContract.PROGRAM_KINDS.contains(record.getKind())) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "该对象不是程序对象");
        }
        byte[] content = store.readProgram(objectId);
        String digest = TeeCrypto.sha256Hex(content);
        if (!digest.equals(record.getCiphertextSha256())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "程序摘要与登记不符");
        }
        return new ProgramResult(TeeContract.VERSION, record.getKind(), digest, TeeCrypto.encode(content));
    }

    /**
     * 跨节点同步的出口形态。
     *
     * <p>抽样脱敏是本地明文处理，不涉及加密；加密的边界是数据离开本节点。
     * 已登记为密文资产的数据只以密文出节点，同步通道不再导出任何明文行。
     */
    public Optional<TeeCrypto.EncryptedObject> ciphertextForSync(String assetId) {
        return assets.findByUpkAssetId(assetId).stream()
                .max(Comparator.comparing(item -> item.getUpk().getAssetVersion()))
                .map(asset -> store.read(asset.getObjectId()));
    }

    /** 请求方接收密文：校验摘要与 AAD 绑定后登记为密文对象，不物化任何明文行。 */
    @Transactional
    public String ingestSynced(String ownerId, TeeCrypto.EncryptedObject object) {
        TeeCrypto.EncryptedObject verified = requireObject(object);
        verifyIntegrity(verified);
        String objectId = objects.findAll().stream()
                .filter(item -> verified.ciphertextSha256().equals(item.getCiphertextSha256()))
                .findFirst().map(item -> item.getUpk().getObjectId()).orElseGet(TeeAssetService::newObjectId);
        store.write(objectId, verified);
        objects.save(TeeObjectDO.builder()
                .upk(new TeeObjectDO.UPK(objectId)).kind("ASSET").ownerId(ownerId)
                .assetId(verified.assetId())
                .keyId(verified.keyId()).keyVersion(verified.keyVersion())
                .ciphertextSha256(verified.ciphertextSha256())
                .sizeBytes((long) TeeCrypto.decode(verified.ciphertextB64()).length)
                .contributorsJson(write(List.of(ownerId)))
                .exportState(TeeContract.EXPORT_PENDING).build());
        return objectId;
    }

    public TeeAssetDO requireAsset(String assetId, String assetVersion) {
        return assets.findById(new TeeAssetDO.UPK(assetId, assetVersion))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密文资产未登记"));
    }

    public List<TeeObjectDO> taskObjects(String taskId) {
        return objects.findByTaskId(taskId);
    }

    /** 结果标识首次出现即绑定任务；已绑定其他任务的结果一律拒绝。 */
    private void requireResultBoundToTask(String resultId, String taskId) {
        for (TeeObjectDO existing : objects.findByResultId(resultId)) {
            if (!taskId.equals(existing.getTaskId())) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED, "结果标识已绑定其他任务");
            }
        }
    }

    private TeeCrypto.EncryptedObject requireObject(TeeCrypto.EncryptedObject object) {
        if (object == null) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "缺少 encryptedObject");
        }
        TeeGuard.requireVersion(object.contractVersion());
        if (!TeeContract.KEY_ALGORITHM.equals(object.algorithm())) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密文算法不符合契约");
        }
        return object;
    }

    /** 大小、摘要与 AAD 绑定必须在放行与解密之前校验；平台不持有密钥，因此不做认证解密。 */
    private void verifyIntegrity(TeeCrypto.EncryptedObject object) {
        byte[] nonce = TeeCrypto.decode(object.nonceB64());
        byte[] aad = TeeCrypto.decode(object.aadB64());
        byte[] ciphertext = TeeCrypto.decode(object.ciphertextB64());
        byte[] tag = TeeCrypto.decode(object.tagB64());
        TeeGuard.requireSize(ciphertext.length, TeeContract.MAX_OBJECT_PLAINTEXT_BYTES);
        if (nonce.length != TeeContract.NONCE_BYTES || tag.length != TeeContract.TAG_BYTES) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "nonce 或 tag 长度不符");
        }
        if (!TeeCrypto.digest(nonce, aad, ciphertext, tag).equals(object.ciphertextSha256())) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文摘要不符");
        }
        if (!TeeCrypto.matchesAad(mapper, aad, object)) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "AAD 绑定与声明不一致");
        }
    }

    private static String newObjectId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private String write(List<String> values) {
        try {
            return mapper.writeValueAsString(values);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "列表序列化失败");
        }
    }

    List<String> readList(String json) {
        try {
            return mapper.readerForListOf(String.class).readValue(json);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "已保存的列表无法读取");
        }
    }
}
