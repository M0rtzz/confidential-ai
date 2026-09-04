/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeKeyRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 密钥与规则请求的落点选择。
 *
 * <p>密钥服务全系统只有一处，在中心端。中心实例直连密钥适配服务；客户端实例不直连，
 * 而是按方案第 04 节第 2 步经双向 TLS 向中心端申请，签发、申领、吊销与规则登记
 * 全部由中心端裁决并记入唯一台账。
 *
 * <p>客户端在委派成功后保留一份只含标识与状态的本地镜像，供 {@code /assets/register}
 * 校验密文对象与密钥、规则的绑定关系。镜像不含任何密钥材料，也不是权威状态：
 * 申领与运行时放行始终由中心端复核。
 */
@Service
public class TeeKeyGateway {

    private final TeeKeyService keyService;
    private final TeePolicyService policyService;
    private final TeeAssetService assetService;
    private final TeeCenterClient center;
    private final TeeKeyRepository keys;
    private final TeePolicyRepository policies;
    private final ObjectMapper mapper;

    public TeeKeyGateway(TeeKeyService keyService, TeePolicyService policyService,
                         TeeAssetService assetService, TeeCenterClient center,
                         TeeKeyRepository keys, TeePolicyRepository policies, ObjectMapper mapper) {
        this.keyService = keyService;
        this.policyService = policyService;
        this.assetService = assetService;
        this.center = center;
        this.keys = keys;
        this.policies = policies;
        this.mapper = mapper;
    }

    /** 本实例是否把密钥请求委派给中心端。 */
    public boolean delegated() {
        return center.configured();
    }

    @Transactional
    public TeeKeyService.IssueResult issue(String ownerId, TeeKeyService.IssueRequest request) {
        if (!delegated()) {
            return keyService.issue(ownerId, request);
        }
        TeeKeyService.IssueResult result = center.post("/keys/issue", request, TeeKeyService.IssueResult.class);
        mirrorKey(ownerId, request.assetId(), request.assetVersion(), result.keyId(),
                result.keyVersion(), result.state());
        return result;
    }

    public TeeKeyService.ClaimResult claim(String ownerId, TeeKeyService.ClaimRequest request) {
        if (!delegated()) {
            return keyService.claim(ownerId, request);
        }
        return center.post("/keys/claim", request, TeeKeyService.ClaimResult.class);
    }

    @Transactional
    public TeeKeyService.RevokeResult revoke(String ownerId, TeeKeyService.RevokeRequest request) {
        if (!delegated()) {
            return keyService.revoke(ownerId, request);
        }
        TeeKeyService.RevokeResult result = center.post("/keys/revoke", request, TeeKeyService.RevokeResult.class);
        keys.findById(new TeeKeyDO.UPK(result.keyId(), result.keyVersion())).ifPresent(key -> {
            key.setState(result.state());
            keys.save(key);
        });
        return result;
    }

    @Transactional
    public TeePolicyService.RegisterResult registerPolicy(String ownerId, TeePolicyService.RegisterRequest request) {
        if (!delegated()) {
            return policyService.register(ownerId, request);
        }
        TeePolicyService.RegisterResult result =
                center.post("/policies/register", request, TeePolicyService.RegisterResult.class);
        mirrorPolicy(ownerId, request.policy(), result);
        return result;
    }

    /**
     * 登记密文资产。中心端直接落本端台账，客户端经平台间契约通道交给中心端。
     *
     * <p>台账唯一在中心端，因此客户端不镜像资产行，避免出现第二份权威记录。</p>
     */
    public TeeAssetService.RegisterResult registerAsset(String ownerId, TeeAssetService.RegisterRequest request) {
        if (!delegated()) {
            return assetService.register(ownerId, request);
        }
        return center.post("/assets/register", request, TeeAssetService.RegisterResult.class);
    }

    /** 台账唯一在中心端；客户端一律回读中心端，不返回本地镜像的计数。 */
    public List<TeeKeyService.LedgerItem> ledger(String ownerId) {
        if (!delegated()) {
            return keyService.ledger(ownerId);
        }
        JsonNode data = center.get("/keys", JsonNode.class);
        List<TeeKeyService.LedgerItem> items = new ArrayList<>();
        for (JsonNode item : data.path("items")) {
            try {
                items.add(mapper.treeToValue(item, TeeKeyService.LedgerItem.class));
            } catch (Exception failure) {
                throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端台账结构不符");
            }
        }
        return items;
    }

    private void mirrorKey(String ownerId, String assetId, String assetVersion,
                           String keyId, String keyVersion, String state) {
        Optional<TeeKeyDO> existing = keys.findById(new TeeKeyDO.UPK(keyId, keyVersion));
        if (existing.isPresent()) {
            TeeKeyDO key = existing.get();
            key.setState(state);
            keys.save(key);
            return;
        }
        keys.save(TeeKeyDO.builder()
                .upk(new TeeKeyDO.UPK(keyId, keyVersion))
                .assetId(assetId).assetVersion(assetVersion).ownerId(ownerId)
                // 资源标识属于中心端密钥服务的内部引用，镜像不保存，客户端也无从直接调用底座。
                .resourceUri("").state(state)
                .issuedAt(Instant.now().toString()).claimCount(0).releaseCount(0)
                .build());
    }

    private void mirrorPolicy(String ownerId, TeePolicyService.Policy policy,
                              TeePolicyService.RegisterResult result) {
        TeePolicyDO.UPK upk = new TeePolicyDO.UPK(result.policyId(), result.policyVersion());
        if (policies.findById(upk).isPresent()) {
            return;
        }
        policies.save(TeePolicyDO.builder()
                // 审批核验在中心端完成，镜像不复刻审批标识，避免看起来像本地已核验。
                .approvalId("")
                .upk(upk)
                .assetId(policy.assetId()).assetVersion(policy.assetVersion())
                .ownerId(ownerId).sandboxId(policy.sandboxId())
                .columnsJson(write(policy.columns())).operatorsJson(write(policy.operators()))
                .reportKindsJson(write(policy.reportKinds()))
                .expiresAt(TeeGuard.requireInstant(policy.expiresAt(), "expiresAt").toString()).state(result.state())
                .build());
    }

    private String write(List<String> values) {
        try {
            return mapper.writeValueAsString(values == null ? List.of() : values);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "授权集合序列化失败");
        }
    }
}
