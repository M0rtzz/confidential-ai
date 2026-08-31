/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * 授权规则登记。
 *
 * <p>规则由有效审批生成，登记到中心密钥服务后由其在放行时强制执行。
 * 列与算子精确匹配、不支持通配符、空集合即禁止——这三条底座不校验，必须在此拦住。
 */
@Service
public class TeePolicyService {

    private final TeePolicyRepository policies;
    private final TeeKeyService keyService;
    private final KeyAdapterClient adapter;
    private final TeeIdentityRegistry registry;
    private final TeeIdempotency idempotency;
    private final ObjectMapper mapper;

    public TeePolicyService(TeePolicyRepository policies, TeeKeyService keyService, KeyAdapterClient adapter,
                            TeeIdentityRegistry registry, TeeIdempotency idempotency, ObjectMapper mapper) {
        this.policies = policies;
        this.keyService = keyService;
        this.adapter = adapter;
        this.registry = registry;
        this.idempotency = idempotency;
        this.mapper = mapper;
    }

    public record Policy(String contractVersion, String policyId, String policyVersion,
                         String assetId, String assetVersion, String ownerId, String sandboxId,
                         List<String> columns, List<String> operators, String expiresAt,
                         List<String> reportKinds) {
    }

    public record RegisterRequest(String contractVersion, String requestId, Policy policy) {
    }

    public record RegisterResult(String contractVersion, String policyId, String policyVersion, String state) {
    }

    @Transactional
    public RegisterResult register(String ownerId, RegisterRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        Policy policy = request.policy();
        if (policy == null) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "缺少 policy");
        }
        TeeGuard.requireVersion(policy.contractVersion());
        String assetId = TeeGuard.requireText(policy.assetId(), "assetId");
        String assetVersion = TeeGuard.requireText(policy.assetVersion(), "assetVersion");
        String sandboxId = TeeGuard.requireText(policy.sandboxId(), "sandboxId");
        TeeGuard.requireOwner(ownerId, TeeGuard.requireText(policy.ownerId(), "ownerId"));

        // 底座对空集合不作限制、把 '*' 当作放开全部，因此登记阶段必须先拒绝这两种写法。
        List<String> columns = TeeGuard.requireGrantSet(policy.columns(), "列");
        List<String> operators = TeeGuard.requireGrantSet(policy.operators(), "算子");
        TeeGuard.requireReportKinds(policy.reportKinds());
        Instant expiresAt = TeeGuard.requireInstant(policy.expiresAt(), "expiresAt");
        TeeGuard.requireNotExpired(expiresAt, TeeContract.Error.POLICY_DENIED, "授权有效期已过");

        String fingerprint = TeeIdempotency.fingerprint(List.of(assetId, assetVersion, sandboxId,
                String.join(",", columns), String.join(",", operators),
                String.join(",", policy.reportKinds()), expiresAt.toString()));
        return idempotency.execute(ownerId, "policies/register", requestId, fingerprint,
                RegisterResult.class, () -> {
            TeeKeyDO key = keyService.active(assetId, assetVersion).orElseThrow(
                    () -> TeeException.of(TeeContract.Error.KEY_REVOKED, "资产版本没有生效的数据密钥"));
            TeeGuard.requireOwner(key.getOwnerId(), ownerId);
            String policyId = Optional.ofNullable(policy.policyId()).filter(value -> !value.isBlank())
                    .orElse("pl-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
            String policyVersion = nextVersion(assetId, assetVersion);
            // 授权对象是可信运行时的工作负载身份；party id 由适配服务从证书推导，平台不复刻该规则。
            adapter.call("/v1/policies/register", Map.of(
                    "resourceUri", key.getResourceUri(),
                    "scope", policyId,
                    "rules", List.of(Map.of(
                            "granteeCertsB64", List.of(TeeCrypto.encode(
                                    registry.workloadCertificatePem().getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                            "columns", columns,
                            "operators", operators))));
            policies.save(TeePolicyDO.builder()
                    .upk(new TeePolicyDO.UPK(policyId, policyVersion))
                    .assetId(assetId).assetVersion(assetVersion).ownerId(ownerId).sandboxId(sandboxId)
                    .columnsJson(write(columns)).operatorsJson(write(operators))
                    .reportKindsJson(write(policy.reportKinds()))
                    .expiresAt(expiresAt.toString()).state(TeeContract.STATE_ACTIVE)
                    .build());
            return new RegisterResult(TeeContract.VERSION, policyId, policyVersion, TeeContract.STATE_ACTIVE);
        });
    }

    public TeePolicyDO require(String policyId, String policyVersion) {
        return policies.findById(new TeePolicyDO.UPK(policyId, policyVersion))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则不存在"));
    }

    /** 放行前复核规则状态、有效期与列范围；任一不满足即拒绝，不降级为粗粒度授权。 */
    public void requireAllows(TeePolicyDO policy, List<String> columns, String operator) {
        if (!TeeContract.STATE_ACTIVE.equals(policy.getState())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则已失效");
        }
        TeeGuard.requireNotExpired(Instant.parse(policy.getExpiresAt()),
                TeeContract.Error.POLICY_DENIED, "授权有效期已过");
        TeeGuard.requireSubset(columns, read(policy.getColumnsJson()), "列");
        TeeGuard.requireSubset(List.of(TeeGuard.requireText(operator, "operatorId")),
                read(policy.getOperatorsJson()), "算子");
    }

    public List<String> reportKinds(TeePolicyDO policy) {
        return read(policy.getReportKindsJson());
    }

    public List<String> columns(TeePolicyDO policy) {
        return read(policy.getColumnsJson());
    }

    private String nextVersion(String assetId, String assetVersion) {
        int max = policies.findByAssetIdAndAssetVersion(assetId, assetVersion).stream()
                .mapToInt(item -> Integer.parseInt(item.getUpk().getPolicyVersion())).max().orElse(0);
        return String.valueOf(max + 1);
    }

    private String write(List<String> values) {
        try {
            return mapper.writeValueAsString(values);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "授权集合序列化失败");
        }
    }

    private List<String> read(String json) {
        try {
            return mapper.readerForListOf(String.class).readValue(json);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "已登记的授权集合无法读取");
        }
    }
}
