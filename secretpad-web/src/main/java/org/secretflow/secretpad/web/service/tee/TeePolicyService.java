/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
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
 * <p>规则来源必须是一份已完成的沙箱审批，由 {@link TeeApprovalPolicySource} 核对；
 * 登记到中心密钥服务后由其在放行时强制执行。
 * 列与算子精确匹配、不支持通配符、空集合即禁止——这三条底座不校验，必须在此拦住。
 */
@Service
public class TeePolicyService {

    private final TeePolicyRepository policies;
    private final TeeAssetRepository assets;
    private final TeeKeyService keyService;
    private final TeeApprovalPolicySource approvals;
    private final KeyAdapterClient adapter;
    private final TeeIdentityRegistry registry;
    private final TeeIdempotency idempotency;
    private final ObjectMapper mapper;

    public TeePolicyService(TeePolicyRepository policies, TeeKeyService keyService,
                            TeeApprovalPolicySource approvals, KeyAdapterClient adapter,
                            TeeIdentityRegistry registry, TeeIdempotency idempotency, ObjectMapper mapper,
                            TeeAssetRepository assets) {
        this.policies = policies;
        this.assets = assets;
        this.keyService = keyService;
        this.approvals = approvals;
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
        // 契约要求规则由有效审批生成：列、算子与有效期都不得超出沙箱审批和挂载管控批准的范围。
        TeeApprovalPolicySource.Approved approved =
                approvals.requireApproved(ownerId, sandboxId, assetId, columns, operators, expiresAt);

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
                    .approvalId(approved.approvalId())
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

    /** 自动登记策略才随数据期限更新；人工指定期限和模型 API 的短期策略保留各自契约。 */
    static boolean followsDataDeadline(TeePolicyDO policy) {
        String expected = "pl-" + TeeCrypto.sha256Hex((policy.getAssetId() + "|" + policy.getSandboxId())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 12);
        return expected.equals(policy.getUpk().getPolicyId())
                && policy.getApprovalId() != null && !policy.getApprovalId().isBlank();
    }

    /**
     * 在当前审批与供数方期限内生成新版本，原版本保留供已签名任务审计。
     * 这里只改变平台检查的截止时间；密钥服务中的 scope、列和算子保持一致，无需重建其规则。
     */
    @Transactional
    public synchronized TeePolicyDO refreshForAsset(TeeAssetDO input, String sandboxId) {
        TeeAssetDO asset = assets.findById(input.getUpk()).orElseThrow(
                () -> TeeException.of(TeeContract.Error.POLICY_DENIED, "密文资产已失效"));
        TeePolicyDO policy = policyForSandbox(asset, sandboxId);
        if (!asset.getUpk().getAssetId().equals(policy.getAssetId())
                || !asset.getUpk().getAssetVersion().equals(policy.getAssetVersion())
                || !asset.getOwnerId().equals(policy.getOwnerId())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则与密文资产绑定不符");
        }
        if (!sandboxId.equals(policy.getSandboxId())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "密文资产的授权规则未覆盖当前沙箱");
        }
        if (!followsDataDeadline(policy) || !TeeContract.STATE_ACTIVE.equals(policy.getState())) {
            return policy;
        }
        TeeApprovalPolicySource.Approved approved = approvals.approvedScope(policy.getOwnerId(),
                sandboxId, policy.getAssetId(), columns(policy), read(policy.getOperatorsJson()));
        if (approved.expiresAt().equals(Instant.parse(policy.getExpiresAt()))) {
            return policy;
        }
        TeeKeyDO key = keyService.require(asset.getKeyId(), asset.getKeyVersion());
        keyService.requireActive(key);
        TeeGuard.requireOwner(key.getOwnerId(), policy.getOwnerId());
        String version = nextVersion(policy.getAssetId(), policy.getAssetVersion());
        TeePolicyDO refreshed = TeePolicyDO.builder()
                .upk(new TeePolicyDO.UPK(policy.getUpk().getPolicyId(), version))
                .assetId(policy.getAssetId()).assetVersion(policy.getAssetVersion())
                .ownerId(policy.getOwnerId()).sandboxId(sandboxId).approvalId(approved.approvalId())
                .columnsJson(policy.getColumnsJson()).operatorsJson(policy.getOperatorsJson())
                .reportKindsJson(policy.getReportKindsJson()).expiresAt(approved.expiresAt().toString())
                .state(TeeContract.STATE_ACTIVE).build();
        policies.save(refreshed);
        // 资产可同时供多个沙箱使用，期限刷新不能改写另一个沙箱的默认策略指针。
        if (policy.getUpk().getPolicyId().equals(asset.getPolicyId())) {
            asset.setPolicyVersion(version);
            assets.save(asset);
        }
        return refreshed;
    }

    /** 按沙箱选择该资产的最新策略，避免后挂载沙箱覆盖原沙箱的授权入口。 */
    private TeePolicyDO policyForSandbox(TeeAssetDO asset, String sandboxId) {
        TeePolicyDO pointed = require(asset.getPolicyId(), asset.getPolicyVersion());
        return policies.findByAssetIdAndAssetVersion(asset.getUpk().getAssetId(),
                        asset.getUpk().getAssetVersion()).stream()
                .filter(policy -> sandboxId.equals(policy.getSandboxId()))
                .filter(policy -> asset.getOwnerId().equals(policy.getOwnerId()))
                .filter(policy -> sandboxId.equals(pointed.getSandboxId())
                        ? pointed.getUpk().getPolicyId().equals(policy.getUpk().getPolicyId())
                        : followsDataDeadline(policy))
                .max(java.util.Comparator.comparingLong(policy ->
                        Long.parseLong(policy.getUpk().getPolicyVersion())))
                .orElseGet(() -> {
                    if (sandboxId.equals(pointed.getSandboxId())) return pointed;
                    throw TeeException.of(TeeContract.Error.POLICY_DENIED, "密文资产的授权规则未覆盖当前沙箱");
                });
    }

    /** 历史结果保留原训练版本，当前授权须覆盖历史范围，审批单更新不改变结果绑定。 */
    @Transactional
    public TeePolicyDO resultSourcePolicy(String policyId, String version) {
        TeePolicyDO original = require(policyId, version);
        if (!TeeContract.STATE_ACTIVE.equals(original.getState())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "结果来源的原授权已失效");
        }
        if (!followsDataDeadline(original)) return original;
        TeeAssetDO asset = assets.findById(new TeeAssetDO.UPK(original.getAssetId(), original.getAssetVersion()))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.POLICY_DENIED, "结果来源数据已失效"));
        TeePolicyDO current = policyForSandbox(asset, original.getSandboxId());
        requireCoveredResultScope(original, current);
        current = refreshForAsset(asset, original.getSandboxId());
        requireCoveredResultScope(original, current);
        return current;
    }

    private void requireCoveredResultScope(TeePolicyDO original, TeePolicyDO current) {
        if (!TeeContract.STATE_ACTIVE.equals(current.getState())
                || !original.getUpk().getPolicyId().equals(current.getUpk().getPolicyId())
                || !java.util.Objects.equals(original.getAssetId(), current.getAssetId())
                || !java.util.Objects.equals(original.getAssetVersion(), current.getAssetVersion())
                || !java.util.Objects.equals(original.getOwnerId(), current.getOwnerId())
                || !java.util.Objects.equals(original.getSandboxId(), current.getSandboxId())
                || !new java.util.HashSet<>(read(current.getColumnsJson())).containsAll(read(original.getColumnsJson()))
                || !new java.util.HashSet<>(read(current.getOperatorsJson())).containsAll(read(original.getOperatorsJson()))
                || !new java.util.HashSet<>(read(current.getReportKindsJson())).containsAll(read(original.getReportKindsJson()))) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "当前授权未覆盖结果来源范围，不能沿用历史结果授权");
        }
    }

    /** 放行前复核规则状态、有效期与列范围；任一不满足即拒绝，不降级为粗粒度授权。 */
    public void requireAllows(TeePolicyDO policy, List<String> columns, String operator) {
        if (!TeeContract.STATE_ACTIVE.equals(policy.getState())) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则已失效");
        }
        if (followsDataDeadline(policy)) {
            // 旧任务仍绑定旧策略版本；期限缩短、挂载解除或停止使用后，必须按最新管控立即拒绝。
            approvals.resolveApproved(policy.getOwnerId(), policy.getSandboxId(), policy.getAssetId(),
                    columns, List.of(TeeGuard.requireText(operator, "operatorId")));
        }
        if (!Instant.now().isBefore(Instant.parse(policy.getExpiresAt()))) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                    "数据计算授权已到期，请核对数据使用截止时间");
        }
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
