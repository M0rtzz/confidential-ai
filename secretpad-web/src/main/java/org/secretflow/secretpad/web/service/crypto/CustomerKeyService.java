/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 客户密钥（UEK）全生命周期。
 *
 * <p>私钥只存在于浏览器 IndexedDB，本服务只操作公钥、版本与状态：生成与分发沿用既有
 * 身份注册路径，本类补齐轮换、回收与销毁三段，以及轮换期间的历史信封重封装落库。
 *
 * <p>状态语义：{@code ACTIVE} 生效；{@code SUPERSEDED} 被新版本取代，历史信封仍可解开；
 * {@code REVOKED} 已回收，不再接受新的封装；{@code DESTROYED} 已销毁，浏览器私钥同时清除，
 * 该版本覆盖的历史密文自此不可解。四种状态单向推进，不回退。
 */
@Service
public class CustomerKeyService {

    private static final String ACTIVE = "ACTIVE";
    private static final String SUPERSEDED = "SUPERSEDED";
    private static final String REVOKED = "REVOKED";
    private static final String DESTROYED = "DESTROYED";

    private final JdbcTemplate jdbc;
    private final ConfidentialComputeService compute;
    private final ConfidentialMetadataStore store;
    private final ObjectMapper mapper;

    public CustomerKeyService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ConfidentialComputeService compute,
                              ConfidentialMetadataStore store, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.compute = compute;
        this.store = store;
        this.mapper = mapper;
    }

    public record RotateRequest(String kid, String encryptionPublicKey, String signingPublicKey,
                                String proofOfPossession) {
    }

    /**
     * 轮换后的历史资产归属。
     *
     * <p>{@code boundToActive} 是已绑定当前公钥的资产版本数，{@code boundToPrevious} 是仍绑定
     * 旧公钥、必须用旧密钥备份才能解开的资产版本。
     */
    public record RotationStatus(String activeKid, int activeVersion, long total, long boundToActive,
                                 List<String> boundToPrevious) {
    }

    /* --------------------------------- 查询 --------------------------------- */

    public List<Map<String, Object>> list(String ownerId) {
        return jdbc.queryForList("select kid,subject_id,algorithm,key_version,fingerprint,status,"
                + "created_at,revoked_at,superseded_at,destroyed_at,rotated_from_kid"
                + " from ds_customer_encryption_key where tenant_id=? order by key_version desc", ownerId)
                .stream().map(CustomerKeyService::camelKeys).toList();
    }

    /**
     * 轮换后的历史资产归属。
     *
     * <p>资产版本的 DEK 信封在封装时把接收公钥标识写进了 AAD，并随 manifest 一同由属主签名，
     * 因此换一把公钥重新封装会改变 manifest 摘要与签名，不是换个信封那么简单。
     * 本方法只如实给出哪些资产版本仍绑定旧公钥，提示持有人保留对应的密钥备份，
     * 不提供自动重封装。
     */
    public RotationStatus rotationStatus(String ownerId) {
        Map<String, Object> active = activeKey(ownerId);
        if (active == null) {
            return new RotationStatus(null, 0, 0, 0, List.of());
        }
        String kid = String.valueOf(active.get("kid"));
        List<String> all = jdbc.queryForList(
                "select asset_version_id from ds_crypto_asset_version where owner_id=?", String.class, ownerId);
        List<String> bound = jdbc.queryForList(
                "select distinct asset_version_id from ds_crypto_key_envelope where recipient_kid=?",
                String.class, kid);
        List<String> previous = new ArrayList<>(all);
        previous.removeAll(bound);
        return new RotationStatus(kid, ((Number) active.get("key_version")).intValue(),
                all.size(), all.size() - previous.size(), previous);
    }

    /* --------------------------------- 变更 --------------------------------- */

    /**
     * 轮换：登记新版本公钥，旧的生效版本转为 {@code SUPERSEDED}。
     *
     * <p>旧版本不作废——历史资产的 DEK 仍按旧公钥封装，作废会立即丢失历史密文。
     * 轮换后新资产用新公钥，历史资产仍需旧密钥备份才能解开，
     * 因此回收旧版本必须由持有人在确认不再需要历史密文后单独执行。
     */
    @Transactional
    public Map<String, Object> rotate(String ownerId, RotateRequest request) {
        Map<String, Object> previous = activeKey(ownerId);
        String previousKid = previous == null ? null : String.valueOf(previous.get("kid"));
        if (previousKid != null && previousKid.equals(request.kid())) {
            throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT, "新密钥标识与当前生效版本相同");
        }
        // 复用既有注册路径：签名校验、kid 冲突判定与公钥落库的规则保持一处。
        compute.registerIdentity(ownerId, new ConfidentialComputeService.IdentityRequest(
                request.kid(), request.encryptionPublicKey(), request.signingPublicKey(),
                request.proofOfPossession()));
        String now = Instant.now().toString();
        if (previousKid != null) {
            jdbc.update("update ds_customer_encryption_key set status=?,superseded_at=?"
                    + " where tenant_id=? and status=? and kid<>?", SUPERSEDED, now, ownerId, ACTIVE, request.kid());
        }
        jdbc.update("update ds_customer_encryption_key set rotated_from_kid=? where kid=?", previousKid, request.kid());
        store.audit(ownerId, "CUSTOMER_KEY_ROTATED", request.kid(), mapper.valueToTree(
                Map.of("fromKid", previousKid == null ? "" : previousKid, "toKid", request.kid())));
        return Map.of("kid", request.kid(), "status", ACTIVE,
                "rotatedFromKid", previousKid == null ? "" : previousKid);
    }

    /** 回收：停用某个公钥版本，历史信封保留，不再接受新的封装。 */
    @Transactional
    public Map<String, Object> revoke(String ownerId, String kid) {
        Map<String, Object> row = requireOwnKey(ownerId, kid);
        String status = String.valueOf(row.get("status"));
        if (DESTROYED.equals(status)) {
            throw TeeException.of(TeeContract.Error.KEY_REVOKED, "该版本已销毁，不能再回收");
        }
        if (REVOKED.equals(status)) {
            return Map.of("kid", kid, "status", REVOKED, "changed", false);
        }
        String now = Instant.now().toString();
        jdbc.update("update ds_customer_encryption_key set status=?,revoked_at=? where kid=?", REVOKED, now, kid);
        // 封装校验走 ds_crypto_identity，两张表必须同时停用，否则回收不生效。
        jdbc.update("update ds_crypto_identity set status=?,revoked_at=? where kid=?", REVOKED, now, kid);
        jdbc.update("update ds_crypto_signing_identity set status=?,revoked_at=? where kid=?", REVOKED, now, kid);
        store.audit(ownerId, "CUSTOMER_KEY_REVOKED", kid, mapper.valueToTree(Map.of("kid", kid)));
        return Map.of("kid", kid, "status", REVOKED, "changed", true);
    }

    /**
     * 销毁：不可逆。
     *
     * <p>服务端只把记录置为 {@code DESTROYED}，浏览器私钥由前端同时清除。
     * 要求调用方回填 kid 作为二次确认，避免误操作把历史密文变成永久不可解。
     */
    @Transactional
    public Map<String, Object> destroy(String ownerId, String kid, String confirmKid) {
        if (!kid.equals(confirmKid)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "确认输入的密钥标识与目标不一致");
        }
        Map<String, Object> row = requireOwnKey(ownerId, kid);
        if (DESTROYED.equals(String.valueOf(row.get("status")))) {
            return Map.of("kid", kid, "status", DESTROYED, "changed", false);
        }
        String now = Instant.now().toString();
        jdbc.update("update ds_customer_encryption_key set status=?,destroyed_at=?,"
                + "revoked_at=coalesce(revoked_at,?) where kid=?", DESTROYED, now, now, kid);
        jdbc.update("update ds_crypto_identity set status=?,revoked_at=coalesce(revoked_at,?) where kid=?",
                DESTROYED, now, kid);
        jdbc.update("update ds_crypto_signing_identity set status=?,revoked_at=coalesce(revoked_at,?) where kid=?",
                DESTROYED, now, kid);
        store.audit(ownerId, "CUSTOMER_KEY_DESTROYED", kid, mapper.valueToTree(Map.of("kid", kid)));
        return Map.of("kid", kid, "status", DESTROYED, "changed", true);
    }

    /* --------------------------------- 工具 --------------------------------- */

    private Map<String, Object> activeKey(String ownerId) {
        List<Map<String, Object>> rows = jdbc.queryForList("select kid,key_version from ds_customer_encryption_key"
                + " where tenant_id=? and status=? order by key_version desc", ownerId, ACTIVE);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /** 只有密钥持有人可以变更自己的密钥；管理员没有代持有人操作的通道。 */
    private Map<String, Object> requireOwnKey(String ownerId, String kid) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select kid,status from ds_customer_encryption_key where kid=? and tenant_id=?", kid, ownerId);
        if (rows.size() != 1) {
            throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "密钥不存在或不属于当前机构");
        }
        return rows.get(0);
    }

    private static Map<String, Object> camelKeys(Map<String, Object> row) {
        Map<String, Object> result = new LinkedHashMap<>();
        row.forEach((column, value) -> {
            StringBuilder builder = new StringBuilder(column.length());
            boolean upper = false;
            for (char item : column.toCharArray()) {
                if (item == '_') {
                    upper = true;
                    continue;
                }
                builder.append(upper ? Character.toUpperCase(item) : Character.toLowerCase(item));
                upper = false;
            }
            result.put(builder.toString(), value);
        });
        return result;
    }
}
