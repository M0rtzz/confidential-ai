/*
 * Copyright 2026 Ant Group Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 */
package org.secretflow.secretpad.web.service.tee;

import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.secretflow.secretpad.web.service.sandbox.TeeAssetRegistrar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 供数方在投出同意票时登记本方密文资产。
 *
 * <p>抽样脱敏产出只是加密落盘：密钥已在台账、密文已在对象存储，但还不是契约意义上的密文资产。
 * 这里按审批单批准的列、算子与期限先登记授权策略，再登记密文资产；可信运行时凭这两条记录
 * 校验授权并申领密钥。只处理本方作为供数方的资产，他方数据一律跳过。</p>
 */
@Service
public class TeeAssetRegistrarImpl implements TeeAssetRegistrar {

    private static final Logger log = LoggerFactory.getLogger(TeeAssetRegistrarImpl.class);
    private static final Set<String> MOUNT_TYPES = Set.of("CREATE", "DATA_CHANGE");
    private static final ZoneId PLATFORM_ZONE = ZoneId.of("Asia/Shanghai");

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final MinioAssetStorage storage;
    private final TeeKeyGateway keyGateway;

    public TeeAssetRegistrarImpl(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                                 MinioAssetStorage storage, TeeKeyGateway keyGateway) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.storage = storage;
        this.keyGateway = keyGateway;
    }

    @Override
    public void registerApproved(Map<String, Object> approval) {
        String type = text(approval.get("approval_type"));
        if (!MOUNT_TYPES.contains(type)) {
            return;
        }
        String sandboxId = text(approval.get("sandbox_id"));
        JsonNode payload = payload(approval.get("payload_json"));
        List<String> operators = values(payload.path("teeOperators"));
        if (operators.isEmpty()) {
            log.info("申请单 {} 未批准任何可信计算算子，跳过密文资产登记", approval.get("id"));
            return;
        }
        String expiresAt = expiry(payload, sandboxId);
        for (String assetId : values(payload.path("datasetAssetIds"))) {
            try {
                registerOne(assetId, sandboxId, payload, operators, expiresAt);
            } catch (RuntimeException failure) {
                log.warn("密文资产 {} 登记失败: {}", assetId, failure.getMessage());
            }
        }
    }

    private void registerOne(String assetId, String sandboxId, JsonNode payload,
                             List<String> operators, String expiresAt) {
        Map<String, Object> asset = single(
                "select storage_uri,metadata_json,provider_node_id from ds_data_asset where id=? and deleted=0",
                assetId);
        if (asset == null) {
            return; // 他方数据由对方自行登记
        }
        JsonNode metadata = payload(asset.get("metadata_json"));
        if (!metadata.path("encrypted").asBoolean(false)) {
            log.info("资产 {} 未加密落盘，不作为密文资产登记", assetId);
            return;
        }
        TeeCrypto.EncryptedObject object = readCiphertext(text(asset.get("storage_uri")));
        if (object == null) {
            return;
        }
        List<String> schema = columns(assetId, metadata);
        if (schema.isEmpty()) {
            log.info("资产 {} 缺少表结构，跳过密文资产登记", assetId);
            return;
        }
        List<String> granted = values(payload.path("teeColumns"));
        if (granted.isEmpty()) {
            granted = schema;
        }
        String owner = ownerOf(text(asset.get("provider_node_id")));
        if (owner.isBlank()) {
            log.info("资产 {} 的供数节点没有对应机构，跳过密文资产登记", assetId);
            return;
        }
        // 标识按资产与沙箱推导，重复登记复用同一条策略与同一次幂等请求，不会越登越多
        String digest = digest(assetId + "|" + sandboxId);
        TeePolicyService.RegisterResult policy = keyGateway.registerPolicy(owner,
                new TeePolicyService.RegisterRequest(TeeContract.VERSION, "pol-" + digest,
                        new TeePolicyService.Policy(TeeContract.VERSION, "pl-" + digest, "1", assetId,
                                object.assetVersion(), owner, sandboxId, granted, operators, expiresAt,
                                List.of("EVALUATION_METRICS"))));
        keyGateway.registerAsset(owner, new TeeAssetService.RegisterRequest(TeeContract.VERSION,
                "ast-" + digest, owner, schema, object,
                policy.policyId(), policy.policyVersion()));
        log.info("密文资产 {} 已按审批登记，沙箱 {}，授权算子 {}", assetId, sandboxId, operators);
    }

    /** 授权期限：审批单显式给出的优先，否则取沙箱到期时间，都没有则给一天。 */
    private String expiry(JsonNode payload, String sandboxId) {
        String declared = payload.path("teeExpiresAt").asText("");
        if (!declared.isBlank()) {
            return declared;
        }
        Map<String, Object> sandbox = single("select expires_at from ds_sandbox where id=? and deleted=0", sandboxId);
        String sandboxExpiry = sandbox == null ? "" : text(sandbox.get("expires_at"));
        Instant deadline = Instant.now().plus(1, ChronoUnit.DAYS);
        if (!sandboxExpiry.isBlank()) {
            try {
                deadline = LocalDateTime.parse(sandboxExpiry).atZone(PLATFORM_ZONE).toInstant();
            } catch (RuntimeException notLocal) {
                log.debug("沙箱 {} 到期时间无法解析: {}", sandboxId, sandboxExpiry);
            }
        }
        return deadline.toString();
    }

    private TeeCrypto.EncryptedObject readCiphertext(String uri) {
        if (uri == null || uri.isBlank()) {
            return null;
        }
        try (InputStream in = storage.open(uri)) {
            TeeCrypto.EncryptedObject object =
                    mapper.readValue(in.readAllBytes(), TeeCrypto.EncryptedObject.class);
            return TeeContract.VERSION.equals(object.contractVersion()) ? object : null;
        } catch (Exception notCiphertext) {
            log.info("存储对象 {} 不是本契约的密文封装，跳过登记", uri);
            return null;
        }
    }

    /** 表结构列：优先取节点权威库登记的列，回退到元数据里的列。 */
    private List<String> columns(String assetId, JsonNode metadata) {
        Map<String, Object> dataset = single(
                "select table_columns_json from ds_node_dataset where asset_id=? and deleted=0 "
                        + "order by updated_at desc limit 1", assetId);
        if (dataset != null) {
            List<String> fromStore = values(payload(dataset.get("table_columns_json")));
            if (!fromStore.isEmpty()) {
                return fromStore;
            }
        }
        return values(metadata.path("columns"));
    }

    /**
     * 供数节点所属机构。登记多在后台线程触发（申请单完成、快照合并），
     * 此时没有登录态，机构标识只能由资产自身的归属推导。
     */
    private String ownerOf(String providerNodeId) {
        if (providerNodeId.isBlank()) {
            return "";
        }
        Map<String, Object> node = single("select inst_id from node where node_id=? and is_deleted=0", providerNodeId);
        return node == null ? "" : text(node.get("inst_id"));
    }

    private static String digest(String value) {
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(hash).substring(0, 12);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private Map<String, Object> single(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private JsonNode payload(Object value) {
        try {
            return mapper.readTree(text(value).isBlank() ? "{}" : text(value));
        } catch (Exception invalid) {
            return mapper.createObjectNode();
        }
    }

    private static List<String> values(JsonNode node) {
        List<String> result = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(item -> {
                String text = item.asText("");
                if (!text.isBlank()) {
                    result.add(text);
                }
            });
        }
        return result;
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
