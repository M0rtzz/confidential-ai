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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 把画布节点的密文中间产物登记成可再次作为输入的派生密文资产。
 *
 * <p>可信执行的算子产物是密文对象，不落明文中间表。若只留对象，下游节点就只能跟着上游一起整图跑。
 * 这里为中间产物登记一条派生资产与配套策略：授权列、算子与到期时间原样继承上游输入的策略，
 * 因此派生资产的可用范围不会超出供数方当初批准的范围，中游节点也就能单独重跑。</p>
 *
 * <p>明文大小取密文长度作为上界。该字段在运行时只用于累计任务的明文预算上限，
 * 用密文长度是偏保守的一侧，不会放宽限制。</p>
 */
@Service
public class TeeIntermediateAssets {

    private static final Logger log = LoggerFactory.getLogger(TeeIntermediateAssets.class);

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final TeeObjectStore store;
    private final TeeKeyGateway keyGateway;

    public TeeIntermediateAssets(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                                 TeeObjectStore store, TeeKeyGateway keyGateway) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.store = store;
        this.keyGateway = keyGateway;
    }

    /**
     * 登记一次节点产出。
     *
     * @param derivedAssetId 派生资产标识，按运行与节点推导，重跑同一节点即覆盖同一条
     * @param sandboxId      所属沙箱
     * @param sourceAssetId  上游输入资产，用于继承授权策略
     * @param objectId       本次产出的密文对象
     * @return 登记成功返回 true；缺少任一前置条件时返回 false，调用方据此退回整图运行
     */
    public boolean register(String derivedAssetId, String sandboxId, String sourceAssetId, String objectId) {
        if (isBlank(derivedAssetId) || isBlank(sandboxId) || isBlank(sourceAssetId) || isBlank(objectId)) {
            return false;
        }
        try {
            Map<String, Object> policy = sourcePolicy(sourceAssetId);
            if (policy == null) {
                log.info("上游资产 {} 没有可继承的授权策略，跳过中间产物登记", sourceAssetId);
                return false;
            }
            Map<String, Object> object = single(
                    "select owner_id,key_id,key_version,size_bytes from tee_object where object_id=? and is_deleted=0",
                    objectId);
            if (object == null) {
                log.info("密文对象 {} 不存在，跳过中间产物登记", objectId);
                return false;
            }
            String owner = text(object.get("owner_id"));
            List<String> columns = values(text(policy.get("columns_json")));
            List<String> operators = values(text(policy.get("operators_json")));
            List<String> reportKinds = values(text(policy.get("report_kinds_json")));
            if (columns.isEmpty() || operators.isEmpty()) {
                log.info("上游策略 {} 未批准列或算子，跳过中间产物登记", policy.get("policy_id"));
                return false;
            }
            String digest = derivedAssetId.replaceAll("[^0-9a-zA-Z]", "");
            String policyId = "pl-mid-" + digest.substring(Math.max(0, digest.length() - 12));
            TeePolicyService.RegisterResult registered = keyGateway.registerPolicy(owner,
                    new TeePolicyService.RegisterRequest(TeeContract.VERSION, "polmid-" + digest,
                            new TeePolicyService.Policy(TeeContract.VERSION, policyId, "1", derivedAssetId,
                                    "1", owner, sandboxId, columns, operators,
                                    text(policy.get("expires_at")), reportKinds)));
            TeeCrypto.EncryptedObject ciphertext = store.read(objectId);
            keyGateway.registerAsset(owner, new TeeAssetService.RegisterRequest(TeeContract.VERSION,
                    "astmid-" + digest, owner, columns, ciphertext,
                    registered.policyId(), registered.policyVersion()));
            recordPlaintextBudget(derivedAssetId, object.get("size_bytes"), columns);
            log.info("中间产物已登记为派生密文资产 {}，继承策略 {}", derivedAssetId, policy.get("policy_id"));
            return true;
        } catch (RuntimeException failure) {
            log.warn("中间产物登记失败 asset={} object={}: {}", derivedAssetId, objectId, failure.getMessage());
            return false;
        }
    }

    /** 记录派生资产的明文预算与表结构，供任务派发时读取，不含任何明文数据行。 */
    private void recordPlaintextBudget(String assetId, Object ciphertextBytes, List<String> columns) {
        long bytes = ciphertextBytes instanceof Number number ? number.longValue() : 0L;
        Map<String, Object> metadata = Map.of("encrypted", Boolean.TRUE,
                "derived", Boolean.TRUE,
                "plaintextBytes", Math.max(bytes, 1L),
                "columns", columns);
        String now = java.time.LocalDateTime.now().toString();
        int changed = jdbc.update("update ds_data_asset set metadata_json=?,updated_at=? where id=?",
                json(metadata), now, assetId);
        if (changed == 0) {
            jdbc.update("insert into ds_data_asset(id,name,provider_node_id,processor_node_id,ingestion_type,"
                            + "modality,data_stage,source_asset_id,datatable_id,storage_uri,metadata_json,"
                            + "created_by,created_at,updated_at,version,status,deleted) "
                            + "values(?,?,?,?,'DERIVED','TABULAR','PROCESSED','',?,'',?,'system',?,?,1,'ACTIVE',0)",
                    assetId, "画布中间产物 " + assetId, localNodeId(), localNodeId(), assetId,
                    json(metadata), now, now);
        }
    }

    private String localNodeId() {
        Map<String, Object> row = single("select node_id from node where is_deleted=0 order by id limit 1");
        return row == null ? "" : text(row.get("node_id"));
    }

    private Map<String, Object> sourcePolicy(String sourceAssetId) {
        Map<String, Object> asset = single(
                "select policy_id,policy_version from tee_asset where asset_id=? and is_deleted=0 "
                        + "order by asset_version desc limit 1", sourceAssetId);
        if (asset == null) {
            return null;
        }
        return single("select policy_id,columns_json,operators_json,report_kinds_json,expires_at "
                        + "from tee_policy where policy_id=? and policy_version=? and is_deleted=0 limit 1",
                text(asset.get("policy_id")), text(asset.get("policy_version")));
    }

    private Map<String, Object> single(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private List<String> values(String json) {
        List<String> result = new ArrayList<>();
        try {
            JsonNode node = mapper.readTree(json == null || json.isBlank() ? "[]" : json);
            node.forEach(item -> {
                String text = item.asText("");
                if (!text.isBlank()) {
                    result.add(text);
                }
            });
        } catch (Exception ignored) {
            // 策略字段损坏时按空处理，调用方会退回整图运行
        }
        return result;
    }

    private String json(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception failure) {
            return "{}";
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
