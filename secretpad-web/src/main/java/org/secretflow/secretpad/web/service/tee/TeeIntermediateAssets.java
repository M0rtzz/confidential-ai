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
 * 这里为中间产物登记一条派生资产与配套策略：授权算子与到期时间原样继承上游输入的策略，授权列取
 * 本次产出的表结构（由算子语义推导），其中来自上游的列仍受上游批准范围约束，新增列是批准范围内
 * 的计算结果。派生资产的可用范围因此不会超出供数方当初批准的范围，中游节点也就能单独重跑。</p>
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
     * <p>派生资产标识取密文结果对象自身的资产标识（运行时申领的 {@code resultId}），与密文封装
     * 内绑定的标识保持一致，否则策略登记在一个标识上、资产登记在另一个标识上，下游按表名解析
     * 时找不到已登记的资产。</p>
     *
     * @param sandboxId      所属沙箱
     * @param sourceAssetId  上游输入资产，用于继承授权策略
     * @param objectId       本次产出的密文对象
     * @param outputColumns  本次产出的表结构列，由算子语义推导，不含任何明文数据
     * @return 登记成功返回派生资产标识；缺少任一前置条件时返回空串，调用方据此保留原有行为
     */
    public String register(String sandboxId, String sourceAssetId, String objectId, List<String> outputColumns) {
        if (isBlank(sandboxId) || isBlank(sourceAssetId) || isBlank(objectId)
                || outputColumns == null || outputColumns.isEmpty()) {
            return "";
        }
        String derivedAssetId = "";
        try {
            Map<String, Object> policy = sourcePolicy(sourceAssetId, sandboxId);
            if (policy == null) {
                log.info("上游资产 {} 没有可继承的授权策略，跳过中间产物登记", sourceAssetId);
                return "";
            }
            Map<String, Object> object = single(
                    "select owner_id,key_id,key_version,size_bytes from tee_object where object_id=? and is_deleted=0",
                    objectId);
            if (object == null) {
                log.info("密文对象 {} 不存在，跳过中间产物登记", objectId);
                return "";
            }
            String owner = text(object.get("owner_id"));
            List<String> operators = values(text(policy.get("operators_json")));
            List<String> reportKinds = values(text(policy.get("report_kinds_json")));
            if (operators.isEmpty()) {
                log.info("上游策略 {} 未批准任何算子，跳过中间产物登记", policy.get("policy_id"));
                return "";
            }
            TeeCrypto.EncryptedObject ciphertext = store.read(objectId);
            derivedAssetId = ciphertext.assetId();
            if (isBlank(derivedAssetId)) {
                log.info("密文对象 {} 未绑定资产标识，跳过中间产物登记", objectId);
                return "";
            }
            List<String> columns = List.copyOf(new java.util.LinkedHashSet<>(outputColumns));
            // 授权继承要读派生资产的上游与表结构，元数据必须先落库，策略登记才能核出批准范围。
            recordPlaintextBudget(derivedAssetId, sourceAssetId, object.get("size_bytes"), columns);
            // 策略标识沿用「资产 + 沙箱」的既定推导，使其随供数方期限与挂载管控一并复核。
            String policyId = "pl-" + TeeCrypto.sha256Hex((derivedAssetId + "|" + sandboxId)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 12);
            String digest = derivedAssetId.replaceAll("[^0-9a-zA-Z]", "");
            TeePolicyService.RegisterResult registered = keyGateway.registerPolicy(owner,
                    new TeePolicyService.RegisterRequest(TeeContract.VERSION, "polmid-" + digest,
                            new TeePolicyService.Policy(TeeContract.VERSION, policyId, "1", derivedAssetId,
                                    ciphertext.assetVersion(), owner, sandboxId, columns, operators,
                                    text(policy.get("expires_at")), reportKinds)));
            keyGateway.registerAsset(owner, new TeeAssetService.RegisterRequest(TeeContract.VERSION,
                    "astmid-" + digest, owner, columns, ciphertext,
                    registered.policyId(), registered.policyVersion()));
            log.info("中间产物已登记为派生密文资产 {}，继承策略 {}", derivedAssetId, policy.get("policy_id"));
            return derivedAssetId;
        } catch (RuntimeException failure) {
            log.warn("中间产物登记失败 asset={} object={}: {}", derivedAssetId, objectId, failure.getMessage());
            return "";
        }
    }

    /** 记录派生资产的上游、明文预算与表结构，供授权继承与任务派发读取，不含任何明文数据行。 */
    private void recordPlaintextBudget(String assetId, String sourceAssetId, Object ciphertextBytes,
                                       List<String> columns) {
        long bytes = ciphertextBytes instanceof Number number ? number.longValue() : 0L;
        Map<String, Object> metadata = Map.of("encrypted", Boolean.TRUE,
                "derived", Boolean.TRUE,
                "plaintextBytes", Math.max(bytes, 1L),
                "columns", columns);
        String now = java.time.LocalDateTime.now().toString();
        int changed = jdbc.update(
                "update ds_data_asset set metadata_json=?,source_asset_id=?,updated_at=? where id=?",
                json(metadata), sourceAssetId, now, assetId);
        if (changed == 0) {
            jdbc.update("insert into ds_data_asset(id,name,provider_node_id,processor_node_id,ingestion_type,"
                            + "modality,data_stage,source_asset_id,datatable_id,storage_uri,metadata_json,"
                            + "created_by,created_at,updated_at,version,status,deleted) "
                            + "values(?,?,?,?,'DERIVED','TABULAR','PROCESSED',?,?,'',?,'system',?,?,1,'ACTIVE',0)",
                    assetId, "画布中间产物 " + assetId, localNodeId(), localNodeId(), sourceAssetId, assetId,
                    json(metadata), now, now);
        }
    }

    private String localNodeId() {
        Map<String, Object> row = single("select node_id from node where is_deleted=0 order by id limit 1");
        return row == null ? "" : text(row.get("node_id"));
    }

    /**
     * 上游资产在本沙箱的最新生效策略。
     *
     * <p>{@code tee_asset} 上的策略指针是该资产的默认策略，同一资产供多个沙箱使用时它可能指向
     * 另一个沙箱，因此按「资产 + 沙箱」取最新版本，与 {@code TeePolicyService} 的选取口径一致。</p>
     */
    private Map<String, Object> sourcePolicy(String sourceAssetId, String sandboxId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select policy_id,policy_version,columns_json,operators_json,report_kinds_json,expires_at "
                        + "from tee_policy where asset_id=? and sandbox_id=? and state='ACTIVE' and is_deleted=0",
                sourceAssetId, sandboxId);
        return rows.stream()
                .max(java.util.Comparator.comparingLong(row -> parseVersion(text(row.get("policy_version")))))
                .orElse(null);
    }

    private static long parseVersion(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException notNumeric) {
            return 0L;
        }
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
