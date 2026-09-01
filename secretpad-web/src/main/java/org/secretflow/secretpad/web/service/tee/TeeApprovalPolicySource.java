/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 授权规则的审批来源。
 *
 * <p>契约第四节要求 {@code /policies/register} 的规则「由有效审批生成」。本组件把沙箱审批与
 * 挂载管控翻译成契约 policy 的约束：授权列、算子与有效期都不得超出审批与管控已经批准的范围。
 * 校验失败一律 {@code POLICY_DENIED}，不降级为粗粒度授权，也不接受调用方自报的授权范围。
 *
 * <p>审批单的 {@code payload_json} 用两个字段承载可信计算授权：{@code teeColumns} 为授权列，
 * 缺省取资产已登记的表结构列；{@code teeOperators} 为授权算子，没有该字段即视为未批准任何算子。
 * 算子在平台原有模型中没有对应概念，只能由数据方在审批时明确列出，不推断、不默认放开。
 */
@Component
public class TeeApprovalPolicySource {

    /** 平台既有时间列写的是本地时间，与契约的 UTC RFC3339 并存，按同一时区约定解析。 */
    private static final ZoneId PLATFORM_ZONE = ZoneId.of("Asia/Shanghai");

    /** 只有这两类审批会挂载数据集，其余类型不产生数据授权。 */
    private static final Set<String> MOUNT_APPROVAL_TYPES = Set.of("CREATE", "DATA_CHANGE");

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final String nodeId;

    public TeeApprovalPolicySource(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                                   @Value("${secretpad.node-id:kuscia-system}") String nodeId) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.nodeId = nodeId;
    }

    /** 一次审批批准的可信计算授权范围。 */
    public record Approved(String approvalId, List<String> columns, List<String> operators, Instant expiresAt) {
    }

    /**
     * 校验规则确实由该机构一份有效审批产生，且未超出审批与管控批准的范围。
     *
     * @return 实际生效的授权范围，供调用方记录来源
     */
    public Approved requireApproved(String ownerId, String sandboxId, String assetId,
                                    List<String> columns, List<String> operators, Instant expiresAt) {
        Map<String, Object> sandbox = single(
                "select owner_id,expires_at from ds_sandbox where id=? and deleted=0", sandboxId);
        if (sandbox == null) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权规则引用的沙箱不存在");
        }
        String sandboxOwner = text(sandbox.get("owner_id"));
        if (!sandboxOwner.equals(ownerId) && !sandboxOwner.equals(nodeId)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "沙箱不属于该机构");
        }
        Map<String, Object> mount = single("select asset_version,expires_at from ds_sandbox_dataset_mount "
                + "where sandbox_id=? and asset_id=? and deleted=0 and status='READY'", sandboxId, assetId);
        if (mount == null) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "该资产未经审批挂载到此沙箱");
        }
        Map<String, Object> control = single(
                "select allow_use,use_until from ds_sandbox_mount_control where sandbox_id=? and asset_id=?",
                sandboxId, assetId);
        if (control != null && !truthy(control.get("allow_use"))) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "数据方已停止该挂载数据的使用");
        }
        Approved approved = approval(sandboxId, assetId);
        // 请求的授权范围必须落在审批批准的范围内，任一越界即拒绝。
        TeeGuard.requireSubset(columns, approved.columns(), "授权列");
        TeeGuard.requireSubset(operators, approved.operators(), "授权算子");
        Instant deadline = approved.expiresAt();
        deadline = earlier(deadline, instant(sandbox.get("expires_at")));
        deadline = earlier(deadline, instant(mount.get("expires_at")));
        if (control != null) {
            deadline = earlier(deadline, instant(control.get("use_until")));
        }
        if (deadline == null) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "审批未给出使用截止时间");
        }
        if (Instant.now().isAfter(deadline)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "审批批准的使用期限已过");
        }
        if (expiresAt.isAfter(deadline)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "授权有效期超过审批批准的期限");
        }
        return new Approved(approved.approvalId(), approved.columns(), approved.operators(), deadline);
    }

    /** 取该沙箱最近一份已完成、且确实包含该资产的挂载类审批。 */
    private Approved approval(String sandboxId, String assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select id,approval_type,payload_json from ds_sandbox_approval "
                        + "where sandbox_id=? and status='COMPLETED' and deleted=0 order by updated_at desc",
                sandboxId);
        for (Map<String, Object> row : rows) {
            if (!MOUNT_APPROVAL_TYPES.contains(text(row.get("approval_type")))) {
                continue;
            }
            JsonNode payload = payload(row.get("payload_json"));
            if (!contains(payload.path("datasetAssetIds"), assetId)) {
                continue;
            }
            List<String> columns = values(payload.path("teeColumns"));
            if (columns.isEmpty()) {
                columns = assetColumns(assetId);
            }
            List<String> operators = values(payload.path("teeOperators"));
            if (operators.isEmpty()) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED, "审批未批准任何可信计算算子");
            }
            if (columns.isEmpty()) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED, "审批未批准任何列");
            }
            return new Approved(text(row.get("id")), columns, operators,
                    instant(payload.path("teeExpiresAt").asText("")));
        }
        throw TeeException.of(TeeContract.Error.POLICY_DENIED, "找不到覆盖该资产的已完成审批");
    }

    /** 资产已登记的表结构列；审批未显式限定列时以此为上限，仍不包含未登记的列。 */
    private List<String> assetColumns(String assetId) {
        Map<String, Object> asset = single(
                "select metadata_json from ds_data_asset where id=? and deleted=0", assetId);
        if (asset == null) {
            return List.of();
        }
        JsonNode metadata = payload(asset.get("metadata_json"));
        List<String> columns = new ArrayList<>();
        for (JsonNode column : metadata.path("columns")) {
            String name = column.isTextual() ? column.asText() : column.path("name").asText("");
            if (!name.isBlank()) {
                columns.add(name);
            }
        }
        return List.copyOf(new LinkedHashSet<>(columns));
    }

    private Map<String, Object> single(String sql, Object... args) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, args);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private JsonNode payload(Object json) {
        try {
            return mapper.readTree(text(json).isBlank() ? "{}" : text(json));
        } catch (Exception unreadable) {
            return mapper.createObjectNode();
        }
    }

    private static boolean contains(JsonNode array, String value) {
        for (JsonNode item : array) {
            if (value.equals(item.asText())) {
                return true;
            }
        }
        return false;
    }

    private static List<String> values(JsonNode array) {
        List<String> values = new ArrayList<>();
        for (JsonNode item : array) {
            String value = item.asText("").trim();
            if (!value.isBlank()) {
                values.add(value);
            }
        }
        return List.copyOf(new LinkedHashSet<>(values));
    }

    private static boolean truthy(Object value) {
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        return !Set.of("0", "false", "FALSE").contains(text(value));
    }

    private static String text(Object value) {
        return Objects.toString(value, "").trim();
    }

    private static Instant earlier(Instant left, Instant right) {
        if (left == null) {
            return right;
        }
        return right == null || left.isBefore(right) ? left : right;
    }

    /** 平台既有时间列没有时区，按平台时区解析；契约字段本身带偏移量。 */
    private static Instant instant(Object value) {
        String text = text(value);
        if (text.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (Exception notOffset) {
            try {
                return LocalDateTime.parse(text).atZone(PLATFORM_ZONE).toInstant();
            } catch (Exception invalid) {
                return null;
            }
        }
    }
}
