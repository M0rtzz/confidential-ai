/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 契约层的输入校验。
 *
 * <p>其中三项是底座不校验、必须由本层兜住的边界：空授权集合、通配符授权、发起方身份。
 * 这三条已由 P4 前置实测确认，放行链路上任何一处遗漏都会让规则形同虚设。
 */
public final class TeeGuard {

    private TeeGuard() {
    }

    public static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "缺少必填字段 " + field);
        }
        return value.trim();
    }

    public static void requireVersion(String contractVersion) {
        if (!TeeContract.VERSION.equals(contractVersion)) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "契约版本不匹配");
        }
    }

    /**
     * 授权集合必须非空且逐项精确匹配。
     *
     * <p>密钥服务把 '*' 视为放开全部列或全部算子，空集合也不会触发校验；
     * 契约要求「空授权集合即禁止」且不支持通配符，因此两种情形都在此拒绝。
     */
    public static List<String> requireGrantSet(Collection<String> values, String field) {
        if (values == null || values.isEmpty()) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, field + "授权集合为空，按契约禁止");
        }
        Set<String> unique = new LinkedHashSet<>();
        for (String value : values) {
            if (value == null || value.isBlank()) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, field + "名称无效");
            }
            String trimmed = value.trim();
            if (TeeContract.WILDCARD.equals(trimmed)) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED, field + "不支持通配符授权");
            }
            unique.add(trimmed);
        }
        return List.copyOf(unique);
    }

    /** 请求的列必须落在已登记授权列之内；请求列为空同样禁止，避免绕过列级限制。 */
    public static void requireSubset(Collection<String> requested, Collection<String> granted, String field) {
        List<String> values = requireGrantSet(requested, field);
        if (!granted.containsAll(values)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, field + "未在授权范围内");
        }
    }

    public static void requireOwner(String expected, String actual) {
        if (expected == null || !expected.equals(actual)) {
            throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "调用方与资产归属不符");
        }
    }

    public static Instant requireInstant(String value, String field) {
        try {
            return Instant.parse(requireText(value, field));
        } catch (DateTimeParseException invalid) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, field + " 不是有效的 UTC 时间");
        }
    }

    public static void requireNotExpired(Instant expiresAt, TeeContract.Error error, String message) {
        if (!Instant.now().minusSeconds(TeeContract.CLOCK_SKEW_SECONDS).isBefore(expiresAt)) {
            throw TeeException.of(error, message);
        }
    }

    public static void requireReportKinds(Collection<String> kinds) {
        for (String kind : requireGrantSet(kinds, "报告类型")) {
            if (!TeeContract.REPORT_KINDS.contains(kind)) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "报告类型不在契约白名单内");
            }
        }
    }

    /**
     * 任务请求的报告类型可以为空，表示本次任务不申请任何明文报告权限。
     *
     * <p>这与 policy 中的授权集合不同：policy 空授权集合按契约禁止；outputPolicy
     * 的空请求集合是最小权限表达。字段缺失仍是无效契约，非空项仍须落在白名单内。
     */
    public static void requireRequestedReportKinds(Collection<String> kinds) {
        if (kinds == null) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "缺少必填字段 reportKinds");
        }
        for (String kind : kinds) {
            if (kind == null || kind.isBlank() || !TeeContract.REPORT_KINDS.contains(kind.trim())) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "报告类型不在契约白名单内");
            }
        }
    }

    public static void requireSize(long bytes, long limit) {
        if (bytes > limit) {
            throw TeeException.of(TeeContract.Error.PAYLOAD_TOO_LARGE, "内容超出契约限额");
        }
    }
}
