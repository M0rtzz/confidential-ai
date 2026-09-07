/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.crypto;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * GPU 密态执行链路的只读聚合。
 *
 * <p>与 CPU 侧 {@code TrustChainService} 同构：六段分别对应会话身份注册、权重与数据密文化、
 * 可信域校验、证明与一次性 TEK、一次性授权放钥、密态执行与输出出域。
 *
 * <p>本类只读 {@code ds-confidential/v1} 已有的元数据表，不写入、不改动既有服务，
 * 也不落在 {@code /api/v1alpha1/tee} 契约命名空间下。计数一律由数据库侧 {@code count}
 * 得出，明细按页取回，因此不受 CPU 侧聚合接口 200 条上限的影响。
 */
@Service
public class GpuChainService {

    /** 明细分页上限；请求超过该值时按该值截断，避免一次取回整张表。 */
    private static final int MAX_PAGE_SIZE = 200;
    private static final int DEFAULT_PAGE_SIZE = 20;

    private final JdbcTemplate jdbc;
    private final ConfidentialComputeService compute;

    public GpuChainService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ConfidentialComputeService compute) {
        this.jdbc = jdbc;
        this.compute = compute;
    }

    public record Metric(String label, long value) {
    }

    public record Segment(String key, String label, String state, List<Metric> metrics) {
    }

    public record Runtime(String securityProfile, String evidenceType, String hardwareModel, String policyId,
                          boolean simulated, boolean attestationVerified, String contractVersion) {
    }

    public record SummaryView(String ownerId, Runtime runtime, List<Map<String, Object>> domains,
                              List<Segment> segments) {
    }

    /** 明细分页；{@code total} 由数据库侧统计，与 {@code items} 的长度无关。 */
    public record PageView(List<Map<String, Object>> items, long total, int page, int size) {
    }

    /**
     * 当前运行档位。
     *
     * <p>取值来自 {@link ConfidentialContract} 的冻结常量：本版本固定为 A100 实验室模拟证据，
     * 不具备 GPU 硬件机密隔离，因此 {@code attestationVerified} 恒为 false。
     */
    public Runtime runtime() {
        return new Runtime(ConfidentialContract.SIM_PROFILE, ConfidentialContract.SIM_EVIDENCE,
                ConfidentialContract.SIM_HARDWARE, ConfidentialContract.SIM_POLICY,
                true, false, ConfidentialContract.VERSION);
    }

    public SummaryView summary(String ownerId) {
        List<Segment> segments = new ArrayList<>();
        segments.add(identitySegment(ownerId));
        segments.add(assetSegment(ownerId));
        segments.add(domainSegment());
        segments.add(attestationSegment(ownerId));
        segments.add(grantSegment(ownerId));
        segments.add(executionSegment(ownerId));
        return new SummaryView(ownerId, runtime(), compute.domains(), segments);
    }

    /* ------------------------------- 分段统计 ------------------------------- */

    private Segment identitySegment(String ownerId) {
        long total = count("select count(*) from ds_crypto_identity where user_id=?", ownerId);
        long active = count("select count(*) from ds_crypto_identity where user_id=? and status='ACTIVE'", ownerId);
        long signing = count("select count(*) from ds_crypto_signing_identity where owner_id=? and status='ACTIVE'",
                ownerId);
        return new Segment("IDENTITY", "会话身份注册", total == 0 ? "EMPTY" : "OK",
                List.of(new Metric("生效", active), new Metric("已登记", total),
                        new Metric("签名身份", signing)));
    }

    private Segment assetSegment(String ownerId) {
        long versions = count("select count(*) from ds_confidential_asset_version where owner_id=?", ownerId);
        long assets = count("select count(*) from ds_confidential_asset where owner_id=?", ownerId);
        return new Segment("ASSET_ENCRYPT", "权重与数据密文化", versions == 0 ? "EMPTY" : "OK",
                List.of(new Metric("密文资产", assets), new Metric("版本", versions)));
    }

    private Segment domainSegment() {
        List<Map<String, Object>> domains = compute.domains();
        long trusted = domains.stream()
                .filter(item -> "active".equals(item.get("status")) && "trusted".equals(item.get("trustStatus")))
                .count();
        return new Segment("DOMAIN_VERIFY", "可信域校验", domains.isEmpty() ? "EMPTY" : "OK",
                List.of(new Metric("可用", trusted), new Metric("已登记", domains.size())));
    }

    private Segment attestationSegment(String ownerId) {
        long tasks = count("select count(*) from ds_crypto_task where owner_id=?", ownerId);
        long sessions = count("select count(*) from ds_tee_attestation_session s"
                + " join ds_crypto_task t on t.task_id=s.task_id where t.owner_id=?", ownerId);
        // 全部证据为实验室模拟，段状态固定为告警，避免被读作已通过硬件证明。
        return new Segment("ATTESTATION", "证明与一次性 TEK", sessions == 0 ? "EMPTY" : "WARN",
                List.of(new Metric("任务", tasks), new Metric("证明会话", sessions)));
    }

    private Segment grantSegment(String ownerId) {
        long total = count("select count(*) from ds_crypto_grant where owner_id=?", ownerId);
        long consumed = count("select count(*) from ds_crypto_grant where owner_id=? and consumed_at is not null",
                ownerId);
        long revoked = count("select count(*) from ds_crypto_grant where owner_id=? and revoked_at is not null",
                ownerId);
        return new Segment("GRANT_RELEASE", "一次性授权放钥", total == 0 ? "EMPTY" : "OK",
                List.of(new Metric("已消费", consumed), new Metric("已吊销", revoked),
                        new Metric("总数", total)));
    }

    private Segment executionSegment(String ownerId) {
        long total = count("select count(*) from ds_confidential_execution e"
                + " join ds_crypto_task t on t.task_id=e.task_id where t.owner_id=?", ownerId);
        long completed = count("select count(*) from ds_confidential_execution e"
                + " join ds_crypto_task t on t.task_id=e.task_id"
                + " where t.owner_id=? and e.completed_at is not null", ownerId);
        long audits = count("select count(*) from ds_crypto_audit_event where user_id=?", ownerId);
        return new Segment("EXECUTION_EGRESS", "密态执行与输出出域", total == 0 ? "EMPTY" : "OK",
                List.of(new Metric("已完成", completed), new Metric("总数", total),
                        new Metric("审计事件", audits)));
    }

    /* ------------------------------- 明细分页 ------------------------------- */

    public PageView identities(String ownerId, int page, int size) {
        return paged("select kid,algorithm,status,created_at,revoked_at,"
                        + "substr(encryption_public_key,1,16) as encryption_public_key_head,"
                        + "substr(signing_public_key,1,16) as signing_public_key_head"
                        + " from ds_crypto_identity where user_id=? order by created_at desc",
                "select count(*) from ds_crypto_identity where user_id=?", ownerId, page, size);
    }

    public PageView assets(String ownerId, int page, int size) {
        return paged("select v.asset_version_id,v.asset_id,v.version_number,v.domain_id,v.algorithm,"
                        + "v.original_file_name,v.original_size,v.cipher_size,v.manifest_hash,v.status,v.created_at,"
                        + "a.name as asset_name,a.asset_type"
                        + " from ds_confidential_asset_version v"
                        + " left join ds_confidential_asset a on a.asset_id=v.asset_id"
                        + " where v.owner_id=? order by v.created_at desc",
                "select count(*) from ds_confidential_asset_version where owner_id=?", ownerId, page, size);
    }

    public PageView attestations(String ownerId, int page, int size) {
        return paged("select s.session_id,s.task_id,s.task_spec_digest,s.tee_pubkey_hash,s.evidence_hash,"
                        + "s.evidence_type,s.simulated,s.hardware_model,s.security_profile,s.policy_id,"
                        + "s.issued_at,s.expires_at,s.status,t.status as task_status"
                        + " from ds_tee_attestation_session s"
                        + " join ds_crypto_task t on t.task_id=s.task_id"
                        + " where t.owner_id=? order by s.issued_at desc",
                "select count(*) from ds_tee_attestation_session s"
                        + " join ds_crypto_task t on t.task_id=s.task_id where t.owner_id=?",
                ownerId, page, size);
    }

    public PageView grants(String ownerId, int page, int size) {
        return paged("select grant_id,task_id,session_id,jti,claims_hash,security_profile,"
                        + "expires_at,consumed_at,revoked_at,created_at"
                        + " from ds_crypto_grant where owner_id=? order by created_at desc",
                "select count(*) from ds_crypto_grant where owner_id=?", ownerId, page, size);
    }

    public PageView executions(String ownerId, int page, int size) {
        return paged("select e.execution_id,e.task_id,e.grant_id,e.session_id,e.security_profile,"
                        + "e.image_digest,e.sbom_digest,e.status,e.output_manifest_hash,e.created_at,e.completed_at"
                        + " from ds_confidential_execution e"
                        + " join ds_crypto_task t on t.task_id=e.task_id"
                        + " where t.owner_id=? order by e.created_at desc",
                "select count(*) from ds_confidential_execution e"
                        + " join ds_crypto_task t on t.task_id=e.task_id where t.owner_id=?",
                ownerId, page, size);
    }

    /**
     * 审计链明细。
     *
     * <p>与 {@code /crypto/audit-events} 的区别在于返回列：这里带上 {@code event_hash} 与
     * {@code previous_hash} 两列，供界面核对哈希链连续性；那个接口只返回事件正文。
     */
    public PageView auditEvents(String ownerId, int page, int size) {
        return paged("select event_id,event_type,subject_id,security_profile,simulated,"
                        + "previous_hash,event_hash,created_at"
                        + " from ds_crypto_audit_event where user_id=? order by created_at desc",
                "select count(*) from ds_crypto_audit_event where user_id=?", ownerId, page, size);
    }

    /* --------------------------------- 工具 --------------------------------- */

    private long count(String sql, Object... args) {
        Long value = jdbc.queryForObject(sql, Long.class, args);
        return value == null ? 0L : value;
    }

    private PageView paged(String sql, String countSql, String ownerId, int page, int size) {
        int effectiveSize = size <= 0 ? DEFAULT_PAGE_SIZE : Math.min(size, MAX_PAGE_SIZE);
        int effectivePage = Math.max(page, 1);
        long total = count(countSql, ownerId);
        List<Map<String, Object>> rows = jdbc.queryForList(sql + " limit ? offset ?",
                ownerId, effectiveSize, (long) (effectivePage - 1) * effectiveSize);
        return new PageView(rows.stream().map(GpuChainService::camelKeys).toList(),
                total, effectivePage, effectiveSize);
    }

    /** 列名按下划线命名，接口对外统一成驼峰，避免把数据库列名带进前端。 */
    private static Map<String, Object> camelKeys(Map<String, Object> row) {
        Map<String, Object> result = new LinkedHashMap<>();
        row.forEach((column, value) -> result.put(camel(column), value));
        return result;
    }

    private static String camel(String column) {
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
        return builder.toString();
    }
}
