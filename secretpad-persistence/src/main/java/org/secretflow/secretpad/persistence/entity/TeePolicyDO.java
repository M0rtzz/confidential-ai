/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */

package org.secretflow.secretpad.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.Where;

import java.io.Serial;
import java.io.Serializable;


/** 授权规则登记；列与算子精确匹配，不支持通配符，空集合即禁止。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_policy")
@Where(clause = "is_deleted = 0")
public class TeePolicyDO extends BaseAggregationRoot<TeePolicyDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "asset_id", nullable = false, length = 64)
    private String assetId;

    @Column(name = "asset_version", nullable = false, length = 32)
    private String assetVersion;

    @Column(name = "owner_id", nullable = false, length = 128)
    private String ownerId;

    @Column(name = "sandbox_id", nullable = false, length = 64)
    private String sandboxId;

    @Column(name = "columns_json", nullable = false, columnDefinition = "text")
    private String columnsJson;

    @Column(name = "operators_json", nullable = false, columnDefinition = "text")
    private String operatorsJson;

    @Column(name = "report_kinds_json", nullable = false, columnDefinition = "text")
    private String reportKindsJson;

    @Column(name = "expires_at", nullable = false, length = 64)
    private String expiresAt;

    @Column(name = "state", nullable = false, length = 32)
    private String state;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "policy_id", nullable = false, length = 64)
        private String policyId;

        @Column(name = "policy_version", nullable = false, length = 32)
        private String policyVersion;

    }
}
