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


/** 密文资产登记；中心端只保存结构与密文引用，不保存数据行。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_asset")
@Where(clause = "is_deleted = 0")
public class TeeAssetDO extends BaseAggregationRoot<TeeAssetDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "owner_id", nullable = false, length = 128)
    private String ownerId;

    @Column(name = "schema_json", nullable = false, columnDefinition = "text")
    private String schemaJson;

    @Column(name = "object_id", nullable = false, length = 64)
    private String objectId;

    @Column(name = "policy_id", nullable = false, length = 64)
    private String policyId;

    @Column(name = "policy_version", nullable = false, length = 32)
    private String policyVersion;

    @Column(name = "key_id", nullable = false, length = 64)
    private String keyId;

    @Column(name = "key_version", nullable = false, length = 32)
    private String keyVersion;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "asset_id", nullable = false, length = 64)
        private String assetId;

        @Column(name = "asset_version", nullable = false, length = 32)
        private String assetVersion;

    }
}
