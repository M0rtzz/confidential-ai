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

/** 中心端签发的数据密钥台账；只记录标识与状态，不保存任何密钥材料。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_key")
@Where(clause = "is_deleted = 0")
public class TeeKeyDO extends BaseAggregationRoot<TeeKeyDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "asset_id", nullable = false, length = 64)
    private String assetId;

    @Column(name = "asset_version", nullable = false, length = 32)
    private String assetVersion;

    @Column(name = "owner_id", nullable = false, length = 128)
    private String ownerId;

    /** CM 中的资源标识；密钥本体由中心密钥服务托管。 */
    @Column(name = "resource_uri", nullable = false, length = 128)
    private String resourceUri;

    @Column(name = "state", nullable = false, length = 32)
    private String state;

    @Column(name = "issued_at", nullable = false, length = 64)
    private String issuedAt;

    @Column(name = "claim_count", nullable = false)
    private Integer claimCount;

    @Column(name = "release_count", nullable = false)
    private Integer releaseCount;

    // 本表不在 data.sync 允许列表内，不跨节点同步，沿用基类的归属默认实现。
    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "key_id", nullable = false, length = 64)
        private String keyId;

        @Column(name = "key_version", nullable = false, length = 32)
        private String keyVersion;
    }
}
