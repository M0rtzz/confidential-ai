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


/** 密文对象元数据；对象本体存放于运行目录，库中不保存密文。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_object")
@Where(clause = "is_deleted = 0")
public class TeeObjectDO extends BaseAggregationRoot<TeeObjectDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "kind", nullable = false, length = 32)
    private String kind;

    @Column(name = "owner_id", nullable = false, length = 128)
    private String ownerId;

    @Column(name = "asset_id", nullable = true, length = 64)
    private String assetId;

    @Column(name = "task_id", nullable = true, length = 64)
    private String taskId;

    @Column(name = "result_id", nullable = true, length = 64)
    private String resultId;

    @Column(name = "key_id", nullable = false, length = 64)
    private String keyId;

    @Column(name = "key_version", nullable = false, length = 32)
    private String keyVersion;

    @Column(name = "ciphertext_sha256", nullable = false, length = 64)
    private String ciphertextSha256;

    @Column(name = "size_bytes", nullable = false)
    private Long sizeBytes;

    @Column(name = "contributors_json", nullable = false, columnDefinition = "text")
    private String contributorsJson;

    @Column(name = "export_state", nullable = false, length = 32)
    private String exportState;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "object_id", nullable = false, length = 64)
        private String objectId;

    }
}
