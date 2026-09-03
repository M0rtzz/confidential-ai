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

/** TEE 导出机构票；投票身份固定为机构 ownerId。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_export_vote")
@Where(clause = "is_deleted = 0")
public class TeeExportVoteDO extends BaseAggregationRoot<TeeExportVoteDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "voter", nullable = false, length = 128)
    private String voter;

    @Column(name = "comment", nullable = false, length = 1024)
    private String comment;

    @Column(name = "voted_at", nullable = false, length = 64)
    private String votedAt;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "export_id", nullable = false, length = 64)
        private String exportId;

        @Column(name = "voter_owner_id", nullable = false, length = 128)
        private String voterOwnerId;
    }
}
