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


/** 任务 nonce 去重；按签发方与 nonce 全局唯一，保留至过期后 24 小时。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_nonce")
@Where(clause = "is_deleted = 0")
public class TeeNonceDO extends BaseAggregationRoot<TeeNonceDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "task_id", nullable = false, length = 64)
    private String taskId;

    @Column(name = "request_id", nullable = false, length = 64)
    private String requestId;

    @Column(name = "expires_at", nullable = false, length = 64)
    private String expiresAt;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "issuer", nullable = false, length = 128)
        private String issuer;

        @Column(name = "nonce", nullable = false, length = 128)
        private String nonce;

    }
}
