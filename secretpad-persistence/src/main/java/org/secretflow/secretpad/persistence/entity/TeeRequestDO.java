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


/** 幂等记录；相同内容重试返回原结果，相同标识不同内容拒绝。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_request")
@Where(clause = "is_deleted = 0")
public class TeeRequestDO extends BaseAggregationRoot<TeeRequestDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "fingerprint", nullable = false, length = 64)
    private String fingerprint;

    @Column(name = "response_json", nullable = false, columnDefinition = "text")
    private String responseJson;

    @Column(name = "created_at", nullable = false, length = 64)
    private String createdAt;

    @Column(name = "owner_id", nullable = false, length = 128)
    private String ownerId;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "request_key", nullable = false, length = 160)
        private String requestKey;

    }
}
