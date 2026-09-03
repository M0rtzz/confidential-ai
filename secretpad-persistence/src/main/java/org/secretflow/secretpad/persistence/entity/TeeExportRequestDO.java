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

/** TEE 结果导出工单；只保存密文摘要、密钥标识和接收者证书指纹。 */
@Entity
@Builder
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_export_request")
@Where(clause = "is_deleted = 0")
public class TeeExportRequestDO extends BaseAggregationRoot<TeeExportRequestDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "result_id", nullable = false, length = 64)
    private String resultId;

    @Column(name = "object_id", nullable = false, length = 64)
    private String objectId;

    @Column(name = "kind", nullable = false, length = 32)
    private String kind;

    @Column(name = "task_id", nullable = false, length = 64)
    private String taskId;

    @Column(name = "ciphertext_sha256", nullable = false, length = 64)
    private String ciphertextSha256;

    @Column(name = "key_id", nullable = false, length = 64)
    private String keyId;

    @Column(name = "key_version", nullable = false, length = 32)
    private String keyVersion;

    @Column(name = "requester_owner_id", nullable = false, length = 128)
    private String requesterOwnerId;

    @Column(name = "recipient_cert_sha256", nullable = false, length = 64)
    private String recipientCertSha256;

    @Column(name = "request_id", nullable = false, length = 64, unique = true)
    private String requestId;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "approved_at", length = 64)
    private String approvedAt;

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
    }
}
