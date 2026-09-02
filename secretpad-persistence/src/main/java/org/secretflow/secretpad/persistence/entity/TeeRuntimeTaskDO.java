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

/** P5 运行时任务授权；只保存签名任务元数据、对象范围和已核实回执，不保存密钥或明文。 */
@Entity
@Builder
@Getter
@Setter
@ToString(exclude = {"taskJws", "receiptJws"})
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tee_runtime_task")
@Where(clause = "is_deleted = 0")
public class TeeRuntimeTaskDO extends BaseAggregationRoot<TeeRuntimeTaskDO> {

    @EmbeddedId
    private UPK upk;

    @Column(name = "request_id", nullable = false, length = 64)
    private String requestId;

    @Column(name = "caller_id", nullable = false, length = 128)
    private String callerId;

    @Column(name = "workload_cert_sha256", nullable = false, length = 64)
    private String workloadCertSha256;

    @Column(name = "object_ids_json", nullable = false, columnDefinition = "text")
    private String objectIdsJson;

    @Column(name = "contributors_json", nullable = false, columnDefinition = "text")
    private String contributorsJson;

    @Column(name = "program_object_id", nullable = true, length = 64)
    private String programObjectId;

    @Column(name = "result_bindings_json", nullable = false, columnDefinition = "text")
    private String resultBindingsJson;

    @Column(name = "task_jws", nullable = false, columnDefinition = "text")
    private String taskJws;

    @Column(name = "expires_at", nullable = false, length = 64)
    private String expiresAt;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "receipt_jws", nullable = true, columnDefinition = "text")
    private String receiptJws;

    @Column(name = "receipt_verified", nullable = false)
    private Boolean receiptVerified;

    @Getter
    @Setter
    @ToString
    @EqualsAndHashCode
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UPK implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @Column(name = "task_id", nullable = false, length = 64)
        private String taskId;
    }
}
