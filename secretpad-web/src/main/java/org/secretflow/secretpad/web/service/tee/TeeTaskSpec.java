/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import java.util.List;

/**
 * 契约第五节的签名任务载荷。
 *
 * <p>下发入口固定为 Kuscia {@code task_input_config} 中的 {@code tee_task_jws}；
 * 任务只携带密文对象引用、元数据与签名，不内联任何数据块。
 */
public record TeeTaskSpec(String contractVersion, String taskId, String requestId, String issuer,
                          String audience, String sandboxId, String operatorId, List<String> columns,
                          List<Input> inputs, Program program, String issuedAt, String expiresAt,
                          String nonce, OutputPolicy outputPolicy, String runtimeImageDigest) {

    public record Input(String assetId, String assetVersion, String keyId, String keyVersion,
                        String policyId, String policyVersion, String objectId,
                        String ciphertextSha256, long plaintextBytes) {
    }

    /** BUILTIN 的 objectId 为空，其摘要指镜像内算子资源；其余模式必须另取程序字节并校验摘要。 */
    public record Program(String kind, String objectId, String sha256, String parameters) {
    }

    public record OutputPolicy(List<String> reportKinds, boolean encryptData, boolean encryptModel,
                               boolean exportRequiresAllContributors) {
    }
}
