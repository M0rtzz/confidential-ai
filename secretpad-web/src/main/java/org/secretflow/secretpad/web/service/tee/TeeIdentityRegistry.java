/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * 机构与可信运行时的证书登记。
 *
 * <p>密钥信封只能密封给已登记的接收者：调用方虽然要提交证书，但服务端会自行计算 DER 摘要
 * 并与部署时登记的指纹比对，因此接受的仍是登记过的公钥，不是调用方任意提供的公钥。
 *
 * <p>这条比对是仿真模式下的关键补偿控制：密钥服务本身不校验发起方身份，
 * 即便有人伪造发起方，密封结果也只有登记私钥的持有者能解开。
 */
@Component
public class TeeIdentityRegistry {

    public record ContractCaller(String ownerId, String endRole) {
    }

    private final ObjectMapper mapper;
    private final Path registryPath;
    private final Path workloadCertPath;

    public TeeIdentityRegistry(ObjectMapper mapper,
            @Value("${TEE_IDENTITY_REGISTRY:/app/tee-identity/registry.json}") String registry,
            @Value("${TEE_IDENTITY_WORKLOAD_CERT:/app/tee-identity/workload.crt}") String workloadCert) {
        this.mapper = mapper;
        this.registryPath = Path.of(registry);
        this.workloadCertPath = Path.of(workloadCert);
    }

    /** 已登记机构证书的 DER SHA-256；缺登记即拒绝，不回退为信任任意证书。 */
    public String institutionFingerprint(String ownerId) {
        JsonNode node = read().path(ownerId).path("certificateSha256");
        if (!node.isTextual() || node.asText().isBlank()) {
            throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "机构证书未登记");
        }
        return node.asText();
    }

    /** 校验调用方提交的接收者证书确实是该机构已登记的那一张。 */
    public X509Certificate requireInstitutionCertificate(String ownerId, String pem) {
        X509Certificate certificate = TeeCrypto.certificate(TeeGuard.requireText(pem, "recipientCertPem"));
        String actual = TeeCrypto.certificateSha256(certificate);
        if (!actual.equals(institutionFingerprint(ownerId))) {
            throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "接收者证书与登记的机构证书不符");
        }
        return certificate;
    }

    /**
     * 平台间契约入口的调用方身份：客户端证书 DER SHA-256 → 机构标识。
     *
     * <p>映射在部署时随公开登记一同发布，未登记的证书即使通过了 CA 验证也一律拒绝，
     * 因此新增一台客户端实例必须显式发布登记，不会因为签发了证书就自动获得机构身份。
     */
    public String ownerByContractCertificate(String certificateSha256) {
        JsonNode node = read().path("contractClientCertificates")
                .path(TeeGuard.requireText(certificateSha256, "certificateSha256"));
        if (!node.isTextual() || node.asText().isBlank()) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "调用方证书未登记为平台间契约身份");
        }
        return node.asText();
    }

    /** Resolve an mTLS caller to an immutable institution and endpoint role. */
    public ContractCaller callerByContractCertificate(String certificateSha256) {
        String fingerprint = TeeGuard.requireText(certificateSha256, "certificateSha256");
        JsonNode root = read();
        JsonNode client = root.path("contractClientCertificates").path(fingerprint);
        JsonNode runtime = root.path("runtimeContractCertificates").path(fingerprint);
        boolean clientRegistered = client.isTextual() && !client.asText().isBlank();
        boolean runtimeRegistered = runtime.isTextual() && !runtime.asText().isBlank();
        if (clientRegistered == runtimeRegistered) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                    "调用方证书未登记或同时占用多个契约角色");
        }
        return runtimeRegistered
                ? new ContractCaller(runtime.asText(), "CENTER")
                : new ContractCaller(client.asText(), "CLIENT");
    }

    /** 可信运行时的工作负载证书；SIMULATION 下预注册，HARDWARE 下另按度量值绑定。 */
    public String workloadCertificatePem() {
        try {
            return Files.readString(workloadCertPath);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "可信运行时证书未就绪");
        }
    }

    public String workloadFingerprint() {
        return TeeCrypto.certificateSha256(TeeCrypto.certificate(workloadCertificatePem()));
    }

    /**
     * 任务签名的受信证书映射：kid → Base64 编码的 DER 证书；未知 kid 一律拒绝。
     *
     * <p>沿用 {@code EncryptUtils} 的既有约定，其公钥参数就是 Base64 DER 证书，
     * 与部署时签发的中心签名身份一致，不另建裸公钥配置。
     */
    public String taskSigningCertificate(String kid) {
        JsonNode node = read().path("taskSigningCertificates").path(TeeGuard.requireText(kid, "kid"));
        if (!node.isTextual() || node.asText().isBlank()) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "任务签名 kid 不在受信映射内");
        }
        return node.asText();
    }

    /**
     * 仿真模式下允许执行的运行镜像摘要。
     *
     * <p>契约第四节规定 SIMULATION 只允许预注册的工作负载证书、指定运行镜像摘要与签名任务，
     * 因此任务声明的镜像摘要必须落在部署时登记的集合内；未登记即拒绝，不接受任意摘要。
     */
    public void requireRuntimeImageDigest(String digest) {
        String value = TeeGuard.requireText(digest, "runtimeImageDigest");
        JsonNode digests = read().path("runtimeImageDigests");
        if (!digests.isArray() || digests.isEmpty()) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "部署未登记可信运行镜像摘要");
        }
        for (JsonNode allowed : digests) {
            if (value.equals(allowed.asText())) {
                return;
            }
        }
        throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "运行镜像摘要不在登记范围内");
    }

    private JsonNode read() {
        try {
            if (Files.size(registryPath) > 256 * 1024) {
                throw new IllegalStateException("登记文件过大");
            }
            return mapper.readTree(Files.readString(registryPath));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "身份登记不可读");
        }
    }

    /** 仅用于只读展示，不返回任何私钥或密钥材料。 */
    public Map<String, String> summary() {
        JsonNode root = read();
        return Map.of("registryFields", String.valueOf(root.size()));
    }
}
