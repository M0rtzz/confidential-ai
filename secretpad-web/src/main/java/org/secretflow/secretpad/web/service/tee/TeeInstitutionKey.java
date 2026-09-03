/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.Arrays;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * 本实例机构身份的私钥持有者。
 *
 * <p>密钥信封由中心端密封给本机构的登记证书，只有本实例能解开；中心端不持有客户端的解封私钥。
 * 数据密钥解开后只在内存中用于一次加密，用完立即清零，本地不落盘、不缓存。
 */
@Component
public class TeeInstitutionKey {

    private final Path certDir;

    public TeeInstitutionKey(@Value("${TEE_INSTITUTION_KEY_DIR:/app/tee-identity-key}") String certDir) {
        this.certDir = Path.of(certDir);
    }

    public boolean available() {
        return Files.isReadable(certDir.resolve("client.crt")) && Files.isReadable(certDir.resolve("client.key"));
    }

    /** 申领密钥时提交的接收者证书；服务端仍会自行核对指纹，不接受任意公钥。 */
    public String certificatePem() {
        try {
            return Files.readString(certDir.resolve("client.crt"), StandardCharsets.UTF_8);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "本机构证书未就绪");
        }
    }

    /** RSA-OAEP-256 解封数据密钥；hash 与 MGF1 均为 SHA-256，label 为空。 */
    public byte[] unwrap(TeeKeyService.KeyEnvelope envelope) {
        if (envelope == null || !TeeContract.ENVELOPE_ALGORITHM.equals(envelope.algorithm())) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密钥信封算法不符");
        }
        byte[] key;
        try {
            PrivateKey privateKey = TeeMutualTls.privateKey(certDir.resolve("client.key"));
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey, new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            key = cipher.doFinal(TeeCrypto.decode(envelope.wrappedKeyB64()));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密钥信封无法解封");
        }
        if (key.length != TeeContract.DATA_KEY_BYTES) {
            Arrays.fill(key, (byte) 0);
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "数据密钥长度不符");
        }
        return key;
    }

    /**
     * 使用 P7 导出信封；到期时在持有私钥的接收机构本地拒绝解封。
     *
     * <p>中心端只签发密封数据密钥和到期时刻，不接触接收机构私钥。该方法是客户端使用
     * 导出信封的统一入口，同时核对本机构证书指纹，防止绕过接收者绑定。
     */
    private byte[] unwrapExport(TeeExportService.ExportResult exported) {
        if (exported == null || exported.keyEnvelope() == null) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "导出信封不能为空");
        }
        Instant expiresAt = TeeGuard.requireInstant(exported.expiresAt(), "expiresAt");
        if (!Instant.now().isBefore(expiresAt)) {
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "导出信封已过期，请重新取回");
        }
        try {
            String localFingerprint = TeeCrypto.certificateSha256(
                    TeeMutualTls.certificate(certDir.resolve("client.crt")));
            if (!localFingerprint.equals(exported.keyEnvelope().recipientCertSha256())) {
                throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH,
                        "导出信封未密封给本机构证书");
            }
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "本机构证书无法读取");
        }
        return unwrap(exported.keyEnvelope());
    }

    /** 解封并认证解密一份 P7 导出结果；数据密钥不会返回给调用方。 */
    public byte[] decryptExport(TeeExportService.ExportResult exported,
                                TeeCrypto.EncryptedObject object, ObjectMapper mapper) {
        byte[] dataKey = unwrapExport(exported);
        try {
            if (object == null
                    || !exported.keyEnvelope().keyId().equals(object.keyId())
                    || !exported.keyEnvelope().keyVersion().equals(object.keyVersion())) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED,
                        "导出信封与密文对象绑定不符");
            }
            return TeeCrypto.open(mapper, dataKey, object);
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }
}
