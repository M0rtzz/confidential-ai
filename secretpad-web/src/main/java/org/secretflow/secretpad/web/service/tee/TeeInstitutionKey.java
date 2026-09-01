/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
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
}
