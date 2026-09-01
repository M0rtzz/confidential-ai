/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * 双向 TLS 出站材料。
 *
 * <p>平台调用密钥适配服务、客户端实例调用中心端契约入口都用这一份实现：
 * 证书与私钥只从挂载目录读取，不接受由配置项或请求传入证书内容。
 */
public final class TeeMutualTls {

    private TeeMutualTls() {
    }

    /** 以挂载目录中的 client.crt/client.key 为出站身份，ca.crt 为唯一信任锚。 */
    public static SSLContext context(Path certDir, String alias) throws Exception {
        X509Certificate certificate = certificate(certDir.resolve("client.crt"));
        X509Certificate authority = certificate(certDir.resolve("ca.crt"));

        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, null);
        char[] empty = new char[0];
        identity.setKeyEntry(alias, privateKey(certDir.resolve("client.key")), empty,
                new Certificate[]{certificate});
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(identity, empty);

        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry(alias + "-ca", authority);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);

        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        return context;
    }

    public static X509Certificate certificate(Path path) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(path)));
    }

    public static PrivateKey privateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
    }
}
