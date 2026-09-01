/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.configuration;

import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 平台间契约入口。
 *
 * <p>只有中心实例配置本端口。契约第二节要求跨机构接口必须双向 TLS 并验证证书链、
 * 有效期与吊销状态，因此这里独立于浏览器端口另开一个连接器：强制客户端证书、
 * 信任锚只有部署时生成的平台间 CA，并加载该 CA 的吊销列表。
 *
 * <p>端口上只服务契约接口，机构标识由 {@code LoginInterceptor} 从客户端证书推导；
 * 会话令牌在本端口上不被接受，本端口的身份也不会出现在浏览器端口上。
 */
@Slf4j
@Configuration
public class TeeContractConnectorConfiguration
        implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    private final int port;
    private final Path certDir;

    public TeeContractConnectorConfiguration(
            @Value("${TEE_CONTRACT_PORT:0}") int port,
            @Value("${TEE_CONTRACT_SERVER_CERT_DIR:/app/tee-contract-server}") String certDir) {
        this.port = port;
        this.certDir = Path.of(certDir);
    }

    private KeyStore trustStore(Path authority) {
        try {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(authority)));
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setCertificateEntry("tee-contract-ca", certificate);
            return store;
        } catch (Exception failure) {
            throw new IllegalStateException("平台间契约入口的信任锚无法装配", failure);
        }
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        if (port <= 0) {
            return;
        }
        Path certificate = certDir.resolve("client.crt");
        Path privateKey = certDir.resolve("client.key");
        Path authority = certDir.resolve("ca.crt");
        if (!Files.isReadable(certificate) || !Files.isReadable(privateKey) || !Files.isReadable(authority)) {
            throw new IllegalStateException("平台间契约入口缺少服务端证书或信任锚，拒绝以无认证方式启动");
        }
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setPort(port);
        connector.setScheme("https");
        connector.setSecure(true);
        ((Http11NioProtocol) connector.getProtocolHandler()).setSSLEnabled(true);

        SSLHostConfig ssl = new SSLHostConfig();
        ssl.setProtocols("TLSv1.2+TLSv1.3");
        ssl.setCertificateVerification("required");
        // JSSE 只认显式装配的信任库；仅给出 PEM 路径会退回 JDK 默认信任库，
        // 那等于接受任何公共 CA 签发的证书，必须在这里直接装配平台间 CA。
        ssl.setTrustStore(trustStore(authority));
        Path revocations = certDir.resolve("ca.crl");
        if (Files.isReadable(revocations)) {
            ssl.setCertificateRevocationListFile(revocations.toString());
        }
        SSLHostConfigCertificate material =
                new SSLHostConfigCertificate(ssl, SSLHostConfigCertificate.Type.RSA);
        material.setCertificateFile(certificate.toString());
        material.setCertificateKeyFile(privateKey.toString());
        ssl.addCertificate(material);
        connector.addSslHostConfig(ssl);

        factory.addAdditionalTomcatConnectors(connector);
        log.info("平台间契约入口已启用，端口 {}，仅接受已登记的客户端证书", port);
    }
}
