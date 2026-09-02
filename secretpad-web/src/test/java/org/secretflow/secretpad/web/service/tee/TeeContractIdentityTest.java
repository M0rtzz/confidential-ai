/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 平台间入口的调用方身份判定。
 *
 * <p>这条判定是跨实例通道唯一的机构身份来源。通过 CA 验证还不够：证书必须显式登记过，
 * 否则同一 CA 下新签发的任何证书都会自动获得机构身份。
 */
class TeeContractIdentityTest {

    private TeeContractIdentity identity(String registryJson) throws Exception {
        Path dir = Files.createTempDirectory("tee-contract-identity");
        Path registry = dir.resolve("registry.json");
        Files.writeString(registry, registryJson);
        return new TeeContractIdentity(new TeeIdentityRegistry(new ObjectMapper(),
                registry.toString(), dir.resolve("workload.crt").toString()));
    }

    private HttpServletRequest requestWith(X509Certificate... chain) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute("jakarta.servlet.request.X509Certificate"))
                .thenReturn(chain.length == 0 ? null : chain);
        return request;
    }

    @Test
    void registeredCertificateResolvesToItsInstitution() throws Exception {
        X509Certificate certificate = TeeTestMaterial.certificate();
        String fingerprint = TeeCrypto.certificateSha256(certificate);
        TeeContractIdentity identity = identity(
                "{\"contractClientCertificates\":{\"" + fingerprint + "\":\"inst-client-1\"}}");
        assertEquals("inst-client-1", identity.requireOwner(requestWith(certificate)));
        assertEquals("CLIENT", identity.requireCaller(requestWith(certificate)).endRole());
    }

    @Test
    void registeredRuntimeCertificateReceivesOnlyCenterRole() throws Exception {
        X509Certificate certificate = TeeTestMaterial.certificate();
        String fingerprint = TeeCrypto.certificateSha256(certificate);
        TeeContractIdentity identity = identity(
                "{\"runtimeContractCertificates\":{\"" + fingerprint + "\":\"inst-center\"}}");
        assertEquals("inst-center", identity.requireCaller(requestWith(certificate)).ownerId());
        assertEquals("CENTER", identity.requireCaller(requestWith(certificate)).endRole());
    }

    @Test
    void certificateCannotOccupyClientAndRuntimeRoles() throws Exception {
        X509Certificate certificate = TeeTestMaterial.certificate();
        String fingerprint = TeeCrypto.certificateSha256(certificate);
        TeeContractIdentity identity = identity("{\"contractClientCertificates\":{\""
                + fingerprint + "\":\"inst-center\"},\"runtimeContractCertificates\":{\""
                + fingerprint + "\":\"inst-center\"}}");
        TeeException failure = assertThrows(TeeException.class,
                () -> identity.requireCaller(requestWith(certificate)));
        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, failure.error());
    }

    @Test
    void unregisteredCertificateIsDenied() throws Exception {
        TeeContractIdentity identity = identity("{\"contractClientCertificates\":{}}");
        TeeException failure = assertThrows(TeeException.class,
                () -> identity.requireOwner(requestWith(TeeTestMaterial.certificate())));
        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, failure.error());
    }

    @Test
    void missingClientCertificateIsDenied() throws Exception {
        TeeContractIdentity identity = identity("{\"contractClientCertificates\":{}}");
        TeeException failure = assertThrows(TeeException.class,
                () -> identity.requireOwner(requestWith()));
        assertEquals(TeeContract.Error.AUDIT_ACCESS_DENIED, failure.error());
    }
}
