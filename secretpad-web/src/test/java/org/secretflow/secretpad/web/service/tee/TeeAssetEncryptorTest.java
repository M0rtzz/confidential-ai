/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 抽样脱敏产出的加密落盘。
 *
 * <p>要落地的性质有三条：落盘字节不含明文、密文与资产版本和密钥版本绑定、
 * 同一资产版本重试复用同一把密钥而不是反复签发。
 */
class TeeAssetEncryptorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    /** 合成数据密钥；先固定填充，供密封与解密两侧使用同一取值。 */
    private final byte[] dataKey = filled();
    private final byte[] plaintext = "age,city\n31,hangzhou\n".getBytes(StandardCharsets.UTF_8);

    private static byte[] filled() {
        byte[] value = new byte[TeeContract.DATA_KEY_BYTES];
        Arrays.fill(value, (byte) 3);
        return value;
    }

    private TeeAssetEncryptor encryptor(TeeKeyGateway gateway, KeyAdapterClient adapter) throws Exception {
        Path dir = Files.createTempDirectory("tee-encryptor");
        TeeTestMaterial.writeIdentity(dir);
        return new TeeAssetEncryptor(gateway, new TeeInstitutionKey(dir.toString()), adapter, mapper);
    }

    private String sealed() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, TeeTestMaterial.certificate().getPublicKey(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                        PSource.PSpecified.DEFAULT));
        return TeeCrypto.encode(cipher.doFinal(dataKey));
    }

    private TeeKeyGateway gatewayIssuing(String keyId) throws Exception {
        TeeKeyGateway gateway = mock(TeeKeyGateway.class);
        when(gateway.delegated()).thenReturn(true);
        when(gateway.issue(eq("inst-a"), any()))
                .thenReturn(new TeeKeyService.IssueResult(TeeContract.VERSION, keyId, "1", "ACTIVE"));
        when(gateway.claim(eq("inst-a"), any())).thenReturn(new TeeKeyService.ClaimResult(
                TeeContract.VERSION, new TeeKeyService.KeyEnvelope(keyId, "1",
                        TeeContract.ENVELOPE_ALGORITHM, "fingerprint", sealed())));
        return gateway;
    }

    @Test
    void sealedOutputCarriesNoPlaintextAndDecryptsBack() throws Exception {
        TeeAssetEncryptor encryptor = encryptor(gatewayIssuing("kd-1"), mock(KeyAdapterClient.class));
        TeeAssetEncryptor.Sealed result = encryptor.seal("inst-a", "asset-1", "1", plaintext);

        assertEquals("kd-1", result.keyId());
        assertEquals("asset-1", result.object().assetId());
        assertEquals(TeeContract.KEY_ALGORITHM, result.object().algorithm());
        String stored = new String(result.payload(), StandardCharsets.UTF_8);
        assertFalse(stored.contains("hangzhou"));
        assertNotEquals(TeeCrypto.sha256Hex(plaintext), result.ciphertextSha256());
        assertArrayEquals(plaintext, TeeCrypto.open(mapper, dataKey, result.object()));
    }

    @Test
    void requestIdsAreDerivedFromTheAssetVersionSoRetriesReuseOneKey() throws Exception {
        TeeKeyGateway gateway = gatewayIssuing("kd-1");
        TeeAssetEncryptor encryptor = encryptor(gateway, mock(KeyAdapterClient.class));
        encryptor.seal("inst-a", "asset-1", "1", plaintext);
        encryptor.seal("inst-a", "asset-1", "1", plaintext);

        org.mockito.ArgumentCaptor<TeeKeyService.IssueRequest> issued =
                org.mockito.ArgumentCaptor.forClass(TeeKeyService.IssueRequest.class);
        org.mockito.Mockito.verify(gateway, org.mockito.Mockito.times(2))
                .issue(eq("inst-a"), issued.capture());
        assertEquals(issued.getAllValues().get(0).requestId(), issued.getAllValues().get(1).requestId());
    }

    @Test
    void withoutKeyServiceOrInstitutionKeyTheFeatureStaysOff() throws Exception {
        TeeKeyGateway gateway = mock(TeeKeyGateway.class);
        KeyAdapterClient adapter = mock(KeyAdapterClient.class);
        when(gateway.delegated()).thenReturn(false);
        when(adapter.configured()).thenReturn(false);
        assertFalse(encryptor(gateway, adapter).available());

        when(adapter.configured()).thenReturn(true);
        assertTrue(encryptor(gateway, adapter).available());

        Path empty = Files.createTempDirectory("tee-encryptor-empty");
        assertFalse(new TeeAssetEncryptor(gateway, new TeeInstitutionKey(empty.toString()),
                adapter, mapper).available());
    }
}
