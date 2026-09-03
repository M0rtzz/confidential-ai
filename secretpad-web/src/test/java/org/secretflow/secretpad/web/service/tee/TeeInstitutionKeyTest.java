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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 机构私钥的信封解封。
 *
 * <p>密钥信封是客户端拿到数据密钥的唯一途径，参数必须与密钥服务密封时完全一致：
 * RSA-OAEP，hash 与 MGF1 均为 SHA-256，label 为空。参数选错会在加密阶段才暴露，
 * 因此在这里按密封方的实现正向验证一次。
 */
class TeeInstitutionKeyTest {

    private Path identityDir() throws Exception {
        Path dir = Files.createTempDirectory("tee-institution");
        TeeTestMaterial.writeIdentity(dir);
        return dir;
    }

    private String seal(byte[] dataKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, TeeTestMaterial.certificate().getPublicKey(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                        PSource.PSpecified.DEFAULT));
        return TeeCrypto.encode(cipher.doFinal(dataKey));
    }

    private TeeKeyService.KeyEnvelope envelope(String wrapped) {
        return new TeeKeyService.KeyEnvelope("kd-1", "1", TeeContract.ENVELOPE_ALGORITHM,
                "fingerprint", wrapped);
    }

    @Test
    void unwrapsKeySealedWithTheSameParameters() throws Exception {
        byte[] dataKey = new byte[TeeContract.DATA_KEY_BYTES];
        Arrays.fill(dataKey, (byte) 7);
        TeeInstitutionKey key = new TeeInstitutionKey(identityDir().toString());
        assertTrue(key.available());
        assertArrayEquals(dataKey, key.unwrap(envelope(seal(dataKey))));
    }

    @Test
    void wrongKeyLengthIsRejected() throws Exception {
        TeeInstitutionKey key = new TeeInstitutionKey(identityDir().toString());
        TeeException failure = assertThrows(TeeException.class,
                () -> key.unwrap(envelope(seal(new byte[16]))));
        assertEquals(TeeContract.Error.DATA_INTEGRITY_FAILED, failure.error());
    }

    @Test
    void otherEnvelopeAlgorithmsAreRejected() throws Exception {
        TeeInstitutionKey key = new TeeInstitutionKey(identityDir().toString());
        TeeException failure = assertThrows(TeeException.class, () -> key.unwrap(
                new TeeKeyService.KeyEnvelope("kd-1", "1", "RSA-PKCS1", "fingerprint", "AAAA")));
        assertEquals(TeeContract.Error.CONTRACT_INVALID, failure.error());
    }

    @Test
    void missingIdentityIsNotAvailable() throws Exception {
        Path empty = Files.createTempDirectory("tee-institution-empty");
        assertFalse(new TeeInstitutionKey(empty.toString()).available());
    }

    @Test
    void exportEnvelopeExpiresAtTheRecipient() throws Exception {
        TeeKeyService.KeyEnvelope envelope = new TeeKeyService.KeyEnvelope("kd-1", "1",
                TeeContract.ENVELOPE_ALGORITHM,
                TeeCrypto.certificateSha256(TeeTestMaterial.certificate()), "AAAA");
        TeeExportService.ExportResult expired = new TeeExportService.ExportResult(
                TeeContract.VERSION, "object-1", envelope, Instant.now().minusSeconds(1).toString());

        TeeException failure = assertThrows(TeeException.class,
                () -> new TeeInstitutionKey(identityDir().toString())
                        .decryptExport(expired, null, new ObjectMapper()));

        assertEquals(TeeContract.Error.EXPORT_NOT_APPROVED, failure.error());
    }

    @Test
    void activeExportEnvelopeCanBeUnwrapped() throws Exception {
        byte[] dataKey = new byte[TeeContract.DATA_KEY_BYTES];
        Arrays.fill(dataKey, (byte) 9);
        ObjectMapper mapper = new ObjectMapper();
        TeeKeyService.KeyEnvelope envelope = new TeeKeyService.KeyEnvelope("kd-1", "1",
                TeeContract.ENVELOPE_ALGORITHM,
                TeeCrypto.certificateSha256(TeeTestMaterial.certificate()), seal(dataKey));
        TeeExportService.ExportResult active = new TeeExportService.ExportResult(
                TeeContract.VERSION, "object-1", envelope, Instant.now().plusSeconds(60).toString());
        byte[] plaintext = "approved-result".getBytes();
        TeeCrypto.EncryptedObject object = TeeCrypto.seal(
                mapper, dataKey, plaintext, "result-1", "1", "kd-1", "1");

        assertArrayEquals(plaintext, new TeeInstitutionKey(identityDir().toString())
                .decryptExport(active, object, mapper));
    }
}
