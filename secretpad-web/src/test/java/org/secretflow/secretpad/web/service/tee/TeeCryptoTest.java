/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** AES-256-GCM 封装、AAD 绑定与摘要的定向测试；篡改任一部分都必须被拒绝。 */
class TeeCryptoTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final byte[] key = key(7);
    private final byte[] plaintext = "age,income\n31,42000\n".getBytes(StandardCharsets.UTF_8);

    private static byte[] key(int seed) {
        byte[] value = new byte[TeeContract.DATA_KEY_BYTES];
        new SecureRandom(new byte[]{(byte) seed}).nextBytes(value);
        return value;
    }

    private TeeCrypto.EncryptedObject seal() {
        return TeeCrypto.seal(mapper, key, plaintext, "asset-1", "1", "kd-1", "1");
    }

    @Test
    void roundTripPreservesPlaintextAndBindsMetadata() {
        TeeCrypto.EncryptedObject object = seal();
        assertEquals(TeeContract.KEY_ALGORITHM, object.algorithm());
        assertEquals(TeeContract.VERSION, object.contractVersion());
        assertEquals(TeeContract.NONCE_BYTES, TeeCrypto.decode(object.nonceB64()).length);
        assertEquals(TeeContract.TAG_BYTES, TeeCrypto.decode(object.tagB64()).length);
        assertArrayEquals(plaintext, TeeCrypto.open(mapper, key, object));
        assertEquals("{\"assetId\":\"asset-1\",\"assetVersion\":1,\"keyId\":\"kd-1\",\"keyVersion\":1}",
                new String(TeeCrypto.decode(object.aadB64()), StandardCharsets.UTF_8));
    }

    @Test
    void legacyP4AadRemainsReadableButUnknownFieldsAreRejected() throws Exception {
        TeeCrypto.EncryptedObject current = seal();
        byte[] legacyAad = ("{\"contractVersion\":\"" + TeeContract.VERSION
                + "\",\"assetId\":\"asset-1\",\"assetVersion\":\"1\","
                + "\"keyId\":\"kd-1\",\"keyVersion\":\"1\"}")
                .getBytes(StandardCharsets.UTF_8);
        assertEquals(true, TeeCrypto.matchesAad(mapper, legacyAad, current));
        byte[] extra = "{\"assetId\":\"asset-1\",\"assetVersion\":1,\"keyId\":\"kd-1\",\"keyVersion\":1,\"extra\":true}"
                .getBytes(StandardCharsets.UTF_8);
        assertEquals(false, TeeCrypto.matchesAad(mapper, extra, current));
    }

    @Test
    void digestCoversNonceAadCiphertextAndTag() {
        TeeCrypto.EncryptedObject object = seal();
        String expected = TeeCrypto.digest(TeeCrypto.decode(object.nonceB64()), TeeCrypto.decode(object.aadB64()),
                TeeCrypto.decode(object.ciphertextB64()), TeeCrypto.decode(object.tagB64()));
        assertEquals(expected, object.ciphertextSha256());
    }

    @Test
    void nonceIsNotReusedAcrossSeals() {
        assertNotEquals(seal().nonceB64(), seal().nonceB64());
    }

    @Test
    void tamperedCiphertextIsRejected() {
        TeeCrypto.EncryptedObject object = seal();
        byte[] ciphertext = TeeCrypto.decode(object.ciphertextB64());
        ciphertext[0] ^= 0x01;
        TeeCrypto.EncryptedObject tampered = withCiphertext(object, TeeCrypto.encode(ciphertext));
        assertEquals(TeeContract.Error.DATA_INTEGRITY_FAILED,
                assertThrows(TeeException.class, () -> TeeCrypto.open(mapper, key, tampered)).error());
    }

    @Test
    void tamperedAadIsRejectedEvenWhenDigestIsRecomputed() {
        TeeCrypto.EncryptedObject object = seal();
        byte[] forged = TeeCrypto.buildAad(mapper, "asset-2", "1", "kd-1", "1");
        String digest = TeeCrypto.digest(TeeCrypto.decode(object.nonceB64()), forged,
                TeeCrypto.decode(object.ciphertextB64()), TeeCrypto.decode(object.tagB64()));
        TeeCrypto.EncryptedObject tampered = new TeeCrypto.EncryptedObject(object.contractVersion(),
                object.assetId(), object.assetVersion(), object.keyId(), object.keyVersion(),
                object.algorithm(), object.nonceB64(), TeeCrypto.encode(forged),
                object.ciphertextB64(), object.tagB64(), digest);
        assertEquals(TeeContract.Error.DATA_INTEGRITY_FAILED,
                assertThrows(TeeException.class, () -> TeeCrypto.open(mapper, key, tampered)).error());
    }

    @Test
    void wrongKeyIsRejected() {
        TeeCrypto.EncryptedObject object = seal();
        assertEquals(TeeContract.Error.DATA_INTEGRITY_FAILED,
                assertThrows(TeeException.class, () -> TeeCrypto.open(mapper, key(9), object)).error());
    }

    @Test
    void shortKeyIsRejected() {
        assertEquals(TeeContract.Error.CONTRACT_INVALID, assertThrows(TeeException.class,
                () -> TeeCrypto.seal(mapper, new byte[16], plaintext, "a", "1", "k", "1")).error());
    }

    @Test
    void base64UrlHasNoPadding() {
        byte[] value = {1, 2, 3, 4, 5};
        String encoded = TeeCrypto.encodeUrl(value);
        assertEquals(-1, encoded.indexOf('='));
        assertArrayEquals(value, TeeCrypto.decodeUrl(encoded));
    }

    private TeeCrypto.EncryptedObject withCiphertext(TeeCrypto.EncryptedObject object, String ciphertextB64) {
        return new TeeCrypto.EncryptedObject(object.contractVersion(), object.assetId(), object.assetVersion(),
                object.keyId(), object.keyVersion(), object.algorithm(), object.nonceB64(), object.aadB64(),
                ciphertextB64, object.tagB64(), object.ciphertextSha256());
    }
}
