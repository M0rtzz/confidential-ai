/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * 契约第四节的密文封装与密钥密封。
 *
 * <p>AES-256-GCM，12 字节 nonce，16 字节 tag；AAD 绑定资产与密钥版本，
 * 摘要为 SHA256(nonce ‖ aad ‖ ciphertext ‖ tag)。接收者公钥只取自已认证的证书。
 */
public final class TeeCrypto {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URLD = Base64.getUrlDecoder();

    private TeeCrypto() {
    }

    /** 密文对象的传输形态；AAD 保留原始字节，接收者核对取值后以原字节认证解密。 */
    public record EncryptedObject(String contractVersion, String assetId, String assetVersion,
                                  String keyId, String keyVersion, String algorithm,
                                  String nonceB64, String aadB64, String ciphertextB64,
                                  String tagB64, String ciphertextSha256) {
    }

    public static byte[] randomNonce() {
        byte[] nonce = new byte[TeeContract.NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    /** AAD 的解码 JSON 绑定资产与密钥版本；字段顺序固定，保证两端逐字节一致。 */
    public static byte[] buildAad(ObjectMapper mapper, String assetId, String assetVersion,
                                  String keyId, String keyVersion) {
        ObjectNode node = mapper.createObjectNode();
        node.put("assetId", assetId);
        node.put("assetVersion", positiveVersion(assetVersion, "assetVersion"));
        node.put("keyId", keyId);
        node.put("keyVersion", positiveVersion(keyVersion, "keyVersion"));
        try {
            return mapper.writeValueAsBytes(node);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "AAD 构造失败");
        }
    }

    private static long positiveVersion(String value, String name) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed <= 0) {
                throw new NumberFormatException(name);
            }
            return parsed;
        } catch (NumberFormatException failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID,
                    name + " 必须是正整数");
        }
    }

    public static EncryptedObject seal(ObjectMapper mapper, byte[] dataKey, byte[] plaintext,
                                       String assetId, String assetVersion, String keyId, String keyVersion) {
        requireKey(dataKey);
        if (plaintext.length > TeeContract.MAX_OBJECT_PLAINTEXT_BYTES) {
            throw TeeException.of(TeeContract.Error.PAYLOAD_TOO_LARGE, "明文超出单对象上限");
        }
        byte[] nonce = randomNonce();
        byte[] aad = buildAad(mapper, assetId, assetVersion, keyId, keyVersion);
        byte[] combined = cipher(Cipher.ENCRYPT_MODE, dataKey, nonce, aad, plaintext);
        byte[] ciphertext = Arrays.copyOfRange(combined, 0, combined.length - TeeContract.TAG_BYTES);
        byte[] tag = Arrays.copyOfRange(combined, combined.length - TeeContract.TAG_BYTES, combined.length);
        return new EncryptedObject(TeeContract.VERSION, assetId, assetVersion, keyId, keyVersion,
                TeeContract.KEY_ALGORITHM, B64.encodeToString(nonce), B64.encodeToString(aad),
                B64.encodeToString(ciphertext), B64.encodeToString(tag),
                digest(nonce, aad, ciphertext, tag));
    }

    public static byte[] open(ObjectMapper mapper, byte[] dataKey, EncryptedObject object) {
        requireKey(dataKey);
        if (!TeeContract.KEY_ALGORITHM.equals(object.algorithm())
                || !TeeContract.VERSION.equals(object.contractVersion())) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密文封装版本或算法不符");
        }
        byte[] nonce = decode(object.nonceB64());
        byte[] aad = decode(object.aadB64());
        byte[] ciphertext = decode(object.ciphertextB64());
        byte[] tag = decode(object.tagB64());
        if (nonce.length != TeeContract.NONCE_BYTES || tag.length != TeeContract.TAG_BYTES) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "nonce 或 tag 长度不符");
        }
        if (!MessageDigest.isEqual(digest(nonce, aad, ciphertext, tag).getBytes(StandardCharsets.US_ASCII),
                object.ciphertextSha256().getBytes(StandardCharsets.US_ASCII))) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密文摘要不符");
        }
        verifyAad(mapper, aad, object);
        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
        try {
            return cipher(Cipher.DECRYPT_MODE, dataKey, nonce, aad, combined);
        } catch (TeeException rejected) {
            throw rejected;
        } catch (RuntimeException failure) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "GCM 认证解密失败");
        }
    }

    /** AAD 以原始字节参与认证，但其取值必须与封装声明一致，避免绑定错资产或错版本。 */
    private static void verifyAad(ObjectMapper mapper, byte[] aad, EncryptedObject object) {
        if (!matchesAad(mapper, aad, object)) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "AAD 绑定与密文声明不一致");
        }
    }

    /**
     * 新对象只写冻结契约的四字段整数版本；读取时兼容已由 P4 生成的五字段字符串版本，
     * 两种形态都要求精确字段集合，不能借兼容逻辑附加未签名语义。
     */
    static boolean matchesAad(ObjectMapper mapper, byte[] aad, EncryptedObject object) {
        try {
            JsonNode node = mapper.readTree(aad);
            java.util.Set<String> fields = new java.util.HashSet<>();
            node.fieldNames().forEachRemaining(fields::add);
            java.util.Set<String> current = java.util.Set.of(
                    "assetId", "assetVersion", "keyId", "keyVersion");
            java.util.Set<String> legacy = java.util.Set.of(
                    "contractVersion", "assetId", "assetVersion", "keyId", "keyVersion");
            boolean shape = fields.equals(current) || (fields.equals(legacy)
                    && TeeContract.VERSION.equals(node.path("contractVersion").asText()));
            return shape && object.assetId().equals(node.path("assetId").asText())
                    && object.assetVersion().equals(node.path("assetVersion").asText())
                    && object.keyId().equals(node.path("keyId").asText())
                    && object.keyVersion().equals(node.path("keyVersion").asText());
        } catch (Exception failure) {
            return false;
        }
    }

    private static byte[] cipher(int mode, byte[] dataKey, byte[] nonce, byte[] aad, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(dataKey, "AES"),
                    new GCMParameterSpec(TeeContract.TAG_BYTES * 8, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "GCM 运算失败");
        }
    }

    public static String digest(byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(nonce);
            sha.update(aad);
            sha.update(ciphertext);
            sha.update(tag);
            return hex(sha.digest());
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "摘要计算失败");
        }
    }

    public static String sha256Hex(byte[] value) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "摘要计算失败");
        }
    }

    public static X509Certificate certificate(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "接收者证书无法解析");
        }
    }

    /** 证书指纹是 DER 证书的 SHA-256，由服务端计算并绑定会话，不接受调用方自报。 */
    public static String certificateSha256(X509Certificate certificate) {
        try {
            return sha256Hex(certificate.getEncoded());
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "证书编码失败");
        }
    }

    public static RSAPublicKey rsaPublicKey(X509Certificate certificate) {
        PublicKey key = certificate.getPublicKey();
        if (!(key instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < 2048) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "接收者证书必须为至少 2048 位的 RSA 公钥");
        }
        return rsa;
    }

    public static String encode(byte[] value) {
        return B64.encodeToString(value);
    }

    public static byte[] decode(String value) {
        try {
            return B64D.decode(value);
        } catch (RuntimeException failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "Base64 字段无法解码");
        }
    }

    /** JWS 使用无填充 Base64URL；现有 Java 工具返回标准 Base64，需在此转换。 */
    public static String encodeUrl(byte[] value) {
        return B64URL.encodeToString(value);
    }

    public static byte[] decodeUrl(String value) {
        try {
            return B64URLD.decode(value);
        } catch (RuntimeException failure) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "JWS 段无法解码");
        }
    }

    private static void requireKey(byte[] dataKey) {
        if (dataKey == null || dataKey.length != TeeContract.DATA_KEY_BYTES) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "数据密钥必须为 32 字节");
        }
    }

    private static String hex(byte[] value) {
        StringBuilder text = new StringBuilder(value.length * 2);
        for (byte b : value) {
            text.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return text.toString();
    }
}
