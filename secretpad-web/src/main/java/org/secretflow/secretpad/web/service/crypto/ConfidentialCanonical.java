package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

/** Canonical JSON and Ed25519 helpers. Contract values use strings, booleans, and integer counters. */
public final class ConfidentialCanonical {
    private static final byte[] ED25519_SPKI_PREFIX = hex("302a300506032b6570032100");
    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private ConfidentialCanonical() {
    }

    public static byte[] bytes(Object value) {
        try {
            JsonNode node = value instanceof JsonNode json ? json : CANONICAL.valueToTree(value);
            return CANONICAL.writeValueAsBytes(canonicalValue(node));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "规范化 JSON 失败");
        }
    }

    public static String sha256(Object value) {
        return sha256Bytes(bytes(value));
    }

    public static String sha256Bytes(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder text = new StringBuilder(64);
            for (byte item : digest) {
                text.append(String.format("%02x", item));
            }
            return text.toString();
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "SHA-256 计算失败");
        }
    }

    public static void verifyEd25519(String rawPublicKey, String signature, Object value) {
        try {
            byte[] raw = decode(rawPublicKey);
            if (raw.length != 32) {
                throw new IllegalArgumentException("invalid Ed25519 key size");
            }
            byte[] spki = new byte[ED25519_SPKI_PREFIX.length + raw.length];
            System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
            System.arraycopy(raw, 0, spki, ED25519_SPKI_PREFIX.length, raw.length);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)));
            verifier.update(bytes(value));
            if (!verifier.verify(decode(signature))) {
                throw new IllegalArgumentException("signature mismatch");
            }
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "Ed25519 签名校验失败");
        }
    }

    public static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    public static JsonNode parse(ObjectMapper mapper, String value) {
        try {
            return mapper.readTree(value);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "持久化 JSON 无法解析");
        }
    }

    private static Object canonicalValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            Map<String, Object> sorted = new TreeMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                sorted.put(field.getKey(), canonicalValue(field.getValue()));
            }
            return sorted;
        }
        if (node.isArray()) {
            ArrayList<Object> values = new ArrayList<>(node.size());
            node.forEach(item -> values.add(canonicalValue(item)));
            return values;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isIntegralNumber()) {
            return node.bigIntegerValue();
        }
        throw TeeException.of(TeeContract.Error.CONTRACT_INVALID,
                "规范化 JSON 仅允许字符串、布尔值、整数、数组、对象和 null");
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
