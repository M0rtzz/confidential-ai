/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 任务签名校验。
 *
 * <p>签名输入是原始两段 Base64URL 字节拼接，验证时不重序列化 payload；
 * 未知 kid、非 RS256、过期与超长有效期都必须拒绝。
 */
class TeeTaskSignatureTest {

    private static final String KID = "tee-task-1";

    // 一次性合成测试材料，仅用于本用例验签；不是任何真实签发身份，禁止导入信任库。
    private static final String TEST_SIGNER_CERT_B64 = "MIIDHzCCAgegAwIBAgIULFzwCQ6wb0nrBoGOoFiqUSEwHXswDQYJKoZIhvcNAQELBQAwHzEdMBsGA1UEAwwUdGVl"
            + "LXRhc2stc2lnbmVyLXRlc3QwHhcNMjYwODMxMTczOTMzWhcNNDYwODI2MTczOTMzWjAfMR0wGwYDVQQDDBR0ZWUt"
            + "dGFzay1zaWduZXItdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALdqOY9UzN9QEeY2cq5eDrO3"
            + "/xSNJOjwugQ0cFjZrhnEYbd2z5Kqk4w/k26RxQWNvvR0eitDTTXTi4GskU8KJGbGnvXNiQRndfOygAlLmffLDVu1"
            + "5oUXg60l6lQjHBWsj5n46UrLLH55tvHXFH1hGYp1JRgyU8M65ctSUnhlfYNOgTeycaUa/ucO+lXRbhjY3rPmOl1R"
            + "XX3GT5S6VH8QPlsBLqndCpQ4BxZod6+xv6P/tCyGhTdUDST862MgKsOnElvems6Okf9mNVwEACUsE51JxeA9dYsR"
            + "OBdny25jTnSVnFWkKlPQ7mNa29VN4vqiCExW37jkUBLdQ/CfOaMH4S8CAwEAAaNTMFEwHQYDVR0OBBYEFOuhx/2I"
            + "pPJPV3Ta8gN3D6hpLLeWMB8GA1UdIwQYMBaAFOuhx/2IpPJPV3Ta8gN3D6hpLLeWMA8GA1UdEwEB/wQFMAMBAf8w"
            + "DQYJKoZIhvcNAQELBQADggEBAFr8QLVMPHysvbNycL0tQBhsxKtH8Rgoye6ZQBQfMjCbUgIiXkl5+QCO8Z5zvcjD"
            + "lyTXJVEv8q+Biw6btpythh5ZDX8Lz8hNnzy6vE2gmoqqQ+nFVzhqmbxmKIn94i/mutnRqL0eSwrLK9PT2v08QMIs"
            + "mHUtlcoqNONhpUEkUaMnMJZHQ4cyQZVblgWHY/BysSB6h1sKH2heQUQOB3SAD9yHhEIpTyGG55E/3kCk+2b8dgdf"
            + "DtMpuRaUBdTrbixZk18OkJwfKtvPsuLMp+cehtcr3pYtfTjXxHZbfsuM9iewWs2DgkDYV/M0ewNzQegvXNcULmi5"
            + "tKAtYUZfX3riass=";

    private static final String TEST_SIGNER_KEY_B64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3ajmPVMzfUBHmNnKuXg6zt/8UjSTo8LoENHBY"
            + "2a4ZxGG3ds+SqpOMP5NukcUFjb70dHorQ00104uBrJFPCiRmxp71zYkEZ3XzsoAJS5n3yw1bteaFF4OtJepUIxwV"
            + "rI+Z+OlKyyx+ebbx1xR9YRmKdSUYMlPDOuXLUlJ4ZX2DToE3snGlGv7nDvpV0W4Y2N6z5jpdUV19xk+UulR/ED5b"
            + "AS6p3QqUOAcWaHevsb+j/7QshoU3VA0k/OtjICrDpxJb3prOjpH/ZjVcBAAlLBOdScXgPXWLETgXZ8tuY050lZxV"
            + "pCpT0O5jWtvVTeL6oghMVt+45FAS3UPwnzmjB+EvAgMBAAECggEAA7FcUlHzRAXBLoDnIzKamiy4som69gOuwxnp"
            + "LyjG1Bb7nq2CNWJA0UCQb9f4fwmhEBvuP8O9oLlPJD+8tzotjHIwTiOiwBdzLQJpiIZgpbgNX0zUxNY53PkX9DS2"
            + "wor0YzW7QLnBfhRmRg0+CN41HPAJ3KhavmIHsWXJakok0klwGxzkR51aNwzdR1MntwRrXqKrL089WweNWHgqmJL2"
            + "rvVX2igvgvxIvRiIopjLuBJmSCGe+lCFhQSFw65QQQyXyBh4wlTKWYhF5CwnPr7JQdQdcj++4vhf7BZuhnvIhS8H"
            + "xne2PmSOI5if67j+4wJCixRylSvzDZeyEgHE5y0zAQKBgQDnOyAu+Dve+LYTDECtDpKCQy9ITDuuJ8GESzie6BFM"
            + "mdNnIXUbyeNkH9vv5W7f6O8IqaocT32fO4tg4w6Q/WxBPzbqH1xmo+WtOBFnATUlDcXYxkBfN7ymTHmmxe6s4Rxh"
            + "0cmrjeyv79SMOFlol6LOtzqXVEaZ7CUPmbJJL2j8LwKBgQDLD+BGQ2ZifxDDjWLD6rjA7abHxrIG+kS+3bruMedS"
            + "Y15RxFlAiJmQjh3+yqmjtZwYvARCHZRNmePbXTpz9+0+mHutbKPTaC+kq7995r9YwqmbvU9rW7gedZfJGbMBbMIW"
            + "n4C5JoyLQEELi1Dna8vNKQwNGVU0QGDFIYGSEy0rAQKBgQCR3IU/u80gqSlJuLfvsrqOu0zPQW+AO4niJwUvkFqh"
            + "RIPLkZprDh6H4WT+3m7jhe+LOmOZejdXQ9t3IaPlqEcqnXLJm0DRamAOtcicfnGEzzxXsy+WIPW6vZEbt84IdfRO"
            + "bGTX+C4vCY29aipURRspZQHrxfjHTeRPA/goHGUQdwKBgQCyoLWmuZWwYZyqmY5fT/TUanqDVOu4raGZ0U2mSan2"
            + "1Mjc3v+wgDmuawZB45+VDqZRL9wDGSgjl5NUnk9UQq2lmdd6OI5o40a98gOSylBa0WsIQGFDzLxLtyAd3IiWYUjf"
            + "Q9KljR6nRI+ziwtReIcgY9JhF37XZyZ5Yz8q88mRAQKBgBGCu2vtfpOeik+qr7CZPOeto7boW3Ot3MCoJjYqYEjA"
            + "9jmKZmsmfZuNunUgOSMmAYdkRtUlk9y/JFZDXsbeCyLV3/95pWqsHNN7XPcERNgsqWPJq/hs5bNbTB334E8tGhak"
            + "AUKnlr08vgqP46BBHgenboNaP9mHjgfE01cMQqZZ";

    private final ObjectMapper mapper = new ObjectMapper();
    /** 部署登记的仿真运行镜像摘要；任务声明其他摘要一律拒绝。 */
    private static final String IMAGE_DIGEST = "sha256:deadbeef";

    private PrivateKey signingKey;
    private TeeRuntimeService service;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(TEST_SIGNER_KEY_B64)));
        TeeIdentityRegistry registry = new TeeIdentityRegistry(mapper, "/dev/null", "/dev/null") {
            @Override
            public String taskSigningCertificate(String kid) {
                if (!KID.equals(kid)) {
                    throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "未知 kid");
                }
                return TEST_SIGNER_CERT_B64;
            }

            @Override
            public void requireRuntimeImageDigest(String digest) {
                if (!IMAGE_DIGEST.equals(digest)) {
                    throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "镜像摘要未登记");
                }
            }
        };
        service = new TeeRuntimeService(null, null, null, null, null, registry, null, mapper);
    }

    private String jws(String kid, String alg, Map<String, Object> payloadOverrides) throws Exception {
        Instant now = Instant.now();
        Map<String, Object> payload = new java.util.LinkedHashMap<>(Map.ofEntries(
                Map.entry("contractVersion", TeeContract.VERSION),
                Map.entry("taskId", "task-1"),
                Map.entry("requestId", "req-1"),
                Map.entry("issuer", "tee-a-center"),
                Map.entry("audience", "tee-a-runtime"),
                Map.entry("sandboxId", "sandbox-1"),
                Map.entry("operatorId", "ml.xgboost"),
                Map.entry("columns", List.of("age", "income")),
                Map.entry("inputs", List.of()),
                Map.entry("program", Map.of("kind", "BUILTIN", "sha256", "abc", "parameters", "{}")),
                Map.entry("issuedAt", now.toString()),
                Map.entry("expiresAt", now.plusSeconds(120).toString()),
                Map.entry("nonce", "nonce-1"),
                Map.entry("outputPolicy", Map.of("reportKinds", List.of("EVALUATION_METRICS"),
                        "encryptData", true, "encryptModel", true, "exportRequiresAllContributors", true)),
                Map.entry("runtimeImageDigest", "sha256:deadbeef")));
        payload.putAll(payloadOverrides);
        String header = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(Map.of("alg", alg, "typ", "JWS", "kid", kid)));
        String body = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(payload));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey);
        signature.update((header + "." + body).getBytes(StandardCharsets.US_ASCII));
        return header + "." + body + "." + TeeCrypto.encodeUrl(signature.sign());
    }

    @Test
    void validTaskIsAccepted() throws Exception {
        TeeTaskSpec task = service.verify(jws(KID, "RS256", Map.of()));
        assertEquals("task-1", task.taskId());
        assertEquals(List.of("age", "income"), task.columns());
        assertEquals("ml.xgboost", task.operatorId());
    }

    @Test
    void unknownKidIsRejected() throws Exception {
        String compact = jws("other-kid", "RS256", Map.of());
        assertEquals(TeeContract.Error.TASK_SIGNATURE_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void nonRs256IsRejected() throws Exception {
        String compact = jws(KID, "HS256", Map.of());
        assertEquals(TeeContract.Error.TASK_SIGNATURE_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void tamperedPayloadIsRejected() throws Exception {
        String[] parts = jws(KID, "RS256", Map.of()).split("\\.");
        String forged = TeeCrypto.encodeUrl(mapper.writeValueAsBytes(Map.of("taskId", "task-2")));
        String compact = parts[0] + "." + forged + "." + parts[2];
        assertEquals(TeeContract.Error.TASK_SIGNATURE_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void expiredTaskIsRejected() throws Exception {
        Instant past = Instant.now().minusSeconds(600);
        String compact = jws(KID, "RS256", Map.of("issuedAt", past.toString(),
                "expiresAt", past.plusSeconds(60).toString()));
        assertEquals(TeeContract.Error.TASK_EXPIRED,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void lifetimeBeyondContractLimitIsRejected() throws Exception {
        Instant now = Instant.now();
        String compact = jws(KID, "RS256", Map.of("issuedAt", now.toString(),
                "expiresAt", now.plusSeconds(TeeContract.MAX_TASK_LIFETIME_SECONDS + 60).toString()));
        assertEquals(TeeContract.Error.CONTRACT_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void outputPolicyMustKeepContractFixedValues() throws Exception {
        String compact = jws(KID, "RS256", Map.of("outputPolicy",
                Map.of("reportKinds", List.of("EVALUATION_METRICS"), "encryptData", false,
                        "encryptModel", true, "exportRequiresAllContributors", true)));
        assertEquals(TeeContract.Error.CONTRACT_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void wildcardColumnsInTaskAreRejected() throws Exception {
        String compact = jws(KID, "RS256", Map.of("columns", List.of("*")));
        assertEquals(TeeContract.Error.POLICY_DENIED,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void unregisteredRuntimeImageDigestIsRejected() throws Exception {
        String compact = jws(KID, "RS256", Map.of("runtimeImageDigest", "sha256:0000"));
        assertEquals(TeeContract.Error.TASK_SIGNATURE_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void builtinProgramCarryingObjectIsRejected() throws Exception {
        String compact = jws(KID, "RS256", Map.of("program",
                Map.of("kind", "BUILTIN", "objectId", "obj-1", "sha256", "abc", "parameters", "{}")));
        assertEquals(TeeContract.Error.CONTRACT_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void nonBuiltinProgramWithoutObjectIsRejected() throws Exception {
        String compact = jws(KID, "RS256", Map.of("program",
                Map.of("kind", "PYTHON", "sha256", "abc", "parameters", "{}")));
        assertEquals(TeeContract.Error.CONTRACT_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }

    @Test
    void unknownProgramKindIsRejected() throws Exception {
        String compact = jws(KID, "RS256", Map.of("program",
                Map.of("kind", "SHELL", "objectId", "obj-1", "sha256", "abc", "parameters", "{}")));
        assertEquals(TeeContract.Error.CONTRACT_INVALID,
                assertThrows(TeeException.class, () -> service.verify(compact)).error());
    }
}
