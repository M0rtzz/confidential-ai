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
    private static final String TEST_SIGNER_CERT_B64 = TeeTestMaterial.CERTIFICATE_B64;

    private static final String TEST_SIGNER_KEY_B64 = TeeTestMaterial.PRIVATE_KEY_B64;

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
