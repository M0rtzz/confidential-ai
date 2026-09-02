/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.dev;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.tee.TeeCrypto;
import org.secretflow.secretpad.web.service.tee.TeeTaskSpec;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P6 任务签名输出必须是确定性的 RS256 Compact JWS。 */
class TeeDevTaskDispatcherTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void compactJwsContainsCompleteTaskAndUsesUnpaddedBase64Url() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        TeeTaskSpec task = task();

        String first = TeeDevTaskDispatcher.compactJws(mapper, task, keyPair.getPrivate(), "center-1");
        String second = TeeDevTaskDispatcher.compactJws(mapper, task, keyPair.getPrivate(), "center-1");
        assertEquals(first, second);
        String[] parts = first.split("\\.");
        assertEquals(3, parts.length);
        assertFalse(parts[0].contains("="));
        assertFalse(parts[1].contains("="));
        assertFalse(parts[2].contains("="));

        JsonNode header = mapper.readTree(TeeCrypto.decodeUrl(parts[0]));
        JsonNode payload = mapper.readTree(TeeCrypto.decodeUrl(parts[1]));
        assertEquals("RS256", header.path("alg").asText());
        assertEquals("JWS", header.path("typ").asText());
        assertEquals("center-1", header.path("kid").asText());
        assertEquals("object-1", payload.path("inputs").get(0).path("objectId").asText());
        assertEquals("sha256:runtime", payload.path("runtimeImageDigest").asText());
        assertEquals("SQL", payload.path("program").path("kind").asText());
        assertEquals("input_table", payload.path("program").path("parameters")
                .path("input_table").asText());

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(TeeCrypto.decodeUrl(parts[2])));
    }

    @Test
    void sqlInputTableIsBoundToP5RuntimeInput() {
        assertEquals("WITH \"src\" AS (SELECT * FROM input_0) SELECT age FROM src",
                TeeDevTaskDispatcher.adaptSql("SELECT age FROM src", "src"));
        assertEquals("WITH \"mounted_table\" AS (SELECT * FROM input_0), c AS (SELECT 1) SELECT * FROM mounted_table",
                TeeDevTaskDispatcher.adaptSql(
                        "WITH c AS (SELECT 1) SELECT * FROM mounted_table", "mounted_table"));
    }

    private static TeeTaskSpec task() {
        return new TeeTaskSpec("tee-contract/1.0", "task-1", "request-1", "center",
                "tee-a-runtime", "sandbox-1", "sql.query", List.of("age"),
                List.of(new TeeTaskSpec.Input("asset-1", 1, "key-1", 1, "policy-1", 1,
                        "object-1", "cipher-sha", 32)),
                new TeeTaskSpec.Program("SQL", "program-1", "program-sha",
                        Map.of("input_table", "input_table")),
                "2026-09-02T00:00:00Z", "2026-09-02T00:04:00Z", "nonce-1",
                new TeeTaskSpec.OutputPolicy(List.of(), true, true, true),
                "sha256:runtime");
    }
}
