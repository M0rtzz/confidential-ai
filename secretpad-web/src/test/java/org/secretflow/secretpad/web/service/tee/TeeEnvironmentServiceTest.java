package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/** 验证未知状态、陈旧检测与密钥服务故障不会被报告为可信就绪。 */
class TeeEnvironmentServiceTest {
    @TempDir Path root;

    private Path snapshot(Instant time, boolean sgx) throws Exception {
        Path path = root.resolve("hardware.json");
        Files.writeString(path, "{\"checkedAt\":\"" + time + "\",\"detectorOk\":true,"
                + "\"deviceChecks\":{\"sgx\":" + sgx + ",\"tdx\":false,\"csv\":false}}");
        return path;
    }

    private TeeEnvironmentService service(Path path, String probe) {
        return new TeeEnvironmentService(new ObjectMapper(), path.toString(), probe, 3600);
    }

    @Test void missingSnapshotFailsClosed() {
        var result = service(root.resolve("missing"), "").environment();
        assertNull(result.checkedAt());
        assertFalse(result.realModeReady());
        assertFalse(result.keyServiceReachable());
        assertTrue(result.blockers().contains("HARDWARE_CHECK_UNAVAILABLE"));
    }

    @Test void frozenFieldsRemainPresentWhenSnapshotIsMissing() throws Exception {
        var result = service(root.resolve("missing"), "").environment();
        String json = org.secretflow.secretpad.common.util.JsonUtils.toJSONString(result);
        var fields = new ObjectMapper().readTree(json);
        var names = new java.util.HashSet<String>();
        fields.fieldNames().forEachRemaining(names::add);
        assertEquals(java.util.Set.of("contractVersion", "runtimeMode", "checkedAt", "hardwareDetected",
                "deviceChecks", "attestationVerified", "keyServiceReachable", "realModeReady", "blockers"), names);
        assertTrue(fields.has("checkedAt"));
        assertTrue(fields.get("checkedAt").isNull());
    }

    @Test void hardwareDoesNotProveAttestation() throws Exception {
        var result = service(snapshot(Instant.now(), true), "").environment();
        assertTrue(result.hardwareDetected());
        assertFalse(result.attestationVerified());
        assertFalse(result.realModeReady());
        assertEquals("SIMULATION", result.runtimeMode());
    }

    @Test void staleAndFutureSnapshotsAreFlagged() throws Exception {
        for (Instant time : new Instant[]{Instant.now().minusSeconds(7200), Instant.now().plusSeconds(90)}) {
            assertTrue(service(snapshot(time, false), "").environment().blockers().contains("HARDWARE_CHECK_STALE"));
        }
    }

    @Test void malformedDeviceResultsAreNotAccepted() throws Exception {
        Path path = snapshot(Instant.now(), false);
        Files.writeString(path, "{\"checkedAt\":\"" + Instant.now() + "\",\"deviceChecks\":{\"sgx\":\"yes\"}}");
        assertTrue(service(path, "").environment().blockers().contains("HARDWARE_CHECK_UNAVAILABLE"));
    }

    @Test void onlyFreshNativeAuthenticatedProbeCounts() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String[] body = {""};
        server.createContext("/health", exchange -> {
            byte[] bytes = body[0].getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var output = exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start();
        try {
            var service = service(snapshot(Instant.now(), false), "http://127.0.0.1:" + server.getAddress().getPort() + "/health");
            for (String method : new String[]{"TCP", "CAPSULE_GET_RA_CERT_MTLS"}) {
                body[0] = "{\"checkedAt\":\"" + Instant.now() + "\",\"reachable\":true,\"method\":\"" + method + "\"}";
                assertEquals(method.equals("CAPSULE_GET_RA_CERT_MTLS"), service.environment().keyServiceReachable());
            }
            body[0] = "{\"checkedAt\":\"" + Instant.now().minusSeconds(60) + "\",\"reachable\":true,\"method\":\"CAPSULE_GET_RA_CERT_MTLS\"}";
            assertFalse(service.environment().keyServiceReachable());
            body[0] = "{\"checkedAt\":\"" + Instant.now() + "\",\"reachable\":\"true\",\"method\":\"CAPSULE_GET_RA_CERT_MTLS\"}";
            assertFalse(service.environment().keyServiceReachable());
            body[0] = "{}";
            assertFalse(service.environment().keyServiceReachable());
        } finally { server.stop(0); }
    }
}
