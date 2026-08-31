package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** 读取宿主机检测快照和独立探测器结果，不接触数据密钥或 Docker socket。 */
@Service
public class TeeEnvironmentService {
    public static final String CONTRACT_VERSION = "tee-contract/1.0";
    private final ObjectMapper mapper;
    private final Path snapshotPath;
    private final String probeUrl;
    private final long snapshotMaxAgeSeconds;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    public TeeEnvironmentService(ObjectMapper mapper,
            @Value("${secretpad.tee-foundation.hardware-snapshot:/app/tee-status/hardware.json}") String snapshot,
            @Value("${TEE_FOUNDATION_PROBE_URL:}") String probeUrl,
            @Value("${secretpad.tee-foundation.snapshot-max-age-seconds:86400}") long maxAge) {
        this.mapper = mapper;
        this.snapshotPath = Path.of(snapshot);
        this.probeUrl = probeUrl;
        this.snapshotMaxAgeSeconds = maxAge;
    }

    public record DeviceChecks(boolean sgx, boolean tdx, boolean csv) { }
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Environment(String contractVersion, String runtimeMode, @JsonFormat(shape = JsonFormat.Shape.STRING) Instant checkedAt,
                              boolean hardwareDetected, DeviceChecks deviceChecks,
                              boolean attestationVerified, boolean keyServiceReachable,
                              boolean realModeReady, List<String> blockers) { }

    public Environment environment() {
        List<String> blockers = new ArrayList<>();
        DeviceChecks checks = new DeviceChecks(false, false, false);
        Instant checkedAt = null;
        try {
            if (Files.size(snapshotPath) > 16384) {
                throw new IllegalArgumentException("检测快照过大");
            }
            JsonNode snapshot = mapper.readTree(Files.readString(snapshotPath));
            Instant observed = Instant.parse(snapshot.required("checkedAt").asText());
            JsonNode devices = snapshot.required("deviceChecks");
            for (String device : List.of("sgx", "tdx", "csv")) {
                if (!devices.required(device).isBoolean()) {
                    throw new IllegalArgumentException("检测结果类型无效");
                }
            }
            checks = new DeviceChecks(devices.get("sgx").booleanValue(),
                    devices.get("tdx").booleanValue(), devices.get("csv").booleanValue());
            checkedAt = observed;
            long age = Duration.between(observed, Instant.now()).getSeconds();
            if (age < -30 || age > snapshotMaxAgeSeconds) {
                blockers.add("HARDWARE_CHECK_STALE");
            }
            if (!snapshot.path("detectorOk").isBoolean() || !snapshot.path("detectorOk").booleanValue()) {
                blockers.add("HARDWARE_CHECK_FAILED");
            }
        } catch (Exception ignored) {
            blockers.add("HARDWARE_CHECK_UNAVAILABLE");
        }
        boolean reachable = probeReachable();
        if (!reachable) {
            blockers.add("KEY_SERVICE_UNAVAILABLE");
        }
        blockers.add("NO_VERIFIED_HARDWARE_RUNTIME");
        return new Environment(CONTRACT_VERSION, "SIMULATION", checkedAt,
                checks.sgx() || checks.tdx() || checks.csv(), checks, false,
                reachable, false, List.copyOf(blockers));
    }

    private boolean probeReachable() {
        if (probeUrl.isBlank()) {
            return false;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(probeUrl))
                    .timeout(Duration.ofSeconds(3)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200 || response.body().length() > 16384) {
                return false;
            }
            JsonNode result = mapper.readTree(response.body());
            long age = Duration.between(Instant.parse(result.required("checkedAt").asText()), Instant.now()).getSeconds();
            return age >= -30 && age <= 30 && result.path("reachable").isBoolean() && result.path("reachable").booleanValue()
                    && "CAPSULE_GET_RA_CERT_MTLS".equals(result.path("method").asText());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception ignored) {
            return false;
        }
    }
}
