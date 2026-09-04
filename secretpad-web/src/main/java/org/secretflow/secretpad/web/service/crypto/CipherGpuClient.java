package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.secretflow.secretpad.web.service.tee.TeeMutualTls;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;

/** mTLS-only client for the CipherGPU data plane. */
@Component
public class CipherGpuClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(CipherGpuClient.class);

    private final ObjectMapper mapper;
    private final String baseUrl;
    private final Path certDir;
    private final boolean allowInsecureHttp;
    private volatile SSLContext sslContext;

    public CipherGpuClient(ObjectMapper mapper,
            @Value("${CIPHERGPU_URL:https://ciphergpu:9000}") String baseUrl,
            @Value("${CIPHERGPU_CLIENT_CERT_DIR:/app/ciphergpu-client}") String certDir,
            @Value("${CIPHERGPU_ALLOW_INSECURE_HTTP:false}") boolean allowInsecureHttp) {
        this.mapper = mapper;
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.certDir = Path.of(certDir);
        this.allowInsecureHttp = allowInsecureHttp;
        if (this.baseUrl.startsWith("http://") && !allowInsecureHttp) {
            throw new IllegalStateException("CipherGPU requires HTTPS unless the explicit test-only override is set");
        }
    }

    public JsonNode health() {
        return send("GET", "/v1/health", null);
    }

    public JsonNode createSession(Object request) {
        return send("POST", "/v1/attestation/sessions", request);
    }

    public JsonNode execute(Object request) {
        return send("POST", "/v1/executions", request);
    }

    public JsonNode registerModelDeployment(Object request) {
        return send("POST", "/v1/model-deployments", request);
    }

    public JsonNode offlineModelDeployment(String deploymentId) {
        return send("POST", "/v1/model-deployments/" + deploymentId + "/offline", java.util.Map.of());
    }

    public JsonNode infer(Object request) {
        return send("POST", "/v1/confidential-inference/chat/completions", request, Duration.ofSeconds(310));
    }

    private JsonNode send(String method, String path, Object payload) {
        return send(method, path, payload, Duration.ofSeconds(30));
    }

    private JsonNode send(String method, String path, Object payload, Duration timeout) {
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(timeout).header("Content-Type", "application/json");
            if ("GET".equals(method)) {
                request.GET();
            } else {
                request.POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(payload)));
            }
            HttpResponse<String> response = client().send(request.build(), HttpResponse.BodyHandlers.ofString());
            JsonNode body = mapper.readTree(response.body());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                        body.path("error").path("code").asText("CIPHERGPU_REJECTED"));
            }
            return body;
        } catch (TeeException rejected) {
            throw rejected;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "CipherGPU 调用被中断");
        } catch (Exception failure) {
            LOGGER.warn("CipherGPU {} {} transport failed: {}: {}", method, path,
                    failure.getClass().getSimpleName(), failure.getMessage());
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "CipherGPU mTLS 通道不可用");
        }
    }

    private HttpClient client() throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5));
        if (baseUrl.startsWith("https://")) {
            builder.sslContext(tlsContext());
        }
        // Uvicorn closes idle HTTP/1.1 connections after a short keep-alive window. A fresh
        // client prevents a later POST from racing with a stale pooled mTLS connection.
        return builder.build();
    }

    private SSLContext tlsContext() throws Exception {
        SSLContext result = sslContext;
        if (result != null) {
            return result;
        }
        synchronized (this) {
            if (sslContext == null) {
                sslContext = TeeMutualTls.context(certDir, "ciphergpu-control-plane");
            }
            return sslContext;
        }
    }
}
