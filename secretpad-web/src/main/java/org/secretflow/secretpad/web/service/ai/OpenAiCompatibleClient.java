package org.secretflow.secretpad.web.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Minimal OpenAI-compatible messages client shared by every platform AI capability. */
@Service
public class OpenAiCompatibleClient {
    private static final int MAX_RESPONSE_CHARS = 1024 * 1024;

    public record Settings(String baseUrl, String modelId, String apiKey, int configVersion) {}

    private final ObjectMapper mapper;
    private final HttpClient http;
    private final Set<String> allowedPrivateHosts;

    public OpenAiCompatibleClient(ObjectMapper mapper,
            @Value("${DATA_SANDBOX_AI_ALLOWED_HOSTS:host.docker.internal}") String allowedHosts) {
        this.mapper = mapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.allowedPrivateHosts = Arrays.stream(allowedHosts.split(","))
                .map(String::trim).filter(value -> !value.isEmpty())
                .map(value -> value.toLowerCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    }

    public String complete(Settings settings, String systemPrompt, String userPrompt) {
        try {
            String baseUrl = normalizeBaseUrl(settings.baseUrl(), allowedPrivateHosts);
            JsonNode payload = mapper.valueToTree(Map.of(
                    "model", required(settings.modelId(), "modelId"),
                    "messages", List.of(
                            Map.of("role", "system", "content", required(systemPrompt, "systemPrompt")),
                            Map.of("role", "user", "content", required(userPrompt, "userPrompt")))));
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + "/chat/completions"))
                    .timeout(Duration.ofSeconds(90))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json");
            if (settings.apiKey() != null && !settings.apiKey().isBlank()) {
                request.header("Authorization", "Bearer " + settings.apiKey().trim());
            }
            HttpResponse<String> response = http.send(
                    request.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload))).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.body() != null && response.body().length() > MAX_RESPONSE_CHARS) {
                throw invalid("模型服务响应超过 1 MiB 限制");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw invalid(safeProviderError(response.statusCode()));
            }
            String content = mapper.readTree(response.body()).path("choices").path(0)
                    .path("message").path("content").asText();
            if (content == null || content.isBlank()) throw invalid("模型服务未返回消息内容");
            return content.trim();
        } catch (TeeException failure) {
            throw failure;
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw unavailable("模型服务调用被中断");
        } catch (Exception failure) {
            throw unavailable("模型服务连接失败");
        }
    }

    public static String normalizeBaseUrl(String value, Set<String> allowedPrivateHosts) {
        try {
            URI uri = URI.create(required(value, "baseUrl").trim());
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            if (host.isBlank() || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
                throw invalid("模型 API 地址格式无效");
            }
            boolean explicitlyAllowed = allowedPrivateHosts.contains(host);
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    && !("http".equalsIgnoreCase(uri.getScheme()) && explicitlyAllowed)) {
                throw invalid("模型 API 地址必须使用 HTTPS；内网 HTTP 主机需由部署配置明确允许");
            }
            if (privateLiteral(host) && !explicitlyAllowed) {
                throw invalid("内网模型地址未列入部署允许清单");
            }
            String normalized = uri.toString();
            return normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized;
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw invalid("模型 API 地址格式无效");
        }
    }

    private static boolean privateLiteral(String host) {
        if (host.equals("localhost") || host.equals("::1") || host.startsWith("127.")
                || host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) {
            return true;
        }
        if (!host.startsWith("172.")) return false;
        String[] parts = host.split("\\.");
        if (parts.length < 2) return false;
        try {
            int second = Integer.parseInt(parts[1]);
            return second >= 16 && second <= 31;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    private static String safeProviderError(int status) {
        if (status == 401 || status == 403) return "API Key 无效或无权调用配置的模型";
        if (status == 404) return "Base URL 或 Model ID 不存在";
        if (status == 408) return "模型服务请求超时";
        if (status == 429) return "模型服务限流，请稍后重试";
        return "模型服务调用失败，HTTP " + status;
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) throw invalid(field + " 不能为空");
        return value.trim();
    }

    private static TeeException invalid(String message) {
        return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message);
    }

    private static TeeException unavailable(String message) {
        return TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, message);
    }
}
