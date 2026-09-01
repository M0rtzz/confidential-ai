/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * 中心密钥适配服务的客户端。
 *
 * <p>平台不实现 Capsule Manager 的原生协议，只通过双向 TLS 调用适配服务；
 * 数据密钥的明文从不进入平台进程，出站结果一律是接收者证书公钥密封后的信封。
 */
@Component
public class KeyAdapterClient {

    private final ObjectMapper mapper;
    private final String baseUrl;
    private final Path certDir;
    private volatile HttpClient client;

    public KeyAdapterClient(ObjectMapper mapper,
            @Value("${TEE_KEY_ADAPTER_URL:}") String baseUrl,
            @Value("${TEE_KEY_ADAPTER_CERT_DIR:/app/tee-adapter-client}") String certDir) {
        this.mapper = mapper;
        this.baseUrl = baseUrl;
        this.certDir = Path.of(certDir);
    }

    public boolean configured() {
        return !baseUrl.isBlank();
    }

    /** 适配服务的业务拒绝以 errorCode 返回，映射为契约错误码；传输失败一律视为服务不可用。 */
    public JsonNode call(String path, Map<String, Object> payload) {
        if (!configured()) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "未配置密钥适配服务");
        }
        HttpResponse<String> response;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(20))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)))
                    .build();
            response = client().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "密钥服务调用被中断");
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "密钥服务不可达");
        }
        if (response.statusCode() != 200) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "密钥服务返回异常状态");
        }
        JsonNode body;
        try {
            body = mapper.readTree(response.body());
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "密钥服务响应无法解析");
        }
        if (body.hasNonNull("errorCode")) {
            throw TeeException.of(translate(body.get("errorCode").asText()), "密钥服务拒绝该请求");
        }
        return body;
    }

    public boolean reachable() {
        if (!configured()) {
            return false;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/v1/health"))
                    .timeout(Duration.ofSeconds(5)).GET().build();
            HttpResponse<String> response = client().send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200
                    && mapper.readTree(response.body()).path("keyServiceReachable").asBoolean(false);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static TeeContract.Error translate(String errorCode) {
        try {
            return TeeContract.Error.valueOf(errorCode);
        } catch (IllegalArgumentException unknown) {
            return TeeContract.Error.KEY_SERVICE_UNAVAILABLE;
        }
    }

    private HttpClient client() throws Exception {
        HttpClient existing = client;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (client == null) {
                client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                        .sslContext(sslContext()).build();
            }
            return client;
        }
    }

    /** 客户端证书与信任链只从挂载目录读取；不接受配置项传入证书内容。 */
    private SSLContext sslContext() throws Exception {
        return TeeMutualTls.context(certDir, "adapter-client");
    }
}
