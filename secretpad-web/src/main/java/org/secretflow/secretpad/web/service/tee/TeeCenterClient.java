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

/**
 * 客户端实例调用中心端契约接口的通道。
 *
 * <p>方案第 04 节第 2 步要求客户端不自造密钥，而是带着自己的证书向中心端申请。
 * 本通道使用独立信任域的双向 TLS：机构标识由中心端从客户端证书推导，
 * 请求体不携带任何自报身份，客户端也无法用它访问中心的会话接口。
 */
@Component
public class TeeCenterClient {

    private final ObjectMapper mapper;
    private final String baseUrl;
    private final Path certDir;
    private volatile HttpClient client;

    public TeeCenterClient(ObjectMapper mapper,
            @Value("${TEE_CONTRACT_CENTER_URL:}") String baseUrl,
            @Value("${TEE_CONTRACT_CLIENT_CERT_DIR:/app/tee-contract-client}") String certDir) {
        this.mapper = mapper;
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim();
        this.certDir = Path.of(certDir);
    }

    /** 只有未直连密钥服务的实例才配置本通道；中心端自身不经由它绕一圈。 */
    public boolean configured() {
        return !baseUrl.isBlank();
    }

    public <T> T post(String path, Object payload, Class<T> type) {
        return parse(send("POST", path, payload), type);
    }

    public <T> T get(String path, Class<T> type) {
        return parse(send("GET", path, null), type);
    }

    /** 中心端可达性；只用于环境展示，失败不抛出。 */
    public boolean reachable() {
        if (!configured()) {
            return false;
        }
        try {
            get("/keys", JsonNode.class);
            return true;
        } catch (TeeException denied) {
            // 中心端已应答并作出业务判断，通道本身可用。
            return denied.error() != TeeContract.Error.KEY_SERVICE_UNAVAILABLE;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private String send(String method, String path, Object payload) {
        if (!configured()) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "未配置中心端契约通道");
        }
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + TeeContract.PREFIX + path))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json");
            builder = "GET".equals(method) ? builder.GET()
                    : builder.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)));
            HttpResponse<String> response = client().send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端契约通道调用被中断");
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端契约通道不可达");
        }
    }

    /** 中心端的业务拒绝按契约错误码原样透传，不在客户端降级或改写。 */
    private <T> T parse(String body, Class<T> type) {
        JsonNode root;
        try {
            root = mapper.readTree(body);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端响应无法解析");
        }
        int code = root.path("status").path("code").asInt(-1);
        if (code != 0) {
            String errorCode = root.path("data").path("errorCode").asText(
                    root.path("status").path("msg").asText(""));
            throw TeeException.of(translate(errorCode), "中心端拒绝该请求");
        }
        try {
            return mapper.treeToValue(root.path("data"), type);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端响应结构不符");
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
                SSLContext context = TeeMutualTls.context(certDir, "tee-contract-client");
                client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                        .sslContext(context).build();
            }
            return client;
        }
    }
}
