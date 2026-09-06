package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.ConfidentialModelService;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Unified ciphertext-only model registry for local weights and OpenAI-compatible endpoints. */
@RestController
@RequestMapping("/api/v1alpha1/confidential-models")
public class ConfidentialModelController implements CryptoApi {
    private final ConfidentialModelService service;

    public ConfidentialModelController(ConfidentialModelService service) {
        this.service = service;
    }

    @GetMapping("/capabilities")
    public SecretPadResponse<Map<String, Object>> capabilities() {
        return SecretPadResponse.success(service.capabilities());
    }

    @GetMapping
    public SecretPadResponse<List<Map<String, Object>>> models() {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.models(owner()));
    }

    /** Platform runtime view: no model package, plaintext or credential fields. */
    @GetMapping("/runtime-instances")
    public SecretPadResponse<List<Map<String, Object>>> runtimeInstances() {
        requireRole("CENTER");
        return SecretPadResponse.success(service.runtimeInstances());
    }

    @GetMapping("/{modelId}")
    public SecretPadResponse<Map<String, Object>> model(@PathVariable String modelId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.modelDetail(owner(), modelId));
    }

    @PostMapping("/weight-upload-sessions")
    public SecretPadResponse<Map<String, Object>> uploadSession(
            @RequestBody ConfidentialModelService.UploadSessionRequest request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.createUploadSession(owner(), request));
    }

    @PostMapping(value = "/weight-upload-sessions/{sessionId}/chunks", consumes = "application/octet-stream")
    public SecretPadResponse<Map<String, Object>> uploadChunk(@PathVariable String sessionId,
            @RequestParam int index, @RequestHeader("X-Cipher-SHA256") String cipherHash,
            @RequestBody byte[] ciphertext) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.uploadChunk(owner(), sessionId, index, ciphertext, cipherHash));
    }

    @PostMapping("/weight-versions")
    public SecretPadResponse<Map<String, Object>> weightVersion(
            @RequestBody ConfidentialModelService.WeightVersionRequest request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.commitWeights(owner(), request));
    }

    @PostMapping("/openai-compatible-versions")
    public SecretPadResponse<Map<String, Object>> openAiVersion(
            @RequestBody ConfidentialModelService.OpenAiVersionRequest request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.createOpenAiVersion(owner(), request));
    }

    @PostMapping("/{modelId}/versions/{versionId}/review")
    public SecretPadResponse<Map<String, Object>> review(@PathVariable String modelId,
            @PathVariable String versionId, @RequestBody ConfidentialModelService.ReviewRequest request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.review(owner(), modelId, versionId, request));
    }

    @PostMapping("/{modelId}/deployments")
    public SecretPadResponse<Map<String, Object>> deploy(@PathVariable String modelId,
            @RequestBody ConfidentialModelService.DeploymentRequest request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.deploy(owner(), modelId, request));
    }

    @PostMapping("/deployments/{deploymentId}/authorize")
    public SecretPadResponse<Map<String, Object>> authorize(@PathVariable String deploymentId,
            @RequestBody ConfidentialModelService.AuthorizeDeploymentRequest request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.authorizeDeployment(owner(), deploymentId, request));
    }

    @PostMapping("/deployments/{deploymentId}/offline")
    public SecretPadResponse<Map<String, Object>> offline(@PathVariable String deploymentId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.offline(owner(), deploymentId));
    }

    @PostMapping("/deployments/{deploymentId}/restart")
    public SecretPadResponse<Map<String, Object>> restart(@PathVariable String deploymentId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.restart(owner(), deploymentId));
    }

    @GetMapping("/deployments/{deploymentId}/logs")
    public SecretPadResponse<Map<String, Object>> logs(@PathVariable String deploymentId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.runtimeLogs(owner(), deploymentId));
    }

    @PostMapping("/deployments/{deploymentId}/destroy")
    public SecretPadResponse<Map<String, Object>> destroy(@PathVariable String deploymentId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.destroy(owner(), deploymentId));
    }

    @PostMapping("/deployments/{deploymentId}/api-keys")
    public SecretPadResponse<Map<String, Object>> createApiKey(@PathVariable String deploymentId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.createRuntimeApiKey(owner(), deploymentId));
    }

    @GetMapping("/deployments/{deploymentId}/api-keys")
    public SecretPadResponse<List<Map<String, Object>>> apiKeys(@PathVariable String deploymentId) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.runtimeApiKeys(owner(), deploymentId));
    }

    @PostMapping("/api-keys/{keyId}/revoke")
    public SecretPadResponse<Void> revokeApiKey(@PathVariable String keyId) {
        requireRole("CLIENT");
        service.revokeRuntimeApiKey(owner(), keyId);
        return SecretPadResponse.success();
    }

    @PostMapping("/deployments/{deploymentId}/chat/completions")
    public SecretPadResponse<com.fasterxml.jackson.databind.JsonNode> runtimeChat(
            @PathVariable String deploymentId, @RequestBody com.fasterxml.jackson.databind.JsonNode request) {
        requireRole("CLIENT");
        return SecretPadResponse.success(service.runtimeChatForOwner(owner(), deploymentId, request));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }

    // 客户模型管理与运行实例运维都在中心端完成，按本实例声明的端身份统一放行。
    private static void requireRole(String expected) {
        String actual = UserContext.getUser().getEndRole();
        if (!"CLIENT".equals(actual) && !"CENTER".equals(actual)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED, "当前登录身份无权执行该操作");
        }
    }
}
