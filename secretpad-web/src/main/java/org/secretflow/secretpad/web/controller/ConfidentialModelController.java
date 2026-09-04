package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.ConfidentialModelService;
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
        return SecretPadResponse.success(service.models(owner()));
    }

    @GetMapping("/{modelId}")
    public SecretPadResponse<Map<String, Object>> model(@PathVariable String modelId) {
        return SecretPadResponse.success(service.modelDetail(owner(), modelId));
    }

    @PostMapping("/weight-upload-sessions")
    public SecretPadResponse<Map<String, Object>> uploadSession(
            @RequestBody ConfidentialModelService.UploadSessionRequest request) {
        return SecretPadResponse.success(service.createUploadSession(owner(), request));
    }

    @PostMapping(value = "/weight-upload-sessions/{sessionId}/chunks", consumes = "application/octet-stream")
    public SecretPadResponse<Map<String, Object>> uploadChunk(@PathVariable String sessionId,
            @RequestParam int index, @RequestHeader("X-Cipher-SHA256") String cipherHash,
            @RequestBody byte[] ciphertext) {
        return SecretPadResponse.success(service.uploadChunk(owner(), sessionId, index, ciphertext, cipherHash));
    }

    @PostMapping("/weight-versions")
    public SecretPadResponse<Map<String, Object>> weightVersion(
            @RequestBody ConfidentialModelService.WeightVersionRequest request) {
        return SecretPadResponse.success(service.commitWeights(owner(), request));
    }

    @PostMapping("/openai-compatible-versions")
    public SecretPadResponse<Map<String, Object>> openAiVersion(
            @RequestBody ConfidentialModelService.OpenAiVersionRequest request) {
        return SecretPadResponse.success(service.createOpenAiVersion(owner(), request));
    }

    @PostMapping("/{modelId}/versions/{versionId}/review")
    public SecretPadResponse<Map<String, Object>> review(@PathVariable String modelId,
            @PathVariable String versionId, @RequestBody ConfidentialModelService.ReviewRequest request) {
        return SecretPadResponse.success(service.review(owner(), modelId, versionId, request));
    }

    @PostMapping("/{modelId}/deployments")
    public SecretPadResponse<Map<String, Object>> deploy(@PathVariable String modelId,
            @RequestBody ConfidentialModelService.DeploymentRequest request) {
        return SecretPadResponse.success(service.deploy(owner(), modelId, request));
    }

    @PostMapping("/deployments/{deploymentId}/authorize")
    public SecretPadResponse<Map<String, Object>> authorize(@PathVariable String deploymentId,
            @RequestBody ConfidentialModelService.AuthorizeDeploymentRequest request) {
        return SecretPadResponse.success(service.authorizeDeployment(owner(), deploymentId, request));
    }

    @PostMapping("/deployments/{deploymentId}/offline")
    public SecretPadResponse<Map<String, Object>> offline(@PathVariable String deploymentId) {
        return SecretPadResponse.success(service.offline(owner(), deploymentId));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
