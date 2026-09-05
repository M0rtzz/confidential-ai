package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.ConfidentialAssetService;
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

/** Authenticated API for ciphertext assets, approval requests and managed usage. */
@RestController
@RequestMapping("/api/v1alpha1")
public class ConfidentialAssetController implements CryptoApi {
    private final ConfidentialAssetService service;

    public ConfidentialAssetController(ConfidentialAssetService service) {
        this.service = service;
    }

    @PostMapping("/confidential-assets/upload-sessions")
    public SecretPadResponse<Map<String, Object>> createUpload(
            @RequestBody ConfidentialAssetService.CreateUploadRequest request) {
        return SecretPadResponse.success(service.createUpload(owner(), request));
    }

    @PostMapping("/confidential-assets/generate-data")
    public SecretPadResponse<Map<String, Object>> generateData(
            @RequestBody ConfidentialAssetService.GenerateDataRequest request) {
        return SecretPadResponse.success(service.generateData(owner(), request));
    }

    @PostMapping(value = "/confidential-assets/upload-sessions/{id}/chunks",
            consumes = "application/octet-stream")
    public SecretPadResponse<Map<String, Object>> uploadChunk(@PathVariable String id,
            @RequestParam int index, @RequestHeader("X-Cipher-SHA256") String hash,
            @RequestBody byte[] ciphertext) {
        return SecretPadResponse.success(service.uploadChunk(owner(), id, index, ciphertext, hash));
    }

    @PostMapping("/confidential-assets/upload-sessions/{id}/commit")
    public SecretPadResponse<Map<String, Object>> commit(@PathVariable String id,
            @RequestBody ConfidentialAssetService.CommitRequest request) {
        return SecretPadResponse.success(service.commit(owner(), id, request));
    }

    @GetMapping("/confidential-assets")
    public SecretPadResponse<List<Map<String, Object>>> assets(
            @RequestParam(required = false) String assetType) {
        return SecretPadResponse.success(service.list(owner(), assetType));
    }

    @GetMapping("/confidential-assets/{id}")
    public SecretPadResponse<Map<String, Object>> asset(@PathVariable String id) {
        return SecretPadResponse.success(service.asset(owner(), id));
    }

    @GetMapping("/confidential-assets/{id}/ciphertext")
    public SecretPadResponse<Map<String, Object>> ciphertext(@PathVariable String id) {
        return SecretPadResponse.success(service.ciphertext(owner(), id));
    }

    @PostMapping("/confidential-assets/{id}/preview-sessions")
    public SecretPadResponse<Map<String, Object>> preview(@PathVariable String id) {
        return SecretPadResponse.success(service.previewSession(owner(), id));
    }

    @PostMapping("/confidential-use-requests")
    public SecretPadResponse<Map<String, Object>> requestUse(
            @RequestBody ConfidentialAssetService.UseRequest request) {
        return SecretPadResponse.success(service.requestUse(owner(), request));
    }

    @PostMapping("/confidential-use-requests/{id}/decision")
    public SecretPadResponse<Map<String, Object>> decide(@PathVariable String id,
            @RequestBody ConfidentialAssetService.DecisionRequest request) {
        return SecretPadResponse.success(service.decide(owner(), id, request));
    }

    @GetMapping("/confidential-assets/{id}/usage-records")
    public SecretPadResponse<List<Map<String, Object>>> usage(@PathVariable String id) {
        return SecretPadResponse.success(service.usage(owner(), id));
    }

    @PostMapping("/confidential-executions/authorize")
    public SecretPadResponse<Map<String, Object>> authorize(
            @RequestBody ConfidentialAssetService.GatewayRequest request) {
        return SecretPadResponse.success(service.authorize(owner(), request));
    }

    @PostMapping("/confidential-executions/grants/consume")
    public SecretPadResponse<Map<String, Object>> consumeGrant(
            @RequestBody ConfidentialAssetService.ConsumeGrantRequest request) {
        return SecretPadResponse.success(service.consumeGrant(owner(), request));
    }

    @PostMapping("/confidential-executions/protocol-validation")
    public SecretPadResponse<Map<String, Object>> protocolValidation(
            @RequestBody ConfidentialAssetService.ProtocolAuthorizationRequest request) {
        return SecretPadResponse.success(service.validateAuthorizationProtocol(owner(), request));
    }

    @PostMapping("/confidential-executions/{id}/events")
    public SecretPadResponse<Map<String, Object>> executionEvent(@PathVariable String id,
            @RequestBody ConfidentialAssetService.ExecutionEventRequest request) {
        return SecretPadResponse.success(service.executionEvent(owner(), id, request));
    }

    @PostMapping("/confidential-executions/{id}/outputs")
    public SecretPadResponse<Map<String, Object>> output(@PathVariable String id,
            @RequestBody ConfidentialAssetService.ExecutionOutputRequest request) {
        return SecretPadResponse.success(service.registerOutput(owner(), id, request));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
