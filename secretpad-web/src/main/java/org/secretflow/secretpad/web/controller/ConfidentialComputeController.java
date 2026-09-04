package org.secretflow.secretpad.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.ConfidentialComputeService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Public control-plane API for ds-confidential/v1. */
@RestController
@RequestMapping("/api/v1alpha1/crypto")
public class ConfidentialComputeController implements CryptoApi {
    private final ConfidentialComputeService service;

    public ConfidentialComputeController(ConfidentialComputeService service) {
        this.service = service;
    }

    @PostMapping("/identities")
    public SecretPadResponse<Map<String, Object>> identity(
            @RequestBody ConfidentialComputeService.IdentityRequest request) {
        return SecretPadResponse.success(service.registerIdentity(owner(), request));
    }

    @GetMapping("/trusted-domains")
    public SecretPadResponse<List<Map<String, Object>>> domains() {
        return SecretPadResponse.success(service.domains());
    }

    @GetMapping("/trusted-domains/{domainId}")
    public SecretPadResponse<Map<String, Object>> domain(@PathVariable String domainId) {
        return SecretPadResponse.success(service.domain(domainId));
    }

    @PostMapping("/trusted-domains/{domainId}/verify")
    public SecretPadResponse<Map<String, Object>> verify(@PathVariable String domainId) {
        return SecretPadResponse.success(service.verifyDomain(owner(), domainId));
    }

    @PostMapping("/tasks")
    public SecretPadResponse<Map<String, Object>> task(
            @RequestBody ConfidentialComputeService.CreateTaskRequest request) {
        return SecretPadResponse.success(service.createTask(owner(), request));
    }

    @PostMapping("/attestation-sessions")
    public SecretPadResponse<JsonNode> attestation(
            @RequestBody ConfidentialComputeService.AttestationRequest request) {
        return SecretPadResponse.success(service.createAttestation(owner(), request));
    }

    @PostMapping("/grants")
    public SecretPadResponse<Map<String, Object>> grant(
            @RequestBody ConfidentialComputeService.GrantRequest request) {
        return SecretPadResponse.success(service.saveGrant(owner(), request));
    }

    public record StartRequest(String grantId) {
    }

    @PostMapping("/tasks/{taskId}/start")
    public SecretPadResponse<JsonNode> start(@PathVariable String taskId, @RequestBody StartRequest request) {
        return SecretPadResponse.success(service.start(owner(), taskId, request.grantId()));
    }

    @GetMapping("/tasks/{taskId}/outputs")
    public SecretPadResponse<JsonNode> output(@PathVariable String taskId) {
        return SecretPadResponse.success(service.output(owner(), taskId));
    }

    @GetMapping("/audit-events")
    public SecretPadResponse<List<JsonNode>> audits() {
        return SecretPadResponse.success(service.audits(owner()));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
