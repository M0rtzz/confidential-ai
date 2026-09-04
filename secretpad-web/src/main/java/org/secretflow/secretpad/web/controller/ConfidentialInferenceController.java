package org.secretflow.secretpad.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.ConfidentialModelService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Encrypted outer transport whose plaintext body is OpenAI chat/completions JSON. */
@RestController
@RequestMapping("/api/v1alpha1/confidential-inference")
public class ConfidentialInferenceController implements CryptoApi {
    private final ConfidentialModelService service;

    public ConfidentialInferenceController(ConfidentialModelService service) {
        this.service = service;
    }

    @PostMapping("/chat/completions")
    public SecretPadResponse<JsonNode> chatCompletions(@RequestBody JsonNode request) {
        return SecretPadResponse.success(service.infer(UserContext.getUser().getOwnerId(), request));
    }
}
