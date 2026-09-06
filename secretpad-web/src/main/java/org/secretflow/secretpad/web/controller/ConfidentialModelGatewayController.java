package org.secretflow.secretpad.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import org.secretflow.secretpad.web.service.crypto.ConfidentialModelService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** OpenAI-compatible public gateway. Authentication is deployment-scoped Bearer API Key. */
@RestController
@RequestMapping("/model-api/v1")
public class ConfidentialModelGatewayController {
    private final ConfidentialModelService service;

    public ConfidentialModelGatewayController(ConfidentialModelService service) {
        this.service = service;
    }

    @PostMapping("/chat/completions")
    public JsonNode chat(@RequestHeader(value = "Authorization", required = false) String authorization,
                         @RequestBody JsonNode request) {
        return service.invokeRuntimeApi(authorization, request);
    }
}
