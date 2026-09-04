package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ConfidentialModelServiceTest {
    private JdbcTemplate jdbc;
    private MinioAssetStorage storage;
    private ConfidentialMetadataStore audit;
    private ConfidentialComputeService compute;
    private CipherGpuClient cipherGpu;
    private ConfidentialModelService service;

    @BeforeEach
    void setUp() {
        jdbc = mock(JdbcTemplate.class);
        storage = mock(MinioAssetStorage.class);
        audit = mock(ConfidentialMetadataStore.class);
        compute = mock(ConfidentialComputeService.class);
        cipherGpu = mock(CipherGpuClient.class);
        service = new ConfidentialModelService(jdbc, new ObjectMapper(), storage, audit, compute, cipherGpu);
    }

    @Test
    void publishesExactlyFiveAuthenticatedContentAlgorithms() {
        Map<String, Object> capabilities = service.capabilities();
        assertEquals("AES-256-GCM", capabilities.get("defaultAlgorithm"));
        List<?> algorithms = (List<?>) capabilities.get("contentEncryptionAlgorithms");
        assertEquals(5, algorithms.size());
        assertTrue(algorithms.toString().contains("XCHACHA20-POLY1305"));
        assertTrue(algorithms.toString().contains("AES-256-SIV"));
    }

    @Test
    void remoteModelRejectsNonHttpsPrivateAndMetadataAddressesBeforeStorage() {
        for (String baseUrl : List.of(
                "http://example.com/v1", "https://127.0.0.1/v1", "https://169.254.169.254/v1")) {
            assertThrows(TeeException.class, () -> service.createOpenAiVersion("owner-1",
                    openAiRequest(baseUrl, encryptedCredential())));
        }
        verifyNoInteractions(jdbc, storage, audit, compute, cipherGpu);
    }

    @Test
    void plaintextCredentialFieldsAreRejected() {
        ObjectNode credential = encryptedCredential();
        credential.put("apiKey", "must-not-enter-control-plane");
        assertThrows(TeeException.class, () -> service.createOpenAiVersion("owner-1",
                openAiRequest("https://8.8.8.8/v1", credential)));
        verifyNoInteractions(jdbc, storage, audit, compute, cipherGpu);
    }

    @Test
    void localWeightDeploymentUsesConfiguredVllmServedModelName() {
        Map<String, Object> version = new LinkedHashMap<>();
        version.put("status", "APPROVED");
        version.put("source_type", "LOCAL_WEIGHTS");
        version.put("runtime_config_json", "{\"servedModelName\":\"deepseek-llm-7b-chat\"}");
        when(jdbc.queryForMap(contains("ds_confidential_model_version"),
                eq("owner-1"), eq("model-1"), eq("version-1"))).thenReturn(version);
        when(cipherGpu.registerModelDeployment(any())).thenReturn(new ObjectMapper().createObjectNode()
                .put("status", "AUTHORIZATION_REQUIRED"));
        when(jdbc.queryForMap(contains("ds_model_deployment"), eq("owner-1"), anyString()))
                .thenAnswer(invocation -> Map.of(
                        "deployment_id", invocation.getArgument(2),
                        "version_id", "version-1",
                        "deployment_type", "LOCAL_WEIGHTS",
                        "security_profile", "a100-sim",
                        "status", "AUTHORIZATION_REQUIRED",
                        "endpoint_path", "/api/v1alpha1/confidential-inference/chat/completions"));

        service.deploy("owner-1", "model-1", new ConfidentialModelService.DeploymentRequest("version-1"));

        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Map<String, Object>> registration =
                org.mockito.ArgumentCaptor.forClass(Map.class);
        verify(cipherGpu).registerModelDeployment(registration.capture());
        assertEquals("deepseek-llm-7b-chat", registration.getValue().get("upstreamModelId"));
    }

    private ConfidentialModelService.OpenAiVersionRequest openAiRequest(String baseUrl, ObjectNode credential) {
        return new ConfidentialModelService.OpenAiVersionRequest(null, "Remote A", "", "a100-domain-a",
                baseUrl, "model-a", credential, new ObjectMapper().createObjectNode(), "controlled-sim-ok");
    }

    private ObjectNode encryptedCredential() {
        ObjectNode value = new ObjectMapper().createObjectNode();
        value.put("format", "ds-envelope/v1");
        value.put("algorithm", "AES-256-GCM");
        value.put("ciphertext", "ciphertext-only");
        value.put("nonce", "nonce");
        value.put("cipherHash", "a".repeat(64));
        value.put("publicKeyId", "domain-key-v1");
        value.putObject("keyEnvelope").put("ciphertext", "sealed-dek");
        return value;
    }
}
