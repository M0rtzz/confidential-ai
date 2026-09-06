package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;

import java.util.List;
import java.util.Map;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class ConfidentialComputeServiceTest {
    private ConfidentialMetadataStore store;
    private CipherGpuClient cipherGpu;
    private ConfidentialComputeService service;

    @BeforeEach
    void setUp() {
        store = mock(ConfidentialMetadataStore.class);
        cipherGpu = mock(CipherGpuClient.class);
        service = new ConfidentialComputeService(store, cipherGpu, new ObjectMapper(),
                "", "sha256:test-workload", "sha256:test-policy", "sha256:test-tls-key");
    }

    @Test
    void everyCurrentDomainIsExplicitlyA100Simulation() {
        for (Map<String, Object> domain : service.domains()) {
            assertEquals(ConfidentialContract.SIM_PROFILE, domain.get("securityProfile"));
            assertEquals(ConfidentialContract.SIM_EVIDENCE, domain.get("evidenceType"));
            assertEquals(ConfidentialContract.SIM_HARDWARE, domain.get("hardwareModel"));
            assertTrue((Boolean) domain.get("simulated"));
        }
    }

    @Test
    void productionProfileCannotRunOnA100() {
        TeeException failure = assertThrows(TeeException.class, () -> service.createTask("owner-1",
                request(ConfidentialContract.PROD_PROFILE, "controlled-sim-ok")));
        assertEquals(TeeContract.Error.REAL_MODE_UNAVAILABLE, failure.error());
        verifyNoInteractions(store, cipherGpu);
    }

    @Test
    void gpuCcAssetCannotDowngradeToSimulation() {
        TeeException failure = assertThrows(TeeException.class, () -> service.createTask("owner-1",
                request(ConfidentialContract.SIM_PROFILE, "gpu-cc")));
        assertEquals(TeeContract.Error.POLICY_DENIED, failure.error());
        verifyNoInteractions(store, cipherGpu);
    }

    @Test
    void blockedDomainFailsBeforeRuntimeContact() {
        TeeException failure = assertThrows(TeeException.class,
                () -> service.verifyDomain("owner-1", "a100-domain-c"));
        assertEquals(TeeContract.Error.POLICY_DENIED, failure.error());
        verifyNoInteractions(store, cipherGpu);
    }

    @Test
    void blockedDomainCannotCreateTask() {
        TeeException failure = assertThrows(TeeException.class,
                () -> service.createTask("owner-1", new ConfidentialComputeService.CreateTaskRequest(
                        "a100-domain-c", "infer", "builtin.digest/v1",
                        List.of("asset-1@v1"), List.of("uek-1"),
                        ConfidentialContract.SIM_PROFILE, "controlled-sim-ok")));
        assertEquals(TeeContract.Error.POLICY_DENIED, failure.error());
        verifyNoInteractions(store, cipherGpu);
    }

    @Test
    void domainResponseNeverClaimsHardwareAttestation() {
        Map<String, Object> domain = service.domain("a100-domain-a");
        assertTrue((Boolean) domain.get("simulated"));
        assertFalse(domain.containsKey("attestationVerified"));
    }

    @Test
    void attestationBindsTekTlsWorkloadPolicyAndFreshness() throws Exception {
        SignedAttestation fixture = signedAttestation(false);
        ConfidentialComputeService boundService = new ConfidentialComputeService(store, cipherGpu,
                fixture.mapper(), fixture.rootPublicKey(), "sha256:test-workload", "sha256:test-policy",
                "sha256:test-tls-key");
        when(store.task("owner-1", "task-1")).thenReturn(fixture.task());
        when(cipherGpu.createSession(any())).thenReturn(fixture.response());

        assertEquals(fixture.response(), boundService.createAttestation("owner-1",
                new ConfidentialComputeService.AttestationRequest("task-1", "nonce-1", "a100-sim")));
    }

    @Test
    void changedTekIsRejectedEvenWhenEvidenceSignatureIsValid() throws Exception {
        SignedAttestation fixture = signedAttestation(true);
        ConfidentialComputeService boundService = new ConfidentialComputeService(store, cipherGpu,
                fixture.mapper(), fixture.rootPublicKey(), "sha256:test-workload", "sha256:test-policy",
                "sha256:test-tls-key");
        when(store.task("owner-1", "task-1")).thenReturn(fixture.task());
        when(cipherGpu.createSession(any())).thenReturn(fixture.response());

        TeeException failure = assertThrows(TeeException.class, () -> boundService.createAttestation("owner-1",
                new ConfidentialComputeService.AttestationRequest("task-1", "nonce-1", "a100-sim")));
        assertEquals(TeeContract.Error.POLICY_DENIED, failure.error());
    }

    @Test
    void executionReceiptIsBoundToTaskSessionAndOutput() throws Exception {
        SignedExecution fixture = signedExecution(false);
        ConfidentialComputeService boundService = new ConfidentialComputeService(store, cipherGpu,
                fixture.mapper(), fixture.rootPublicKey(), "sha256:test-workload", "sha256:test-policy",
                "sha256:test-tls-key");
        when(store.task("owner-1", "task-1")).thenReturn(fixture.task());
        when(store.consumeGrant("owner-1", "grant-1")).thenReturn(fixture.grant());
        when(cipherGpu.execute(any())).thenReturn(fixture.response());

        assertEquals(fixture.response(), boundService.start("owner-1", "task-1", "grant-1"));
        verify(store).saveExecution("task-1", "grant-1", "session-1", fixture.response());
    }

    @Test
    void tamperedExecutionOutputIsRejectedAfterReceiptSigning() throws Exception {
        SignedExecution fixture = signedExecution(true);
        ConfidentialComputeService boundService = new ConfidentialComputeService(store, cipherGpu,
                fixture.mapper(), fixture.rootPublicKey(), "sha256:test-workload", "sha256:test-policy",
                "sha256:test-tls-key");
        when(store.task("owner-1", "task-1")).thenReturn(fixture.task());
        when(store.consumeGrant("owner-1", "grant-1")).thenReturn(fixture.grant());
        when(cipherGpu.execute(any())).thenReturn(fixture.response());

        TeeException failure = assertThrows(TeeException.class,
                () -> boundService.start("owner-1", "task-1", "grant-1"));
        assertEquals(TeeContract.Error.POLICY_DENIED, failure.error());
    }

    private static ConfidentialComputeService.CreateTaskRequest request(String profile, String requirement) {
        return new ConfidentialComputeService.CreateTaskRequest("a100-domain-a", "verify",
                "builtin.digest/v1", List.of("asset-1@v1"), List.of("uek-1"), profile, requirement);
    }

    private static SignedAttestation signedAttestation(boolean changeResponseTek) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        KeyPair signer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encodedPublicKey = signer.getPublic().getEncoded();
        String rootPublicKey = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOfRange(encodedPublicKey, encodedPublicKey.length - 32,
                        encodedPublicKey.length));
        byte[] signedTek = new byte[32];
        Arrays.fill(signedTek, (byte) 7);
        byte[] responseTek = changeResponseTek ? new byte[32] : signedTek;
        Instant now = Instant.now();
        String taskExpiry = now.plus(5, ChronoUnit.MINUTES).toString();
        String evidenceExpiry = now.plus(4, ChronoUnit.MINUTES).toString();
        ObjectNode spec = mapper.createObjectNode().put("domainId", "a100-domain-a");
        ConfidentialMetadataStore.TaskRow task = new ConfidentialMetadataStore.TaskRow(spec, "task-digest",
                "a100-sim", "controlled-sim-ok", taskExpiry);
        ObjectNode evidence = mapper.createObjectNode();
        evidence.put("contractVersion", ConfidentialContract.VERSION);
        evidence.put("runtimeMode", "SIMULATION");
        evidence.put("attestationVerified", false);
        evidence.put("securityProfile", ConfidentialContract.SIM_PROFILE);
        evidence.put("evidenceType", ConfidentialContract.SIM_EVIDENCE);
        evidence.put("simulated", true);
        evidence.put("hardwareModel", ConfidentialContract.SIM_HARDWARE);
        evidence.put("clientNonce", "nonce-1");
        evidence.put("taskSpecDigest", "task-digest");
        evidence.put("teeEphemeralPublicKeyHash", ConfidentialCanonical.sha256Bytes(signedTek));
        evidence.put("tlsPublicKeyHash", "sha256:test-tls-key");
        evidence.put("workloadDigest", "sha256:test-workload");
        evidence.put("policyDigest", "sha256:test-policy");
        evidence.put("sessionId", "session-1");
        evidence.put("issuedAt", now.toString());
        evidence.put("expiresAt", evidenceExpiry);
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signer.getPrivate());
        signature.update(ConfidentialCanonical.bytes(evidence));
        ObjectNode response = evidence.deepCopy();
        response.put("sessionId", "session-1");
        response.put("teeEphemeralPublicKey",
                Base64.getUrlEncoder().withoutPadding().encodeToString(responseTek));
        response.set("evidence", evidence);
        response.put("evidenceSignature",
                Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign()));
        response.put("evidenceSigningPublicKey", rootPublicKey);
        response.put("expiresAt", evidenceExpiry);
        return new SignedAttestation(mapper, rootPublicKey, task, response);
    }

    private static SignedExecution signedExecution(boolean tamperOutput) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        KeyPair signer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encodedPublicKey = signer.getPublic().getEncoded();
        String rootPublicKey = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOfRange(encodedPublicKey, encodedPublicKey.length - 32,
                        encodedPublicKey.length));
        Instant now = Instant.now();
        ObjectNode spec = mapper.createObjectNode();
        spec.put("taskId", "task-1");
        ConfidentialMetadataStore.TaskRow task = new ConfidentialMetadataStore.TaskRow(spec, "task-digest",
                "a100-sim", "controlled-sim-ok", now.plus(5, ChronoUnit.MINUTES).toString());
        ObjectNode payload = mapper.createObjectNode();
        payload.set("grant", mapper.createObjectNode());
        payload.set("sealedDeks", mapper.createArrayNode());
        payload.set("encryptedInputs", mapper.createArrayNode());
        payload.set("outputRecipients", mapper.createArrayNode());
        payload.put("scenario", "NORMAL");
        ConfidentialMetadataStore.GrantRow grant = new ConfidentialMetadataStore.GrantRow(
                "task-1", "session-1", payload, "a100-sim", now.plusSeconds(60).toString(), null);

        ObjectNode receipt = mapper.createObjectNode();
        receipt.put("contractVersion", ConfidentialContract.VERSION);
        receipt.put("executionId", "exec-1");
        receipt.put("taskId", "task-1");
        receipt.put("taskSpecDigest", "task-digest");
        receipt.put("sessionId", "session-1");
        receipt.put("runtimeMode", "SIMULATION");
        receipt.put("attestationVerified", false);
        receipt.put("securityProfile", ConfidentialContract.SIM_PROFILE);
        receipt.put("evidenceType", ConfidentialContract.SIM_EVIDENCE);
        receipt.put("simulated", true);
        receipt.put("hardwareModel", ConfidentialContract.SIM_HARDWARE);
        receipt.put("outputCiphertextSha256", "output-hash");
        receipt.put("completedAt", now.toString());
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signer.getPrivate());
        signature.update(ConfidentialCanonical.bytes(receipt));
        receipt.put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign()));

        ObjectNode response = mapper.createObjectNode();
        response.put("executionId", "exec-1");
        response.put("status", "SUCCEEDED");
        response.set("receipt", receipt);
        ObjectNode encryptedOutput = mapper.createObjectNode();
        encryptedOutput.put("ciphertextSha256", tamperOutput ? "tampered-output-hash" : "output-hash");
        response.set("encryptedOutput", encryptedOutput);
        return new SignedExecution(mapper, rootPublicKey, task, grant, response);
    }

    private record SignedAttestation(ObjectMapper mapper, String rootPublicKey,
                                     ConfidentialMetadataStore.TaskRow task, ObjectNode response) {
    }

    private record SignedExecution(ObjectMapper mapper, String rootPublicKey,
                                   ConfidentialMetadataStore.TaskRow task,
                                   ConfidentialMetadataStore.GrantRow grant, ObjectNode response) {
    }
}
