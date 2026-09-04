package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfidentialCanonicalTest {

    @Test
    void ed25519SignatureUsesCanonicalPropertyOrder() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        String rawPublicKey = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        Map<String, Object> signed = new LinkedHashMap<>();
        signed.put("z", "last");
        signed.put("a", Map.of("simulated", true, "securityProfile", "a100-sim"));

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(ConfidentialCanonical.bytes(signed));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        ConfidentialCanonical.verifyEd25519(rawPublicKey, signature,
                Map.of("a", Map.of("securityProfile", "a100-sim", "simulated", true), "z", "last"));
    }

    @Test
    void tamperedSignedClaimIsRejected() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        String rawPublicKey = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(ConfidentialCanonical.bytes(Map.of("securityProfile", "a100-sim")));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        TeeException failure = assertThrows(TeeException.class,
                () -> ConfidentialCanonical.verifyEd25519(rawPublicKey, signature,
                        Map.of("securityProfile", "gpu-cc-prod")));
        assertEquals(TeeContract.Error.TASK_SIGNATURE_INVALID, failure.error());
    }

    @Test
    void verifiesPythonRfc8785SignatureForJsonNode() throws Exception {
        String publicKey = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
        String signature = "4or2laouxlHzKOaLOf_vDvbL9cY7YurGGiEv6r3eN6wrV-Yyp08095GgA67s_WWfr23w5EHwRs5EM-p35W7uBw";
        var payload = new ObjectMapper().readTree("""
                {"z":"last","maxUses":1,"a":{"simulated":true,"securityProfile":"a100-sim"}}
                """);

        ConfidentialCanonical.verifyEd25519(publicKey, signature, payload);
    }
}
