/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.crypto.ConfidentialContract;
import org.secretflow.secretpad.web.service.crypto.ConfidentialModelService;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** TEE 环境能力对照：仿真档位下不得把支持能力呈现为已达成。 */
class TeeCapabilityServiceTest {

    private static TeeCapabilityService newService(String runtimeMode, boolean sgx, boolean attestationVerified) {
        TeeEnvironmentService environmentService = mock(TeeEnvironmentService.class);
        when(environmentService.environment()).thenReturn(new TeeEnvironmentService.Environment(
                TeeEnvironmentService.CONTRACT_VERSION, runtimeMode, null, sgx,
                new TeeEnvironmentService.DeviceChecks(sgx, false, false),
                attestationVerified, false, false, List.of()));
        ConfidentialModelService modelService = mock(ConfidentialModelService.class);
        when(modelService.capabilities()).thenReturn(Map.of("contentEncryptionAlgorithms", List.of(
                Map.of("algorithm", "AES-256-GCM"), Map.of("algorithm", "CHACHA20-POLY1305"))));
        return new TeeCapabilityService(environmentService, modelService);
    }

    private static TeeCapabilityService.Option option(List<TeeCapabilityService.Option> options, String value) {
        return options.stream().filter(item -> value.equals(item.value())).findFirst().orElseThrow();
    }

    @Test
    void undetectedCpuDevicesAreNotSelectable() {
        TeeCapabilityService.CapabilityView view = newService("SIMULATION", false, false).capabilities();
        assertFalse(option(view.cpuEncryptions(), "SGX").available());
        assertFalse(option(view.cpuEncryptions(), "TDX").available());
        assertTrue(option(view.cpuEncryptions(), "NONE").available());
    }

    @Test
    void detectedCpuDeviceBecomesSelectable() {
        TeeCapabilityService.CapabilityView view = newService("HARDWARE", true, true).capabilities();
        assertTrue(option(view.cpuEncryptions(), "SGX").available());
        assertFalse(option(view.cpuEncryptions(), "CSV").available());
    }

    @Test
    void productionGpuProfileStaysUnavailable() {
        TeeCapabilityService.CapabilityView view = newService("SIMULATION", false, false).capabilities();
        assertTrue(option(view.gpuEncryptions(), ConfidentialContract.SIM_PROFILE).available());
        assertFalse(option(view.gpuEncryptions(), ConfidentialContract.PROD_PROFILE).available());
    }

    @Test
    void hardwareAttestationCannotBeRequiredInSimulation() {
        assertFalse(option(newService("SIMULATION", false, false).capabilities()
                .attestationRequirements(), "REQUIRE_HARDWARE").available());
        assertTrue(option(newService("HARDWARE", true, true).capabilities()
                .attestationRequirements(), "REQUIRE_HARDWARE").available());
    }

    @Test
    void simulationMarksCpuRequirementsUnsatisfied() {
        List<TeeCapabilityService.RequirementRow> rows =
                newService("SIMULATION", false, false).capabilities().requirements();
        assertEquals(5, rows.size());
        assertFalse(rows.get(0).satisfied());
        assertFalse(rows.get(1).satisfied());
        assertFalse(rows.get(2).satisfied());
        // GPU 两条陈述的是协议能力而非硬件隔离，仿真档位下仍成立。
        assertTrue(rows.get(3).satisfied());
        assertTrue(rows.get(4).satisfied());
    }

    @Test
    void contentAlgorithmsComeFromModelCapabilities() {
        TeeCapabilityService.CapabilityView view = newService("SIMULATION", false, false).capabilities();
        assertEquals(List.of("AES-256-GCM", "CHACHA20-POLY1305"), view.contentAlgorithms());
        assertEquals("AES-256-GCM", view.defaultContentAlgorithm());
    }
}
