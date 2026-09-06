package org.secretflow.secretpad.web.service.crypto;

import java.util.Set;

/** Frozen public constants for ds-confidential/v1. */
public final class ConfidentialContract {
    public static final String VERSION = "ds-confidential/v1";
    public static final String SIM_PROFILE = "a100-sim";
    public static final String PROD_PROFILE = "gpu-cc-prod";
    public static final String SIM_EVIDENCE = "SIMULATED_LAB_V1";
    public static final String SIM_HARDWARE = "NVIDIA A100";
    public static final String SIM_POLICY = "policy/a100-sim/v1";
    public static final Set<String> RUNTIME_REQUIREMENTS = Set.of("gpu-cc", "controlled-sim-ok", "public");

    private ConfidentialContract() {
    }
}
