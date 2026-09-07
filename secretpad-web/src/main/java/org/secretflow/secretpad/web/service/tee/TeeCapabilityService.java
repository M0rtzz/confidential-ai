/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.secretflow.secretpad.web.service.crypto.ConfidentialContract;
import org.secretflow.secretpad.web.service.crypto.ConfidentialModelService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * TEE 环境可选的加密能力与技术要求对照。
 *
 * <p>两类取值分开给出：{@code supported} 是本系统实现的能力，{@code current} 是本实例
 * 当前实际具备的档位。硬件探测未通过时对应选项标为不可用并给出原因，
 * 界面据此禁选，不把支持能力呈现为已达成。
 */
@Service
public class TeeCapabilityService {

    private final TeeEnvironmentService environmentService;
    private final ConfidentialModelService modelService;

    public TeeCapabilityService(TeeEnvironmentService environmentService, ConfidentialModelService modelService) {
        this.environmentService = environmentService;
        this.modelService = modelService;
    }

    /** 单个可选项；{@code available=false} 时 {@code reason} 说明为何不可选。 */
    public record Option(String value, String label, String description, boolean available, String reason) {
    }

    /** 技术要求对照行：左列条款，右列分「系统支持」与「本实例当前」。 */
    public record RequirementRow(String requirement, String supported, String current, boolean satisfied) {
    }

    public record CapabilityView(TeeEnvironmentService.Environment environment,
                                 List<Option> cpuEncryptions, List<Option> gpuEncryptions,
                                 List<Option> attestationRequirements, List<String> contentAlgorithms,
                                 String defaultContentAlgorithm, List<RequirementRow> requirements) {
    }

    public CapabilityView capabilities() {
        TeeEnvironmentService.Environment environment = environmentService.environment();
        TeeEnvironmentService.DeviceChecks devices = environment.deviceChecks();
        boolean simulation = "SIMULATION".equals(environment.runtimeMode());

        List<Option> cpu = new ArrayList<>();
        cpu.add(new Option("NONE", "不启用", "不要求 CPU 内存加密", true, ""));
        cpu.add(cpuOption("SGX", "Intel SGX", "enclave 级安全内存分区", devices.sgx()));
        cpu.add(cpuOption("TDX", "Intel TDX", "机密虚拟机级内存加密", devices.tdx()));
        cpu.add(cpuOption("CSV", "海光 CSV", "国产平台的机密虚拟机内存加密", devices.csv()));

        List<Option> gpu = List.of(
                new Option("NONE", "不启用", "不使用 GPU 密态执行", true, ""),
                new Option(ConfidentialContract.SIM_PROFILE, "A100 模拟档位",
                        "客户端加密、HPKE 封装与一次性授权均为真实实现，证据为实验室模拟", true, ""),
                new Option(ConfidentialContract.PROD_PROFILE, "GPU 机密计算",
                        "要求 GPU 硬件机密隔离", false, "当前无 GPU 机密计算硬件，系统拒绝把该档位降级到模拟环境"));

        List<Option> attestation = List.of(
                new Option("ALLOW_SIMULATION", "允许仿真证据", "接受实验室模拟证据，适用于开发与演示", true, ""),
                new Option("REQUIRE_HARDWARE", "要求硬件证明", "只接受经验证的硬件远程证明", !simulation,
                        simulation ? "本实例运行在 SIMULATION 档位，无法提供硬件证明" : ""));

        Object algorithms = modelService.capabilities().get("contentEncryptionAlgorithms");
        List<String> algorithmNames = new ArrayList<>();
        if (algorithms instanceof List<?> values) {
            values.forEach(item -> {
                if (item instanceof Map<?, ?> row && row.get("algorithm") != null) {
                    algorithmNames.add(String.valueOf(row.get("algorithm")));
                }
            });
        }

        return new CapabilityView(environment, cpu, gpu, attestation, algorithmNames,
                "AES-256-GCM", requirements(environment, devices));
    }

    private static Option cpuOption(String value, String label, String description, boolean detected) {
        return new Option(value, label, description, detected,
                detected ? "" : "本机未探测到对应字符设备");
    }

    /**
     * 技术要求对照。
     *
     * <p>「系统支持」描述实现范围，「本实例当前」描述实测结论。CPU 三条在 SIMULATION
     * 档位下一律判为未达成——仿真不提供任何内存机密性保证，不得以支持能力代替。
     */
    private List<RequirementRow> requirements(TeeEnvironmentService.Environment environment,
                                              TeeEnvironmentService.DeviceChecks devices) {
        boolean hardware = environment.hardwareDetected() && environment.attestationVerified();
        String cpuCurrent = devices.sgx() || devices.tdx() || devices.csv()
                ? "已探测到硬件设备" : "未探测到 SGX / TDX / CSV 字符设备";
        String modeCurrent = "SIMULATION".equals(environment.runtimeMode())
                ? "SIMULATION，不具备该保证" : environment.runtimeMode();
        return List.of(
                new RequirementRow("硬件隔离，保证计算环境隔离性与内存机密性",
                        "SGX / TDX / CSV 三类 CPU TEE", cpuCurrent, hardware),
                new RequirementRow("抵御操作系统及更高层软件的攻击",
                        "CPU 级安全内存分区，enclave 内存不对宿主机开放", modeCurrent, hardware),
                new RequirementRow("宿主机、云平台、虚拟化无法窥探计算内存",
                        "内存加密由 CPU 硬件完成，密钥不出芯片", modeCurrent, hardware),
                new RequirementRow("支持 GPU 密态方案",
                        "CipherGPU 数据面：HPKE 封装、一次性 TEK 与 ODK 出域",
                        "协议已启用，证据为 " + ConfidentialContract.SIM_EVIDENCE, true),
                new RequirementRow("支持多种硬件类型",
                        "CPU 三类 TEE 与 NVIDIA GPU，安全档位可按环境配置",
                        ConfidentialContract.SIM_PROFILE + "；" + ConfidentialContract.PROD_PROFILE + " 拒绝降级",
                        true));
    }
}
