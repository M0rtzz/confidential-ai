/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import lombok.RequiredArgsConstructor;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeCapabilityService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * TEE 环境加密能力与技术要求对照。
 *
 * <p>只读接口，路径在 {@code /api/v1alpha1/data-sandbox} 下，不属于冻结的
 * {@code /api/v1alpha1/tee} 契约，因此不 implement {@link TeeApi}。
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/data-sandbox")
public class TeeCapabilityController {

    private final TeeCapabilityService capabilities;

    @GetMapping("/tee-capabilities")
    public SecretPadResponse<TeeCapabilityService.CapabilityView> capabilities() {
        return SecretPadResponse.success(capabilities.capabilities());
    }
}
