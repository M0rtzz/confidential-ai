/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import lombok.RequiredArgsConstructor;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.GpuChainService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * GPU 密态执行链路的只读聚合接口。
 *
 * <p>路径在 {@code /api/v1alpha1/data-sandbox} 下，与 CPU 侧的 {@link TrustChainController}
 * 同一命名空间，不属于冻结的 {@code /api/v1alpha1/tee} 契约，因此不 implement {@link TeeApi}。
 * 全部为只读查询，数据范围限定在当前会话所属机构。
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/data-sandbox/gpu-chain")
public class GpuChainController {

    private final GpuChainService gpuChain;

    @GetMapping("/summary")
    public SecretPadResponse<GpuChainService.SummaryView> summary() {
        return SecretPadResponse.success(gpuChain.summary(owner()));
    }

    @GetMapping("/identities")
    public SecretPadResponse<GpuChainService.PageView> identities(
            @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "20") int size) {
        return SecretPadResponse.success(gpuChain.identities(owner(), page, size));
    }

    @GetMapping("/assets")
    public SecretPadResponse<GpuChainService.PageView> assets(
            @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "20") int size) {
        return SecretPadResponse.success(gpuChain.assets(owner(), page, size));
    }

    @GetMapping("/attestations")
    public SecretPadResponse<GpuChainService.PageView> attestations(
            @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "20") int size) {
        return SecretPadResponse.success(gpuChain.attestations(owner(), page, size));
    }

    @GetMapping("/grants")
    public SecretPadResponse<GpuChainService.PageView> grants(
            @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "20") int size) {
        return SecretPadResponse.success(gpuChain.grants(owner(), page, size));
    }

    @GetMapping("/executions")
    public SecretPadResponse<GpuChainService.PageView> executions(
            @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "20") int size) {
        return SecretPadResponse.success(gpuChain.executions(owner(), page, size));
    }

    @GetMapping("/audit-events")
    public SecretPadResponse<GpuChainService.PageView> auditEvents(
            @RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "20") int size) {
        return SecretPadResponse.success(gpuChain.auditEvents(owner(), page, size));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
