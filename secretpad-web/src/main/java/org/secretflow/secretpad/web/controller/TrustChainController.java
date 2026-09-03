/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import lombok.RequiredArgsConstructor;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeRuntimeService;
import org.secretflow.secretpad.web.service.tee.TrustChainService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * P2 + P8 只读聚合接口：信任链看板。
 *
 * <p>路径全部在 {@code /api/v1alpha1/data-sandbox} 下，不属于冻结的 {@code /api/v1alpha1/tee}
 * 契约，因此本控制器不 implement {@link TeeApi}。{@code /instance} 免登录，
 * 其余接口沿用普通会话鉴权。
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/data-sandbox")
public class TrustChainController {

    private final TrustChainService trustChain;

    @GetMapping("/instance")
    public SecretPadResponse<TrustChainService.InstanceView> instance() {
        return SecretPadResponse.success(trustChain.instance());
    }

    @GetMapping("/trust-chain/summary")
    public SecretPadResponse<TrustChainService.SummaryView> summary() {
        return SecretPadResponse.success(trustChain.summary(owner(), ownerName()));
    }

    @GetMapping("/trust-chain/keys")
    public SecretPadResponse<TrustChainService.KeysView> keys() {
        return SecretPadResponse.success(trustChain.keys(owner()));
    }

    @GetMapping("/trust-chain/policies")
    public SecretPadResponse<TrustChainService.PoliciesView> policies() {
        return SecretPadResponse.success(trustChain.policies());
    }

    @GetMapping("/trust-chain/objects")
    public SecretPadResponse<TrustChainService.ObjectsView> objects() {
        return SecretPadResponse.success(trustChain.objects(owner()));
    }

    @GetMapping("/trust-chain/objects/{objectId}/preview")
    public SecretPadResponse<TrustChainService.PreviewView> preview(@PathVariable String objectId) {
        return SecretPadResponse.success(trustChain.preview(owner(), objectId));
    }

    @GetMapping("/trust-chain/tasks")
    public SecretPadResponse<TrustChainService.TasksView> tasks(
            @RequestParam(required = false) Integer limit) {
        return SecretPadResponse.success(trustChain.tasks(limit));
    }

    @GetMapping("/trust-chain/tasks/{taskId}/receipt")
    public SecretPadResponse<TeeRuntimeService.ReceiptResult> receipt(@PathVariable String taskId) {
        return SecretPadResponse.success(trustChain.receipt(taskId));
    }

    @GetMapping("/trust-chain/exports")
    public SecretPadResponse<TrustChainService.ExportsView> exports() {
        return SecretPadResponse.success(trustChain.exports(owner()));
    }

    @GetMapping("/trust-chain/peer")
    public SecretPadResponse<TrustChainService.PeerView> peer() {
        return SecretPadResponse.success(trustChain.peer(owner()));
    }

    @GetMapping("/trust-chain/unbind-check")
    public SecretPadResponse<TrustChainService.UnbindCheckView> unbindCheck() {
        return SecretPadResponse.success(trustChain.unbindCheck(owner()));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }

    private static String ownerName() {
        return UserContext.getUser().getOwnerName();
    }
}
