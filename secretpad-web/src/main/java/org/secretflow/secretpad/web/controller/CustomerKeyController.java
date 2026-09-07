/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import lombok.RequiredArgsConstructor;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.crypto.CustomerKeyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 客户密钥（UEK）全生命周期接口。
 *
 * <p>属 {@code ds-confidential/v1} 数据面，不在冻结的 {@code /api/v1alpha1/tee} 契约命名空间下，
 * 因此不 implement {@link TeeApi}。独立成类是为了不改动
 * {@code ConfidentialComputeController}，避免与大模型管理的并行分支冲突。
 *
 * <p>全部操作限定在当前会话所属机构，管理员没有代持有人轮换或销毁的通道——
 * 服务端不持有私钥，代执行只会制造记录与浏览器不一致的状态。
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/crypto/customer-keys")
public class CustomerKeyController {

    private final CustomerKeyService customerKeys;

    @GetMapping
    public SecretPadResponse<List<Map<String, Object>>> list() {
        return SecretPadResponse.success(customerKeys.list(owner()));
    }

    @GetMapping("/rotation-status")
    public SecretPadResponse<CustomerKeyService.RotationStatus> rotationStatus() {
        return SecretPadResponse.success(customerKeys.rotationStatus(owner()));
    }

    @PostMapping("/rotate")
    public SecretPadResponse<Map<String, Object>> rotate(@RequestBody CustomerKeyService.RotateRequest request) {
        return SecretPadResponse.success(customerKeys.rotate(owner(), request));
    }

    @PostMapping("/{kid}/revoke")
    public SecretPadResponse<Map<String, Object>> revoke(@PathVariable String kid) {
        return SecretPadResponse.success(customerKeys.revoke(owner(), kid));
    }

    @PostMapping("/{kid}/destroy")
    public SecretPadResponse<Map<String, Object>> destroy(@PathVariable String kid,
                                                          @RequestBody Map<String, String> body) {
        return SecretPadResponse.success(customerKeys.destroy(owner(), kid, body.get("confirmKid")));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
