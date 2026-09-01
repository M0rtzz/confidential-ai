/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeKeyGateway;
import org.secretflow.secretpad.web.service.tee.TeeKeyService;
import org.secretflow.secretpad.web.service.tee.TeePolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 密钥签发、申领、吊销与授权规则登记。
 *
 * <p>调用主体取自会话，或在平台间入口上取自客户端证书，两条路径都不接受请求自报机构。
 * 请求落在哪一端由 {@link TeeKeyGateway} 决定：中心实例本地裁决，客户端实例转交中心端。
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/tee")
public class TeeKeyController implements TeeApi {

    private final TeeKeyGateway gateway;

    @PostMapping("/keys/issue")
    public SecretPadResponse<TeeKeyService.IssueResult> issue(@RequestBody TeeKeyService.IssueRequest request) {
        return SecretPadResponse.success(gateway.issue(owner(), request));
    }

    @PostMapping("/keys/claim")
    public SecretPadResponse<TeeKeyService.ClaimResult> claim(@RequestBody TeeKeyService.ClaimRequest request) {
        return SecretPadResponse.success(gateway.claim(owner(), request));
    }

    @PostMapping("/keys/revoke")
    public SecretPadResponse<TeeKeyService.RevokeResult> revoke(@RequestBody TeeKeyService.RevokeRequest request) {
        return SecretPadResponse.success(gateway.revoke(owner(), request));
    }

    @PostMapping("/policies/register")
    public SecretPadResponse<TeePolicyService.RegisterResult> register(
            @RequestBody TeePolicyService.RegisterRequest request) {
        return SecretPadResponse.success(gateway.registerPolicy(owner(), request));
    }

    /** 密钥台账；按机构过滤，只返回标识与计数，不返回任何密钥材料。 */
    @GetMapping("/keys")
    public SecretPadResponse<Map<String, Object>> ledger() {
        List<TeeKeyService.LedgerItem> items = gateway.ledger(owner());
        return SecretPadResponse.success(Map.of("contractVersion", TeeContract.VERSION, "items", items));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
