/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeContract;
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

/** 密钥签发、申领、吊销与授权规则登记；调用主体一律取自会话，不接受请求自报机构。 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/tee")
public class TeeKeyController implements TeeApi {

    private final TeeKeyService keyService;
    private final TeePolicyService policyService;

    @PostMapping("/keys/issue")
    public SecretPadResponse<TeeKeyService.IssueResult> issue(@RequestBody TeeKeyService.IssueRequest request) {
        return SecretPadResponse.success(keyService.issue(owner(), request));
    }

    @PostMapping("/keys/claim")
    public SecretPadResponse<TeeKeyService.ClaimResult> claim(@RequestBody TeeKeyService.ClaimRequest request) {
        return SecretPadResponse.success(keyService.claim(owner(), request));
    }

    @PostMapping("/keys/revoke")
    public SecretPadResponse<TeeKeyService.RevokeResult> revoke(@RequestBody TeeKeyService.RevokeRequest request) {
        return SecretPadResponse.success(keyService.revoke(owner(), request));
    }

    @PostMapping("/policies/register")
    public SecretPadResponse<TeePolicyService.RegisterResult> register(
            @RequestBody TeePolicyService.RegisterRequest request) {
        return SecretPadResponse.success(policyService.register(owner(), request));
    }

    /** 密钥台账；按机构过滤，只返回标识与计数，不返回任何密钥材料。 */
    @GetMapping("/keys")
    public SecretPadResponse<Map<String, Object>> ledger() {
        List<TeeKeyService.LedgerItem> items = keyService.ledger(owner());
        return SecretPadResponse.success(Map.of("contractVersion", TeeContract.VERSION, "items", items));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
