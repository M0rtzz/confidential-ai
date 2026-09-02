/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeRuntimeService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 可信运行时的输入密钥放行与结果密钥申领；接收者必须是已登记的可信运行时。 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/tee")
public class TeeRuntimeController implements TeeApi {

    private final TeeRuntimeService runtimeService;

    @PostMapping("/runtime/release")
    public SecretPadResponse<TeeRuntimeService.ReleaseResult> release(
            @RequestBody TeeRuntimeService.ReleaseRequest request) {
        return SecretPadResponse.success(runtimeService.release(caller(), request));
    }

    @PostMapping("/runtime/output-key")
    public SecretPadResponse<TeeRuntimeService.OutputKeyResult> outputKey(
            @RequestBody TeeRuntimeService.OutputKeyRequest request) {
        return SecretPadResponse.success(runtimeService.outputKey(caller(), request));
    }

    @PostMapping("/tasks/{taskId}/receipt")
    public SecretPadResponse<TeeRuntimeService.ReceiptResult> receipt(
            @PathVariable String taskId,
            @RequestBody TeeRuntimeService.ReceiptRequest request) {
        return SecretPadResponse.success(runtimeService.receipt(caller(), taskId, request));
    }

    @GetMapping("/tasks/{taskId}/receipt")
    public SecretPadResponse<TeeRuntimeService.ReceiptResult> receipt(@PathVariable String taskId) {
        return SecretPadResponse.success(runtimeService.receipt(caller(), taskId));
    }

    private static String caller() {
        return UserContext.getUser().getOwnerId();
    }
}
