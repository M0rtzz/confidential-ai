/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeAssetService;
import org.secretflow.secretpad.web.service.tee.TeeCrypto;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** 密文资产登记与密文对象读写；所有出参均为密文或元数据，不含数据行。 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/tee")
public class TeeAssetController implements TeeApi {

    private final TeeAssetService assetService;

    @PostMapping("/assets/register")
    public SecretPadResponse<TeeAssetService.RegisterResult> register(
            @RequestBody TeeAssetService.RegisterRequest request) {
        return SecretPadResponse.success(assetService.register(owner(), request));
    }

    @PostMapping("/objects")
    public SecretPadResponse<TeeAssetService.ObjectResult> putObject(
            @RequestBody TeeAssetService.ObjectRequest request) {
        return SecretPadResponse.success(assetService.putObject(owner(), request));
    }

    @GetMapping("/objects/{objectId}")
    public SecretPadResponse<TeeCrypto.EncryptedObject> object(@PathVariable String objectId,
            @RequestHeader(value = "X-TEE-Task-Id", required = false) String taskId) {
        return SecretPadResponse.success(assetService.readObject(owner(), objectId, taskId));
    }

    @GetMapping("/programs/{objectId}")
    public SecretPadResponse<TeeAssetService.ProgramResult> program(@PathVariable String objectId,
            @RequestHeader("X-TEE-Task-Id") String taskId) {
        return SecretPadResponse.success(assetService.readProgram(owner(), taskId, objectId));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }
}
