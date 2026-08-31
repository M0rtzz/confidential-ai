package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeEnvironmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 本实例环境信息只读入口，登录拦截器强制校验普通用户会话。 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/tee")
public class TeeEnvironmentController {
    private final TeeEnvironmentService environmentService;

    @GetMapping("/environment")
    public SecretPadResponse<TeeEnvironmentService.Environment> environment() {
        return SecretPadResponse.success(environmentService.environment());
    }
}
