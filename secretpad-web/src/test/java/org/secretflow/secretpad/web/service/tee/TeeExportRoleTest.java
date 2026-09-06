/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.web.interceptor.LoginInterceptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 结果导出与审批仅客户端可用，中心端目录与写入口均拒绝。 */
class TeeExportRoleTest {
    private final LoginInterceptor interceptor = mock(LoginInterceptor.class, CALLS_REAL_METHODS);

    @AfterEach
    void cleanContext() { UserContext.remove(); }

    @Test
    void centerCannotAccessExportModule() {
        assertFalse(allowed("CENTER", "GET", "/exports/catalog"));
        assertFalse(allowed("CENTER", "POST", "/exports"));
        assertFalse(allowed("CENTER", "POST", "/exports/exp-1/action"));
        assertFalse(allowed("CENTER", "POST", "/exports/exp-1/download"));
        assertFalse(allowed("CENTER", "GET", "/exports/mine"));
        assertFalse(allowed("CENTER", "GET", "/exports/history"));
    }

    @Test
    void clientKeepsOwnExportEndpoints() {
        assertTrue(allowed("CLIENT", "GET", "/exports/catalog"));
        assertTrue(allowed("CLIENT", "GET", "/exports/exportable"));
        assertTrue(allowed("CLIENT", "GET", "/exports/history"));
        assertTrue(allowed("CLIENT", "POST", "/exports/exp-1/download"));
    }

    @Test
    void staleSessionStillRequiresReloginForCatalog() {
        assertFalse(allowed(null, "GET", "/exports/catalog"));
    }

    private boolean allowed(String role, String method, String path) {
        UserContextDTO user = new UserContextDTO();
        user.setOwnerId("owner");
        user.setEndRole(role);
        UserContext.setBaseUser(user);
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/api/v1alpha1/tee" + path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        return Boolean.TRUE.equals(ReflectionTestUtils.invokeMethod(interceptor, "checkEndRole", request, response));
    }
}
