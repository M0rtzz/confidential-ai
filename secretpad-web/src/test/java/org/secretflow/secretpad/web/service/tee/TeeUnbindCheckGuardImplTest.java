/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.errorcode.NodeRouteErrorCode;
import org.secretflow.secretpad.common.exception.SecretpadException;
import org.secretflow.secretpad.common.util.UserContext;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 解绑前的 TEE 未清理项拦截。
 *
 * <p>除了"有未清理项就拦住"，还要覆盖校验对象的选取：数据留在中心端而管不到的永远是数据方，
 * 所以客户端解除接入校验本机构，中心端解绑某个客户端校验对端机构。
 */
class TeeUnbindCheckGuardImplTest {

    private static final String CLIENT = "inst-a";
    private static final String CENTER = "inst-center";

    @AfterEach
    void clear() {
        UserContext.remove();
    }

    private TrustChainService trustChain(String endRole, String pendingOwnerId) {
        TrustChainService trustChain = mock(TrustChainService.class);
        when(trustChain.endRole()).thenReturn(endRole);
        when(trustChain.unbindCheck(anyString()))
                .thenReturn(new TrustChainService.UnbindCheckView(true, clean()));
        when(trustChain.unbindCheck(pendingOwnerId))
                .thenReturn(new TrustChainService.UnbindCheckView(false, List.of(
                        new TrustChainService.Blocker("ACTIVE_KEY", "生效的数据密钥", 3, "在密钥台账逐把吊销"),
                        new TrustChainService.Blocker("OPEN_EXPORT", "未完结的导出工单", 0, "投票结清或撤销工单"),
                        new TrustChainService.Blocker("LIVE_OBJECT", "仍在中心端的密文结果", 0, "清理结果对象"),
                        new TrustChainService.Blocker("RUNNING_JOB", "运行中的作业", 0, "等待作业结束"))));
        return trustChain;
    }

    private static List<TrustChainService.Blocker> clean() {
        return List.of(new TrustChainService.Blocker("ACTIVE_KEY", "生效的数据密钥", 0, "在密钥台账逐把吊销"),
                new TrustChainService.Blocker("OPEN_EXPORT", "未完结的导出工单", 0, "投票结清或撤销工单"),
                new TrustChainService.Blocker("LIVE_OBJECT", "仍在中心端的密文结果", 0, "清理结果对象"),
                new TrustChainService.Blocker("RUNNING_JOB", "运行中的作业", 0, "等待作业结束"));
    }

    private static void login(String ownerId) {
        UserContextDTO user = new UserContextDTO();
        user.setName("devadmin");
        user.setOwnerId(ownerId);
        UserContext.setBaseUser(user);
    }

    @Test
    void centerInstanceChecksThePeerInstitution() {
        login(CENTER);
        TeeUnbindCheckGuardImpl guard = new TeeUnbindCheckGuardImpl(trustChain("CENTER", CLIENT));

        SecretpadException refused = assertThrows(SecretpadException.class,
                () -> guard.check(CENTER, CLIENT));

        assertEquals(NodeRouteErrorCode.NODE_ROUTE_DELETE_ERROR.getCode(),
                refused.getErrorCode().getCode());
    }

    @Test
    void clientInstanceChecksItsOwnInstitution() {
        login(CLIENT);
        // 客户端删除的是指向中心端的路由，对端是中心端，但该拦的是本机构自己留在中心端的数据
        TeeUnbindCheckGuardImpl guard = new TeeUnbindCheckGuardImpl(trustChain("CLIENT", CLIENT));

        SecretpadException refused = assertThrows(SecretpadException.class,
                () -> guard.check(CLIENT, CENTER));

        assertEquals(NodeRouteErrorCode.NODE_ROUTE_DELETE_ERROR.getCode(),
                refused.getErrorCode().getCode());
    }

    @Test
    void allowsUnbindWhenNothingPending() {
        login(CLIENT);
        TeeUnbindCheckGuardImpl guard = new TeeUnbindCheckGuardImpl(trustChain("CLIENT", "inst-other"));

        assertDoesNotThrow(() -> guard.check(CLIENT, CENTER));
    }
}
