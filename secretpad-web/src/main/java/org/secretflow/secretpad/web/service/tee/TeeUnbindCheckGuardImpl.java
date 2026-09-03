/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.errorcode.NodeRouteErrorCode;
import org.secretflow.secretpad.common.exception.SecretpadException;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.TeeUnbindCheckGuard;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/** {@link TeeUnbindCheckGuard} 的实现；直接复用信任链聚合服务的 unbind-check 计算。 */
@Component
public class TeeUnbindCheckGuardImpl implements TeeUnbindCheckGuard {

    private final TrustChainService trustChain;

    public TeeUnbindCheckGuardImpl(TrustChainService trustChain) {
        this.trustChain = trustChain;
    }

    @Override
    public void check(String srcOwnerId, String dstOwnerId) {
        String ownerId = target(srcOwnerId, dstOwnerId);
        if (ownerId == null) {
            return;
        }
        TrustChainService.UnbindCheckView view = trustChain.unbindCheck(ownerId);
        if (view.clean()) {
            return;
        }
        List<TrustChainService.Blocker> pending = view.blockers().stream()
                .filter(blocker -> blocker.count() > 0).toList();
        String detail = pending.stream()
                .map(blocker -> blocker.label() + "(" + blocker.count() + ")")
                .collect(Collectors.joining("、"));
        throw SecretpadException.of(NodeRouteErrorCode.NODE_ROUTE_DELETE_ERROR,
                "机构 " + ownerId + " 仍有未清理的 TEE 数据关联：" + detail);
    }

    /**
     * 客户端解除接入时校验本机构，中心端解绑某个客户端时校验对端机构。
     * 判据是"谁的数据会被留在中心端而管不到"，答案永远是数据方那一侧。
     */
    private String target(String srcOwnerId, String dstOwnerId) {
        UserContextDTO user = UserContext.getUserOrNotExist();
        String self = user == null ? null : user.getOwnerId();
        if (!"CENTER".equals(trustChain.endRole())) {
            return self;
        }
        if (self != null && self.equals(srcOwnerId)) {
            return dstOwnerId;
        }
        if (self != null && self.equals(dstOwnerId)) {
            return srcOwnerId;
        }
        return dstOwnerId;
    }
}
