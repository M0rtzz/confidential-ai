/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.service;

/**
 * 解绑前的 TEE 未清理项校验。
 *
 * <p>{@code secretpad-service} 不依赖 {@code secretpad-web}，TEE 台账的查询与委派都在
 * web 模块；因此这里只声明接口，实现 bean 由 web 模块提供，{@code NodeRouterServiceImpl}
 * 用 {@link org.springframework.beans.factory.ObjectProvider} 注入——非 TEE 部署下没有
 * 实现 bean 时按既有行为跳过，不阻塞解绑。
 */
public interface TeeUnbindCheckGuard {

    /**
     * 校验解绑这条路由是否安全，仍有未清理的 TEE 数据关联时抛出异常并列出未清理项与数量。
     *
     * <p>传入路由两端的机构标识，由实现按本实例的端身份决定校验哪一个：
     * 中心端解绑某个客户端时校验对端机构，客户端解除接入时校验本机构自己——
     * 有数据留在中心端而管不到的，永远是数据方。
     */
    void check(String srcOwnerId, String dstOwnerId);
}
