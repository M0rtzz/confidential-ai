/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;

/**
 * 平台间契约入口的调用方身份。
 *
 * <p>契约第二节要求跨机构接口的身份由服务端证书取得，不能信任请求自报的机构。
 * 这里只认已在部署时登记的客户端证书：连接由容器握手时验证证书链、有效期与吊销，
 * 本类再按 DER 摘要反查机构标识，未登记一律拒绝。
 */
@Component
public class TeeContractIdentity {

    private static final String CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final TeeIdentityRegistry registry;

    public TeeContractIdentity(TeeIdentityRegistry registry) {
        this.registry = registry;
    }

    /** 取本次连接的客户端证书对应的机构标识；缺证书或未登记都视为越权。 */
    public String requireOwner(HttpServletRequest request) {
        Object attribute = request.getAttribute(CERTIFICATE_ATTRIBUTE);
        if (!(attribute instanceof X509Certificate[] chain) || chain.length == 0) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "平台间入口缺少客户端证书");
        }
        X509Certificate leaf = chain[0];
        try {
            leaf.checkValidity();
        } catch (Exception expired) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "调用方证书不在有效期内");
        }
        return registry.ownerByContractCertificate(TeeCrypto.certificateSha256(leaf));
    }
}
