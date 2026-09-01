/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.util.Arrays;

/**
 * 治理产出的加密落盘。
 *
 * <p>方案第 04 节第 3 步：抽样脱敏在本地完成后，客户端向中心端申请密钥、在内存中加密，
 * 密文落盘，密钥随即销毁。客户端实例的密钥请求经 {@link TeeKeyGateway} 委派给中心端，
 * 中心实例则直连本地密钥适配服务，两者的落盘形态一致。
 */
@Service
public class TeeAssetEncryptor {

    private final TeeKeyGateway gateway;
    private final TeeInstitutionKey institutionKey;
    private final KeyAdapterClient adapter;
    private final ObjectMapper mapper;

    public TeeAssetEncryptor(TeeKeyGateway gateway, TeeInstitutionKey institutionKey,
                             KeyAdapterClient adapter, ObjectMapper mapper) {
        this.gateway = gateway;
        this.institutionKey = institutionKey;
        this.adapter = adapter;
        this.mapper = mapper;
    }

    /** 密文封装及其序列化形态；调用方按此写入对象存储。 */
    public record Sealed(TeeCrypto.EncryptedObject object, byte[] payload,
                         String keyId, String keyVersion, String ciphertextSha256) {
    }

    /** 本实例是否具备加密落盘条件：能取到密钥服务，且持有本机构解封私钥。 */
    public boolean available() {
        return institutionKey.available() && (gateway.delegated() || adapter.configured());
    }

    /**
     * 为一份治理产出申领密钥并加密。
     *
     * <p>请求标识按资产版本推导，因此重试复用同一把密钥、同一条台账记录，不会重复签发。
     */
    public Sealed seal(String ownerId, String assetId, String assetVersion, byte[] plaintext) {
        TeeKeyService.IssueResult issued = gateway.issue(ownerId, new TeeKeyService.IssueRequest(
                TeeContract.VERSION, "gov-issue-" + assetId + "-" + assetVersion, assetId, assetVersion));
        TeeKeyService.ClaimResult claimed = gateway.claim(ownerId, new TeeKeyService.ClaimRequest(
                TeeContract.VERSION, "gov-claim-" + assetId + "-" + assetVersion, assetId, assetVersion,
                issued.keyId(), issued.keyVersion(), institutionKey.certificatePem()));
        byte[] dataKey = institutionKey.unwrap(claimed.keyEnvelope());
        try {
            TeeCrypto.EncryptedObject object = TeeCrypto.seal(mapper, dataKey, plaintext,
                    assetId, assetVersion, issued.keyId(), issued.keyVersion());
            return new Sealed(object, serialize(object), issued.keyId(), issued.keyVersion(),
                    object.ciphertextSha256());
        } finally {
            // 加密完成即清除应用可控的密钥缓冲；不承诺清除 GC 或底层库的副本。
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    public byte[] serialize(TeeCrypto.EncryptedObject object) {
        try {
            return mapper.writeValueAsBytes(object);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密文封装序列化失败");
        }
    }
}
