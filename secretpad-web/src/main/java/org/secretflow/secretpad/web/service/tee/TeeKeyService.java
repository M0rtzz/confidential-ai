/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.repository.TeeKeyRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * 密钥签发、申领与吊销。
 *
 * <p>密钥本体由中心密钥服务托管，平台只保存台账与状态；申领返回的始终是密封信封，
 * 平台进程内不出现数据密钥明文。客户端不自产密钥，加密后即销毁，本地不留副本。
 */
@Service
public class TeeKeyService {

    private final TeeKeyRepository keys;
    private final TeePolicyRepository policies;
    private final KeyAdapterClient adapter;
    private final TeeIdentityRegistry registry;
    private final TeeIdempotency idempotency;

    public TeeKeyService(TeeKeyRepository keys, TeePolicyRepository policies, KeyAdapterClient adapter,
                         TeeIdentityRegistry registry, TeeIdempotency idempotency) {
        this.keys = keys;
        this.policies = policies;
        this.adapter = adapter;
        this.registry = registry;
        this.idempotency = idempotency;
    }

    public record IssueRequest(String contractVersion, String requestId, String assetId, String assetVersion) {
    }

    public record IssueResult(String contractVersion, String keyId, String keyVersion, String state) {
    }

    public record ClaimRequest(String contractVersion, String requestId, String assetId, String assetVersion,
                               String keyId, String keyVersion, String recipientCertPem) {
    }

    public record KeyEnvelope(String keyId, String keyVersion, String algorithm,
                              String recipientCertSha256, String wrappedKeyB64) {
    }

    public record ClaimResult(String contractVersion, KeyEnvelope keyEnvelope) {
    }

    public record RevokeRequest(String contractVersion, String requestId, String keyId,
                                String keyVersion, String reason) {
    }

    public record RevokeResult(String contractVersion, String keyId, String keyVersion, String state) {
    }

    public record LedgerItem(String keyId, String keyVersion, String assetId, String ownerId, String state,
                             String issuedAt, int claimCount, int releaseCount) {
    }

    /** 每个资产版本对应一个数据密钥版本；同一版本重复签发返回已有密钥，不新建。 */
    @Transactional
    public IssueResult issue(String ownerId, IssueRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String assetId = TeeGuard.requireText(request.assetId(), "assetId");
        String assetVersion = TeeGuard.requireText(request.assetVersion(), "assetVersion");
        String fingerprint = TeeIdempotency.fingerprint(List.of(assetId, assetVersion));
        return idempotency.execute(ownerId, "keys/issue", requestId, fingerprint, IssueResult.class, () -> {
            requireAssetOwner(assetId, ownerId);
            Optional<TeeKeyDO> existing = active(assetId, assetVersion);
            if (existing.isPresent()) {
                TeeKeyDO key = existing.get();
                return new IssueResult(TeeContract.VERSION, key.getUpk().getKeyId(),
                        key.getUpk().getKeyVersion(), key.getState());
            }
            String keyId = "kd-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
            String resourceUri = "tee-" + UUID.randomUUID().toString().replace("-", "");
            adapter.call("/v1/keys/issue", Map.of("resourceUri", resourceUri));
            keys.save(TeeKeyDO.builder()
                    .upk(new TeeKeyDO.UPK(keyId, "1"))
                    .assetId(assetId).assetVersion(assetVersion).ownerId(ownerId)
                    .resourceUri(resourceUri).state(TeeContract.STATE_ACTIVE)
                    .issuedAt(Instant.now().toString()).claimCount(0).releaseCount(0)
                    .build());
            return new IssueResult(TeeContract.VERSION, keyId, "1", TeeContract.STATE_ACTIVE);
        });
    }

    /** 所有者申领加密密钥；接收者公钥只取自已登记的机构证书，服务端自行核对指纹。 */
    @Transactional
    public ClaimResult claim(String ownerId, ClaimRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String keyId = TeeGuard.requireText(request.keyId(), "keyId");
        String keyVersion = TeeGuard.requireText(request.keyVersion(), "keyVersion");
        String assetId = TeeGuard.requireText(request.assetId(), "assetId");
        String assetVersion = TeeGuard.requireText(request.assetVersion(), "assetVersion");
        X509Certificate recipient = registry.requireInstitutionCertificate(ownerId, request.recipientCertPem());
        String fingerprint = TeeIdempotency.fingerprint(
                List.of(assetId, assetVersion, keyId, keyVersion, TeeCrypto.certificateSha256(recipient)));
        return idempotency.execute(ownerId, "keys/claim", requestId, fingerprint, ClaimResult.class, () -> {
            TeeKeyDO key = require(keyId, keyVersion);
            TeeGuard.requireOwner(key.getOwnerId(), ownerId);
            // 申领必须指向该密钥实际绑定的资产版本，避免调用方误取其他资产的密钥。
            if (!key.getAssetId().equals(assetId) || !key.getAssetVersion().equals(assetVersion)) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED, "密钥与资产版本绑定不符");
            }
            requireActive(key);
            JsonNode sealed = adapter.call("/v1/keys/escrow-seal", Map.of(
                    "resourceUri", key.getResourceUri(),
                    "recipientCertPemB64", encodeCertificate(recipient)));
            key.setClaimCount(key.getClaimCount() + 1);
            keys.save(key);
            return new ClaimResult(TeeContract.VERSION, envelope(key, sealed));
        });
    }

    /** 吊销后拒绝后续申领与运行时放行；已释放的密钥与既有明文导出无法追回。 */
    @Transactional
    public RevokeResult revoke(String ownerId, RevokeRequest request) {
        TeeGuard.requireVersion(request.contractVersion());
        String requestId = TeeGuard.requireText(request.requestId(), "requestId");
        String keyId = TeeGuard.requireText(request.keyId(), "keyId");
        String keyVersion = TeeGuard.requireText(request.keyVersion(), "keyVersion");
        TeeGuard.requireText(request.reason(), "reason");
        String fingerprint = TeeIdempotency.fingerprint(List.of(keyId, keyVersion));
        return idempotency.execute(ownerId, "keys/revoke", requestId, fingerprint, RevokeResult.class, () -> {
            TeeKeyDO key = require(keyId, keyVersion);
            TeeGuard.requireOwner(key.getOwnerId(), ownerId);
            List<String> scopes = new ArrayList<>();
            for (TeePolicyDO policy : policies.findByAssetIdAndAssetVersion(key.getAssetId(), key.getAssetVersion())) {
                scopes.add(policy.getUpk().getPolicyId());
                policy.setState(TeeContract.STATE_REVOKED);
                policies.save(policy);
            }
            adapter.call("/v1/keys/revoke", Map.of("resourceUri", key.getResourceUri(), "scopes", scopes));
            key.setState(TeeContract.STATE_REVOKED);
            keys.save(key);
            return new RevokeResult(TeeContract.VERSION, keyId, keyVersion, TeeContract.STATE_REVOKED);
        });
    }

    /** 台账只返回标识与计数，绝不返回密钥材料。 */
    public List<LedgerItem> ledger(String ownerId) {
        return keys.findByOwnerId(ownerId).stream()
                .sorted(Comparator.comparing(TeeKeyDO::getIssuedAt).reversed())
                .map(key -> new LedgerItem(key.getUpk().getKeyId(), key.getUpk().getKeyVersion(),
                        key.getAssetId(), key.getOwnerId(), key.getState(), key.getIssuedAt(),
                        key.getClaimCount(), key.getReleaseCount()))
                .toList();
    }

    TeeKeyDO require(String keyId, String keyVersion) {
        return keys.findById(new TeeKeyDO.UPK(keyId, keyVersion))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密钥不存在"));
    }

    void requireActive(TeeKeyDO key) {
        if (!TeeContract.STATE_ACTIVE.equals(key.getState())) {
            throw TeeException.of(TeeContract.Error.KEY_REVOKED, "密钥已吊销");
        }
    }

    void countRelease(TeeKeyDO key) {
        key.setReleaseCount(key.getReleaseCount() + 1);
        keys.save(key);
    }

    /** 结果出域信封按一次密钥申领记账，不把它混入可信运行时放行计数。 */
    void countClaim(TeeKeyDO key) {
        key.setClaimCount(key.getClaimCount() + 1);
        keys.save(key);
    }

    Optional<TeeKeyDO> active(String assetId, String assetVersion) {
        return keys.findByAssetIdAndAssetVersion(assetId, assetVersion).stream()
                .filter(key -> TeeContract.STATE_ACTIVE.equals(key.getState())).findFirst();
    }

    KeyEnvelope envelope(TeeKeyDO key, JsonNode sealed) {
        return new KeyEnvelope(key.getUpk().getKeyId(), key.getUpk().getKeyVersion(),
                TeeContract.ENVELOPE_ALGORITHM, sealed.path("recipientCertSha256").asText(),
                sealed.path("wrappedKeyB64").asText());
    }

    static String encodeCertificate(X509Certificate certificate) {
        try {
            String pem = "-----BEGIN CERTIFICATE-----\n"
                    + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
            return TeeCrypto.encode(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "接收者证书编码失败");
        }
    }

    /** 同一资产的归属以首次签发登记为准；不同机构再次申请一律拒绝。 */
    private void requireAssetOwner(String assetId, String ownerId) {
        for (TeeKeyDO key : keys.findByAssetId(assetId)) {
            if (!key.getOwnerId().equals(ownerId)) {
                throw TeeException.of(TeeContract.Error.ASSET_OWNER_MISMATCH, "该资产已由其他机构登记");
            }
        }
    }
}
