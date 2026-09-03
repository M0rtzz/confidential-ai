/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeRequestDO;
import org.secretflow.secretpad.persistence.repository.TeeRequestRepository;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * 幂等记录。
 *
 * <p>按调用主体、操作与 requestId 保存至少 24 小时：相同内容重试返回原结果，
 * 相同标识不同内容拒绝。指纹按已校验字段的确定性序列计算，不使用原始 JSON 属性顺序。
 */
@Component
public class TeeIdempotency {

    private final TeeRequestRepository repository;
    private final ObjectMapper mapper;

    public TeeIdempotency(TeeRequestRepository repository, ObjectMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /** 指纹只覆盖已校验后的确定性字段序列，调用方按业务顺序传入。 */
    public static String fingerprint(List<String> canonicalFields) {
        return TeeCrypto.sha256Hex(String.join("", canonicalFields).getBytes(StandardCharsets.UTF_8));
    }

    public <T> T execute(String ownerId, String operation, String requestId, String fingerprint,
                         Class<T> type, Supplier<T> action) {
        return execute(ownerId, operation, requestId, fingerprint, type, action, result -> null);
    }

    /**
     * 带提前失效时刻的幂等执行。
     *
     * <p>{@code retainUntil} 从结果中取出该记录的失效时刻；返回 null 表示按通用保留期处理。
     * 出域信封用它把留存窗口收敛到信封自身的有效期，避免密封密钥材料长期驻留。
     */
    public <T> T execute(String ownerId, String operation, String requestId, String fingerprint,
                         Class<T> type, Supplier<T> action, Function<T, String> retainUntil) {
        String key = TeeCrypto.sha256Hex((ownerId + "" + operation + "" + requestId)
                .getBytes(StandardCharsets.UTF_8));
        Optional<TeeRequestDO> existing = repository.findById(new TeeRequestDO.UPK(key));
        if (existing.isPresent()) {
            TeeRequestDO record = existing.get();
            if (!record.getFingerprint().equals(fingerprint)) {
                throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT, "相同请求标识对应不同内容");
            }
            try {
                return mapper.readValue(record.getResponseJson(), type);
            } catch (Exception failure) {
                throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "已保存的幂等结果无法读取");
            }
        }
        T result = action.get();
        try {
            repository.save(TeeRequestDO.builder()
                    .upk(new TeeRequestDO.UPK(key))
                    .fingerprint(fingerprint)
                    .responseJson(mapper.writeValueAsString(result))
                    .createdAt(Instant.now().toString())
                    .ownerId(ownerId)
                    .retainUntil(retainUntil.apply(result))
                    .build());
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "幂等记录写入失败");
        }
        return result;
    }
}
