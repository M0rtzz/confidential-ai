/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import lombok.extern.slf4j.Slf4j;
import org.secretflow.secretpad.persistence.repository.TeeNonceRepository;
import org.secretflow.secretpad.persistence.repository.TeeRequestRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * 幂等记录与 nonce 的保留期清理。
 *
 * <p>契约要求幂等记录保留至少 24 小时、nonce 保留至过期后 24 小时。两张表原本只增不删，
 * 长期运行会持续增长；这里只删除已过保留期的记录，保留期内的重试判定与重放判定不受影响。
 *
 * <p>删除 nonce 不会放宽重放约束：任务本身最长 5 分钟有效，保留期外的 nonce 对应的任务
 * 早已过期，重放会先被时效校验拒绝。
 */
@Slf4j
@Component
public class TeeRetention {

    private final TeeNonceRepository nonces;
    private final TeeRequestRepository requests;

    public TeeRetention(TeeNonceRepository nonces, TeeRequestRepository requests) {
        this.nonces = nonces;
        this.requests = requests;
    }

    @Scheduled(fixedDelayString = "${secretpad.tee.retention.interval-ms:3600000}")
    @Transactional
    public void purge() {
        int removed = purgeOnce(Instant.now());
        if (removed > 0) {
            log.info("TEE 保留期清理完成，删除 {} 条已过期记录", removed);
        }
    }

    /** 按给定时刻执行一次清理，返回删除条数；时间参数便于定向测试。 */
    int purgeOnce(Instant now) {
        String nonceDeadline = now.toString();
        String requestDeadline = now.minusSeconds(TeeContract.RETENTION_SECONDS).toString();
        int removed = 0;
        for (var nonce : nonces.findRetentionExpired(nonceDeadline)) {
            nonces.delete(nonce);
            removed++;
        }
        for (var request : requests.findRetentionExpired(requestDeadline, now.toString())) {
            requests.delete(request);
            removed++;
        }
        return removed;
    }
}
