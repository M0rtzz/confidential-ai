/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeNonceDO;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/** 任务 nonce 去重；按签发方与 nonce 全局唯一，保留至过期后 24 小时。 */
@Repository
public interface TeeNonceRepository extends BaseRepository<TeeNonceDO, TeeNonceDO.UPK> {

    /** 保留期已过的记录；expiresAt 存的是过期时间加保留期后的时刻。 */
    @Query("select n from TeeNonceDO n where n.expiresAt < :deadline")
    List<TeeNonceDO> findRetentionExpired(@Param("deadline") String deadline);
}
