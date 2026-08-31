/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeNonceDO;
import org.springframework.stereotype.Repository;

/** 任务 nonce 去重；按签发方与 nonce 全局唯一，保留至过期后 24 小时。 */
@Repository
public interface TeeNonceRepository extends BaseRepository<TeeNonceDO, TeeNonceDO.UPK> {
}
