/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeRequestDO;
import org.springframework.stereotype.Repository;

/** 幂等记录；相同内容重试返回原结果，相同标识不同内容拒绝。 */
@Repository
public interface TeeRequestRepository extends BaseRepository<TeeRequestDO, TeeRequestDO.UPK> {
}
