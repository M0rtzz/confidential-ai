/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeRequestDO;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/** 幂等记录；相同内容重试返回原结果，相同标识不同内容拒绝。 */
@Repository
public interface TeeRequestRepository extends BaseRepository<TeeRequestDO, TeeRequestDO.UPK> {

    /** 超过契约最短保留期的记录；清理只针对已过保留期的部分。 */
    @Query("select r from TeeRequestDO r where r.createdAt < :deadline")
    List<TeeRequestDO> findCreatedBefore(@Param("deadline") String deadline);
}
