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

    /**
     * 可清理的记录。
     *
     * <p>两类：超过契约最短保留期的，以及登记了提前失效时刻且已到期的。
     * 出域信封属于后者——它的可用窗口只有五分钟，没有理由按通用保留期驻留。
     */
    @Query("select r from TeeRequestDO r where r.createdAt < :deadline"
            + " or (r.retainUntil is not null and r.retainUntil < :now)")
    List<TeeRequestDO> findRetentionExpired(@Param("deadline") String deadline,
                                            @Param("now") String now);
}
