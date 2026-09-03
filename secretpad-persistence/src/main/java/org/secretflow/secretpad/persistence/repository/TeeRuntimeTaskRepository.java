/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.springframework.stereotype.Repository;

import java.util.List;

/** P5 运行时任务授权与已核实回执。 */
@Repository
public interface TeeRuntimeTaskRepository
        extends BaseRepository<TeeRuntimeTaskDO, TeeRuntimeTaskDO.UPK> {

    /** 信任链看板的全量视图，按创建时间倒序，上限 200 条。 */
    List<TeeRuntimeTaskDO> findTop200ByOrderByGmtCreateDesc();
}
