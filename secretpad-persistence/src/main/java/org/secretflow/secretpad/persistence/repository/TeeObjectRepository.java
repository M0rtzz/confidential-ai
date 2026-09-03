/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

/** 密文对象元数据；对象本体存放于运行目录，库中不保存密文。 */
@Repository
public interface TeeObjectRepository extends BaseRepository<TeeObjectDO, TeeObjectDO.UPK> {

    /** 结果标识首次申领时用于原子绑定任务。 */
    List<TeeObjectDO> findByResultId(String resultId);

    /** 按任务列出产出对象。 */
    List<TeeObjectDO> findByTaskId(String taskId);

    /** 最近产出的密文结果对象；贡献方过滤在服务层按机构标识精确比对完成，不用字符串匹配。 */
    List<TeeObjectDO> findTop200ByKindInOrderByGmtCreateDesc(Collection<String> kinds);

    /** 信任链看板：中心端全量视图，按创建时间倒序，上限 200 条。 */
    List<TeeObjectDO> findTop200ByOrderByGmtCreateDesc();

    /** 信任链看板：客户端本地登记的对象（按机构过滤），按创建时间倒序，上限 200 条。 */
    List<TeeObjectDO> findTop200ByOwnerIdOrderByGmtCreateDesc(String ownerId);
}
