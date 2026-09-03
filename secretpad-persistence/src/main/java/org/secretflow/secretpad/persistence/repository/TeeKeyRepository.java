/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.springframework.stereotype.Repository;

import java.util.List;

/** 中心端签发的数据密钥台账；查询不返回密钥材料。 */
@Repository
public interface TeeKeyRepository extends BaseRepository<TeeKeyDO, TeeKeyDO.UPK> {

    /** 按资产版本查找已签发的密钥；每个资产版本对应一个数据密钥版本。 */
    List<TeeKeyDO> findByAssetIdAndAssetVersion(String assetId, String assetVersion);

    /** 按资产查找已签发的密钥，用于校验资产归属。 */
    List<TeeKeyDO> findByAssetId(String assetId);

    /** 台账查询按机构过滤。 */
    List<TeeKeyDO> findByOwnerId(String ownerId);

    /** 中心端信任链看板的全量视图，按创建时间倒序，上限 200 条。 */
    List<TeeKeyDO> findTop200ByOrderByGmtCreateDesc();
}
