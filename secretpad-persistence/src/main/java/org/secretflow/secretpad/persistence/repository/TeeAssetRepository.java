/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.springframework.stereotype.Repository;

import java.util.List;

/** 密文资产登记；中心端只保存结构与密文引用，不保存数据行。 */
@Repository
public interface TeeAssetRepository extends BaseRepository<TeeAssetDO, TeeAssetDO.UPK> {

    /** 按资产标识取已登记的密文资产版本。 */
    List<TeeAssetDO> findByUpkAssetId(String assetId);

    /** 按机构列出已登记的密文资产。 */
    List<TeeAssetDO> findByOwnerId(String ownerId);
}
