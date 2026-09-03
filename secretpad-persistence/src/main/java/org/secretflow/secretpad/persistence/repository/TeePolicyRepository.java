/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.springframework.stereotype.Repository;

import java.util.List;

/** 授权规则登记；列与算子精确匹配，不支持通配符，空集合即禁止。 */
@Repository
public interface TeePolicyRepository extends BaseRepository<TeePolicyDO, TeePolicyDO.UPK> {

    /** 取资产版本上已登记的授权规则。 */
    List<TeePolicyDO> findByAssetIdAndAssetVersion(String assetId, String assetVersion);

    /** 中心端信任链看板的全量视图，按创建时间倒序，上限 200 条。 */
    List<TeePolicyDO> findTop200ByOrderByGmtCreateDesc();
}
