/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeExportVoteDO;
import org.springframework.stereotype.Repository;

import java.util.List;

/** TEE 导出机构票仓储。 */
@Repository
public interface TeeExportVoteRepository extends BaseRepository<TeeExportVoteDO, TeeExportVoteDO.UPK> {

    List<TeeExportVoteDO> findByUpkExportIdOrderByUpkVoterOwnerId(String exportId);

    List<TeeExportVoteDO> findByUpkVoterOwnerIdAndStatusOrderByGmtCreateDesc(
            String voterOwnerId, String status);
}
