/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.persistence.repository;

import org.secretflow.secretpad.persistence.entity.TeeExportRequestDO;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** TEE 导出工单仓储。 */
@Repository
public interface TeeExportRequestRepository
        extends BaseRepository<TeeExportRequestDO, TeeExportRequestDO.UPK> {

    Optional<TeeExportRequestDO> findByRequestId(String requestId);

    List<TeeExportRequestDO> findByRequesterOwnerIdOrderByGmtCreateDesc(String requesterOwnerId);

    List<TeeExportRequestDO> findByResultIdAndRequesterOwnerIdAndStatusOrderByGmtCreateDesc(
            String resultId, String requesterOwnerId, String status);

    List<TeeExportRequestDO> findByResultIdAndRequesterOwnerIdOrderByGmtCreateDesc(
            String resultId, String requesterOwnerId);

    List<TeeExportRequestDO> findByObjectIdAndStatus(String objectId, String status);

    /** 信任链看板的全量视图，按创建时间倒序，上限 200 条。 */
    List<TeeExportRequestDO> findTop200ByOrderByGmtCreateDesc();
}
