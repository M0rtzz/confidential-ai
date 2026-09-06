/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */

package org.secretflow.secretpad.service.sync;

import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.persistence.entity.ProjectAssetDO;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProjectAssetUsageSnapshotGuardTest {
    private static final LocalDateTime BASE_TIME = LocalDateTime.of(2026, 9, 6, 12, 0);

    @Test
    void rejectsLowerVersion() {
        ProjectAssetDO existing = asset(2, "2026-09-30T00:00:00Z", BASE_TIME);
        ProjectAssetDO incoming = asset(1, "2026-09-29T00:00:00Z", BASE_TIME.plusMinutes(1));

        assertTrue(ProjectAssetUsageSnapshotGuard.reject(existing, incoming));
    }

    @Test
    void acceptsHigherVersion() {
        ProjectAssetDO existing = asset(2, "2026-09-30T00:00:00Z", BASE_TIME);
        ProjectAssetDO incoming = asset(3, "2026-10-01T00:00:00Z", BASE_TIME.minusMinutes(1));

        assertFalse(ProjectAssetUsageSnapshotGuard.reject(existing, incoming));
    }

    @Test
    void rejectsDifferentCutoffAtSamePositiveVersion() {
        ProjectAssetDO existing = asset(2, "2026-09-30T00:00:00Z", BASE_TIME);
        ProjectAssetDO incoming = asset(2, "2026-10-01T00:00:00Z", BASE_TIME.plusMinutes(1));

        assertTrue(ProjectAssetUsageSnapshotGuard.reject(existing, incoming));
    }

    @Test
    void acceptsSamePositiveVersionAndSameCutoff() {
        ProjectAssetDO existing = asset(2, "2026-09-30T00:00:00Z", BASE_TIME);
        ProjectAssetDO incoming = asset(2, "2026-09-30T00:00:00Z", BASE_TIME.plusMinutes(1));

        assertFalse(ProjectAssetUsageSnapshotGuard.reject(existing, incoming));
    }

    @Test
    void rejectsOlderSnapshotWhenBothHaveNoVersion() {
        ProjectAssetDO existing = asset(0, "2026-09-30T00:00:00Z", BASE_TIME);
        ProjectAssetDO incoming = asset(0, "2026-10-01T00:00:00Z", BASE_TIME.minusMinutes(1));

        assertTrue(ProjectAssetUsageSnapshotGuard.reject(existing, incoming));
    }

    @Test
    void allowsSoftDeleteRegardlessOfSnapshotAge() {
        ProjectAssetDO existing = asset(2, "2026-09-30T00:00:00Z", BASE_TIME);
        ProjectAssetDO incoming = asset(1, "2026-09-29T00:00:00Z", BASE_TIME.minusMinutes(1));
        incoming.setIsDeleted(true);

        assertFalse(ProjectAssetUsageSnapshotGuard.reject(existing, incoming));
    }

    private static ProjectAssetDO asset(long version, String cutoff, LocalDateTime modified) {
        ProjectAssetDO asset = new ProjectAssetDO();
        asset.setAssetJson("{\"usage_control_version\":" + version
                + ",\"control_valid_until\":\"" + cutoff + "\""
                + ",\"access_end\":\"" + cutoff + "\"}");
        asset.setExpiresAt(cutoff);
        asset.setGmtModified(modified);
        return asset;
    }
}
