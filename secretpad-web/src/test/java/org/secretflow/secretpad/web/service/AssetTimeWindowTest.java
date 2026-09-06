/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class AssetTimeWindowTest {
    @Test
    void exactDeadlineIsExclusiveAcrossTimeZones() {
        Instant cutoff = Instant.parse("2026-09-29T16:00:00Z");
        assertTrue(AssetTimeWindow.within(null, "2026-09-30T00:00:00", cutoff.minusNanos(1)));
        assertFalse(AssetTimeWindow.within(null, "2026-09-30T00:00:00", cutoff));
        assertFalse(AssetTimeWindow.within(null, "2026-09-29T16:00:00.000Z", cutoff.plusSeconds(1)));
    }

    @Test
    void dateOnlyIncludesTheSelectedDayAndInvalidDeadlineNeverAllowsUse() {
        assertTrue(AssetTimeWindow.within(null, "2026-09-30", Instant.parse("2026-09-30T15:59:59Z")));
        assertFalse(AssetTimeWindow.within(null, "2026-09-30", Instant.parse("2026-09-30T16:00:00Z")));
        assertFalse(AssetTimeWindow.within(null, "invalid", Instant.now()));
    }
}
