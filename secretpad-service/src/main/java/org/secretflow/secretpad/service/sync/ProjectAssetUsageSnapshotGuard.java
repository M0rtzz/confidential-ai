/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */

package org.secretflow.secretpad.service.sync;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.ProjectAssetDO;

import java.time.LocalDateTime;
import java.util.List;

/** 防止较旧的使用控制快照覆盖当前项目资产的有效期限。 */
final class ProjectAssetUsageSnapshotGuard {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<String> CONTROL_FIELDS = List.of(
            "control_valid_from", "control_valid_until", "access_start", "access_end");

    private ProjectAssetUsageSnapshotGuard() {
    }

    static boolean reject(ProjectAssetDO existing, ProjectAssetDO incoming) {
        if (existing == null || incoming == null || Boolean.TRUE.equals(incoming.getIsDeleted())) {
            return false;
        }
        JsonNode existingSnapshot = snapshot(existing.getAssetJson());
        JsonNode incomingSnapshot = snapshot(incoming.getAssetJson());
        long existingVersion = version(existingSnapshot);
        long incomingVersion = version(incomingSnapshot);
        if (existingVersion > 0) {
            if (incomingVersion < existingVersion) {
                return true;
            }
            return incomingVersion == existingVersion
                    && !sameControl(existingSnapshot, incomingSnapshot, existing, incoming);
        }
        if (incomingVersion > 0) {
            return false;
        }
        LocalDateTime existingModified = existing.getGmtModified();
        LocalDateTime incomingModified = incoming.getGmtModified();
        return existingModified != null
                && incomingModified != null
                && incomingModified.isBefore(existingModified);
    }

    private static boolean sameControl(JsonNode existingSnapshot, JsonNode incomingSnapshot,
            ProjectAssetDO existing, ProjectAssetDO incoming) {
        for (String field : CONTROL_FIELDS) {
            String existingValue = controlValue(existingSnapshot, field);
            String incomingValue = controlValue(incomingSnapshot, field);
            if (!existingValue.equals(incomingValue)) {
                return false;
            }
        }
        return normalize(existing.getExpiresAt()).equals(normalize(incoming.getExpiresAt()));
    }

    private static String controlValue(JsonNode snapshot, String field) {
        String value = text(snapshot, field);
        if (!value.isEmpty()) {
            return value;
        }
        if ("control_valid_from".equals(field)) {
            return text(snapshot, "valid_from");
        }
        if ("control_valid_until".equals(field)) {
            return text(snapshot, "valid_until");
        }
        return "";
    }

    private static JsonNode snapshot(String value) {
        if (value == null || value.isBlank()) {
            return MAPPER.createObjectNode();
        }
        try {
            return MAPPER.readTree(value);
        } catch (Exception ignored) {
            return MAPPER.createObjectNode();
        }
    }

    private static long version(JsonNode snapshot) {
        JsonNode value = snapshot.path("usage_control_version");
        if (value.isIntegralNumber()) {
            return Math.max(0L, value.longValue());
        }
        try {
            return Math.max(0L, Long.parseLong(value.asText("0").trim()));
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    private static String text(JsonNode snapshot, String field) {
        return normalize(snapshot.path(field).asText(""));
    }

    private static String normalize(String value) {
        return value == null || "null".equalsIgnoreCase(value.trim()) ? "" : value.trim();
    }
}
