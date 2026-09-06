/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TeeTreeReportValidatorTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void acceptsReportsProducedForAllSupportedTreeKinds() {
        for (String kind : List.of("SKLEARN_TREE", "XGBOOST", "LIGHTGBM")) {
            ObjectNode report = validReport();
            report.put("kind", kind);
            assertEquals(report, TeeTreeReportValidator.validate(report, List.of("age"), 0));
        }
    }

    @Test
    void rejectsUnknownFields() {
        ObjectNode report = validReport();
        report.put("unexpected", true);

        assertError(TeeContract.Error.CONTRACT_INVALID, report, List.of("age"), 0);
    }

    @Test
    void rejectsUnauthorizedFeatureWithPolicyError() {
        ObjectNode report = validReport();
        ((ObjectNode) report.withArray("nodes").get(0)).put("feature", "secret");

        assertError(TeeContract.Error.POLICY_DENIED, report, List.of("age"), 0);
    }

    @Test
    void rejectsDuplicateIdsAndMissingReferences() {
        ObjectNode duplicate = validReport();
        ((ObjectNode) duplicate.withArray("nodes").get(2)).put("nodeId", 1);
        assertError(TeeContract.Error.CONTRACT_INVALID, duplicate, List.of("age"), 0);

        ObjectNode missing = validReport();
        ((ObjectNode) missing.withArray("nodes").get(0)).put("rightChild", 99);
        assertError(TeeContract.Error.CONTRACT_INVALID, missing, List.of("age"), 0);
    }

    @Test
    void rejectsSelfCycleAndTreeIndexMismatch() {
        ObjectNode cycle = validReport();
        ((ObjectNode) cycle.withArray("nodes").get(0)).put("leftChild", 0);
        assertError(TeeContract.Error.CONTRACT_INVALID, cycle, List.of("age"), 0);

        assertError(TeeContract.Error.CONTRACT_INVALID, validReport(), List.of("age"), 1);
    }

    @Test
    void rejectsMoreThanEightHundredNodes() {
        ObjectNode report = validReport();
        ArrayNode nodes = report.withArray("nodes");
        for (int index = 3; index <= 801; index++) {
            nodes.addObject().put("nodeId", index);
        }
        report.put("nodeCount", nodes.size());
        report.put("totalNodeCount", nodes.size());

        assertError(TeeContract.Error.CONTRACT_INVALID, report, List.of("age"), 0);
    }

    private ObjectNode validReport() {
        ObjectNode report = mapper.createObjectNode();
        report.put("schemaVersion", "tree-report-v1");
        report.put("kind", "SKLEARN_TREE");
        report.put("treeIndex", 0);
        report.put("treeCount", 1);
        report.put("nodeCount", 3);
        report.put("totalNodeCount", 3);
        report.put("leafCount", 2);
        report.put("maxDepth", 1);
        report.put("truncated", false);
        report.put("truncatedNodeCount", 0);
        ArrayNode nodes = report.putArray("nodes");
        nodes.add(splitNode(0, "age", 1, 2));
        nodes.add(leafNode(1, 50));
        nodes.add(leafNode(2, 50));
        return report;
    }

    private ObjectNode splitNode(int id, String feature, int left, int right) {
        ObjectNode node = mapper.createObjectNode();
        node.put("nodeId", id);
        node.put("feature", feature);
        node.put("threshold", 18.5);
        node.put("leftChild", left);
        node.put("rightChild", right);
        node.put("value", 100);
        node.put("samples", 100);
        node.put("depth", 0);
        node.put("isLeaf", false);
        node.putArray("truncatedChildren");
        node.put("splitType", "numerical");
        node.put("comparison", "le");
        node.putNull("missingChild");
        node.putNull("missingDirection");
        node.putNull("categories");
        return node;
    }

    private ObjectNode leafNode(int id, int samples) {
        ObjectNode node = mapper.createObjectNode();
        node.put("nodeId", id);
        node.put("feature", "");
        node.putNull("threshold");
        node.putNull("leftChild");
        node.putNull("rightChild");
        node.put("value", 0);
        node.put("samples", samples);
        node.put("depth", 1);
        node.put("isLeaf", true);
        node.putArray("truncatedChildren");
        node.putNull("splitType");
        node.putNull("comparison");
        node.putNull("missingChild");
        node.putNull("missingDirection");
        node.putNull("categories");
        return node;
    }

    private void assertError(TeeContract.Error error, ObjectNode report, List<String> features, int treeIndex) {
        assertEquals(error, assertThrows(TeeException.class,
                () -> TeeTreeReportValidator.validate(report, features, treeIndex)).error());
    }
}
