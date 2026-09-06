/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 对可信执行侧返回的树报告执行第二次结构、引用和列级白名单校验。 */
public final class TeeTreeReportValidator {

    private static final Set<String> TOP_FIELDS = Set.of(
            "schemaVersion", "kind", "treeIndex", "treeCount", "nodeCount", "totalNodeCount",
            "leafCount", "maxDepth", "truncated", "truncatedNodeCount", "nodes");
    private static final Set<String> NODE_FIELDS = Set.of(
            "nodeId", "feature", "threshold", "leftChild", "rightChild", "value", "samples",
            "depth", "isLeaf", "truncatedChildren", "splitType", "comparison", "missingChild",
            "missingDirection", "categories", "cover", "gain");
    private static final Set<String> REQUIRED_NODE_FIELDS = Set.of(
            "nodeId", "feature", "threshold", "leftChild", "rightChild", "value", "samples",
            "depth", "isLeaf", "truncatedChildren", "splitType", "comparison", "missingChild",
            "missingDirection", "categories");
    private static final Set<String> KINDS = Set.of("SKLEARN_TREE", "XGBOOST", "LIGHTGBM");
    private static final Set<String> SPLIT_TYPES = Set.of("numerical", "categorical");
    private static final Set<String> COMPARISONS = Set.of("le", "lt", "in", "eq");
    private static final Set<String> MISSING_DIRECTIONS = Set.of("left", "right");
    private static final Set<String> TRUNCATED_SIDES = Set.of("left", "right", "missing");
    private static final int MAX_NODES = 800;

    private TeeTreeReportValidator() {
    }

    /**
     * 校验树报告并返回原始 JSON 节点；列授权失败使用 POLICY_DENIED，其余失败使用 CONTRACT_INVALID。
     */
    public static JsonNode validate(JsonNode content, List<String> features, int treeIndex) {
        if (content == null || !content.isObject()) {
            invalid("tree report must be an object");
        }
        if (treeIndex < 0) {
            invalid("treeIndex must be non-negative");
        }
        requireExactFields(content, TOP_FIELDS, "tree report fields");
        if (!"tree-report-v1".equals(text(content.get("schemaVersion")))) {
            invalid("tree report schema version is invalid");
        }
        if (!KINDS.contains(text(content.get("kind")))) {
            invalid("tree report kind is invalid");
        }

        JsonNode nodesNode = content.get("nodes");
        if (nodesNode == null || !nodesNode.isArray()
                || nodesNode.size() < 1 || nodesNode.size() > MAX_NODES) {
            invalid("tree report node count is invalid");
        }
        int nodeCount = requiredInt(content.get("nodeCount"), "nodeCount");
        int totalNodeCount = requiredInt(content.get("totalNodeCount"), "totalNodeCount");
        if (nodeCount != nodesNode.size() || totalNodeCount < nodeCount) {
            invalid("tree report node counts do not match");
        }
        int actualTreeIndex = requiredNonNegativeInt(content.get("treeIndex"), "treeIndex");
        if (actualTreeIndex != treeIndex) {
            invalid("tree report treeIndex does not match the request");
        }
        JsonNode treeCountNode = content.get("treeCount");
        Integer treeCount = nullablePositiveInt(treeCountNode, "treeCount");
        if (treeCount != null && actualTreeIndex >= treeCount) {
            invalid("treeIndex is outside the tree range");
        }
        int leafCount = requiredInt(content.get("leafCount"), "leafCount");
        JsonNode maxDepthNode = content.get("maxDepth");
        Integer maxDepth = nullableNonNegativeInt(maxDepthNode, "maxDepth");
        JsonNode truncatedNode = content.get("truncated");
        if (truncatedNode == null || !truncatedNode.isBoolean()
                || truncatedNode.booleanValue() != (totalNodeCount > nodeCount)) {
            invalid("tree report truncation state is invalid");
        }
        int truncatedNodeCount = requiredInt(content.get("truncatedNodeCount"), "truncatedNodeCount");
        if (truncatedNodeCount != totalNodeCount - nodeCount
                || leafCount < 0 || leafCount > nodeCount) {
            invalid("tree report summary is invalid");
        }
        Set<String> authorizedFeatures = validateFeatures(features);

        Map<String, NodeRecord> byId = new LinkedHashMap<>();
        for (JsonNode node : nodesNode) {
            NodeRecord record = validateNode(node, authorizedFeatures);
            if (byId.put(record.idKey(), record) != null) {
                invalid("tree report contains duplicate nodeId");
            }
        }
        validateReferences(byId, nodesNode, truncatedNode.booleanValue());

        Set<String> roots = new HashSet<>(byId.keySet());
        for (NodeRecord node : byId.values()) {
            if (node.parentLeft() != null) {
                roots.remove(node.parentLeft());
            }
            if (node.parentRight() != null) {
                roots.remove(node.parentRight());
            }
        }
        if (roots.size() != 1) {
            invalid("tree report must contain exactly one root");
        }
        validateTraversal(byId, roots.iterator().next());
        int actualLeafCount = (int) byId.values().stream().filter(NodeRecord::leaf).count();
        if (actualLeafCount != leafCount) {
            invalid("tree report leaf count does not match");
        }
        int actualMaxDepth = byId.values().stream().mapToInt(NodeRecord::depth).max().orElse(-1);
        if (maxDepth == null || actualMaxDepth != maxDepth) {
            invalid("tree report maxDepth does not match");
        }
        int bytes = content.toString().getBytes(StandardCharsets.UTF_8).length;
        if (bytes > TeeContract.MAX_REPORT_BYTES) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "tree report exceeds contract size");
        }
        return content;
    }

    private static Set<String> validateFeatures(List<String> features) {
        if (features == null) {
            invalid("tree report features are missing");
        }
        Set<String> authorized = new HashSet<>();
        for (String feature : features) {
            if (feature == null || feature.isEmpty()) {
                invalid("tree report feature authorization is invalid");
            }
            authorized.add(feature);
        }
        return authorized;
    }

    private static NodeRecord validateNode(JsonNode node, Set<String> authorizedFeatures) {
        if (node == null || !node.isObject()) {
            invalid("tree report node is not an object");
        }
        Set<String> fields = fieldNames(node);
        if (!NODE_FIELDS.containsAll(fields) || !fields.containsAll(REQUIRED_NODE_FIELDS)) {
            invalid("tree report node fields are invalid");
        }
        JsonNode nodeId = node.get("nodeId");
        String idKey = idKey(nodeId, "nodeId");
        String feature = textRequired(node.get("feature"), "feature");
        if (!feature.isEmpty() && !authorizedFeatures.contains(feature)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                    "tree report exposes an unauthorized feature");
        }
        int depth = requiredNonNegativeInt(node.get("depth"), "depth");
        JsonNode isLeaf = node.get("isLeaf");
        if (isLeaf == null || !isLeaf.isBoolean()) {
            invalid("tree report isLeaf is invalid");
        }
        if (!isNullOrNumericOrCategories(node.get("threshold"))) {
            invalid("tree report threshold is invalid");
        }
        if (!numeric(node.get("value")) || !numeric(node.get("samples"))) {
            invalid("tree report node values are invalid");
        }
        for (String field : List.of("cover", "gain")) {
            if (node.has(field) && !numeric(node.get(field))) {
                invalid("tree report node metric is invalid");
            }
        }
        List<String> truncatedChildren = requiredStringList(node.get("truncatedChildren"), "truncatedChildren");
        if (new HashSet<>(truncatedChildren).size() != truncatedChildren.size()
                || !TRUNCATED_SIDES.containsAll(truncatedChildren)) {
            invalid("tree report truncated children are invalid");
        }
        String splitType = nullableText(node.get("splitType"));
        if (splitType != null && !SPLIT_TYPES.contains(splitType)) {
            invalid("tree report splitType is invalid");
        }
        String comparison = nullableText(node.get("comparison"));
        if (comparison != null && !COMPARISONS.contains(comparison)) {
            invalid("tree report comparison is invalid");
        }
        String missingDirection = nullableText(node.get("missingDirection"));
        if (missingDirection != null && !MISSING_DIRECTIONS.contains(missingDirection)) {
            invalid("tree report missingDirection is invalid");
        }
        JsonNode categories = node.get("categories");
        if (!categories.isNull() && !categoryValues(categories)) {
            invalid("tree report categories are invalid");
        }
        boolean leaf = isLeaf.booleanValue();
        if (leaf) {
            if (!feature.isEmpty() || !node.get("threshold").isNull()
                    || !node.get("leftChild").isNull() || !node.get("rightChild").isNull()
                    || !node.get("missingChild").isNull() || missingDirection != null
                    || splitType != null || comparison != null || !categories.isNull()) {
                invalid("leaf node contains split fields");
            }
        } else {
            if (splitType == null || comparison == null) {
                invalid("split node is missing split metadata");
            }
            if ("categorical".equals(splitType) && !"in".equals(comparison)) {
                invalid("categorical split comparison is invalid");
            }
            if ("numerical".equals(splitType) && !categories.isNull()) {
                invalid("numerical split contains categories");
            }
            if ("categorical".equals(splitType) && categories.size() == 0) {
                invalid("categorical split categories are empty");
            }
        }
        return new NodeRecord(idKey, node, leaf, depth,
                referenceKey(node.get("leftChild"), "leftChild"),
                referenceKey(node.get("rightChild"), "rightChild"));
    }

    private static void validateReferences(Map<String, NodeRecord> byId, JsonNode nodes, boolean truncated) {
        Map<String, String> parents = new HashMap<>();
        for (JsonNode node : nodes) {
            String id = idKey(node.get("nodeId"), "nodeId");
            NodeRecord record = byId.get(id);
            List<String> truncatedChildren = requiredStringList(node.get("truncatedChildren"), "truncatedChildren");
            for (String side : List.of("left", "right")) {
                String child = "left".equals(side) ? record.parentLeft() : record.parentRight();
                if (child != null) {
                    if (!byId.containsKey(child) || parents.put(child, id) != null || child.equals(id)) {
                        invalid("tree report child reference is invalid");
                    }
                } else if (!record.leaf() && !truncatedChildren.contains(side)) {
                    invalid("tree report split child is missing");
                }
            }
            String missing = referenceKey(node.get("missingChild"), "missingChild");
            if (missing != null) {
                if (!byId.containsKey(missing)
                        || (!missing.equals(record.parentLeft()) && !missing.equals(record.parentRight()))) {
                    invalid("tree report missing child reference is invalid");
                }
                String expected = missing.equals(record.parentLeft()) ? "left" : "right";
                if (!expected.equals(nullableText(node.get("missingDirection")))) {
                    invalid("tree report missing direction is invalid");
                }
            } else if (!node.get("missingDirection").isNull()) {
                invalid("tree report missing direction has no child");
            }
            if (truncatedChildren.contains("missing") && !truncated) {
                invalid("tree report has truncated missing child without truncation");
            }
        }
    }

    private static void validateTraversal(Map<String, NodeRecord> byId, String root) {
        Set<String> visited = new HashSet<>();
        ArrayDeque<Visit> stack = new ArrayDeque<>();
        stack.push(new Visit(root, 0));
        while (!stack.isEmpty()) {
            Visit visit = stack.pop();
            if (!visited.add(visit.id())) {
                invalid("tree report contains a cycle");
            }
            NodeRecord node = byId.get(visit.id());
            if (node == null || node.depth() != visit.depth()) {
                invalid("tree report depth or child reference is invalid");
            }
            if (node.parentRight() != null) {
                stack.push(new Visit(node.parentRight(), visit.depth() + 1));
            }
            if (node.parentLeft() != null) {
                stack.push(new Visit(node.parentLeft(), visit.depth() + 1));
            }
        }
        if (visited.size() != byId.size()) {
            invalid("tree report contains disconnected nodes");
        }
    }

    private static boolean isNullOrNumericOrCategories(JsonNode node) {
        return node != null && (node.isNull() || numeric(node) || categoryValues(node));
    }

    private static boolean numeric(JsonNode node) {
        return numeric(node, 0);
    }

    private static boolean numeric(JsonNode node, int depth) {
        if (node == null || node.isNull()) {
            return true;
        }
        if (node.isNumber()) {
            return !node.isFloatingPointNumber() || Double.isFinite(node.doubleValue());
        }
        if (!node.isArray() || depth >= 3) {
            return false;
        }
        for (JsonNode item : node) {
            if (!numeric(item, depth + 1)) {
                return false;
            }
        }
        return true;
    }

    private static boolean categoryValues(JsonNode node) {
        if (node == null || !node.isArray()) {
            return false;
        }
        for (JsonNode item : node) {
            if (item.isTextual()) {
                continue;
            }
            if (!item.isNumber() || (item.isFloatingPointNumber() && !Double.isFinite(item.doubleValue()))) {
                return false;
            }
        }
        return true;
    }

    private static String referenceKey(JsonNode node, String field) {
        if (node == null || node.isNull()) {
            return null;
        }
        return idKey(node, field);
    }

    private static String idKey(JsonNode node, String field) {
        if (node == null || (!node.isIntegralNumber() && !node.isTextual())) {
            invalid(field + " is invalid");
        }
        if (node.isTextual()) {
            if (node.textValue().isEmpty()) {
                invalid(field + " is empty");
            }
            return "s:" + node.textValue();
        }
        return "n:" + node.bigIntegerValue();
    }

    private static List<String> requiredStringList(JsonNode node, String field) {
        if (node == null || !node.isArray()) {
            invalid(field + " must be an array");
        }
        List<String> values = new ArrayList<>();
        for (JsonNode item : node) {
            if (!item.isTextual()) {
                invalid(field + " contains an invalid value");
            }
            values.add(item.textValue());
        }
        return values;
    }

    private static Integer nullablePositiveInt(JsonNode node, String field) {
        if (node == null || node.isNull()) {
            return null;
        }
        int value = requiredInt(node, field);
        if (value <= 0) {
            invalid(field + " must be positive");
        }
        return value;
    }

    private static Integer nullableNonNegativeInt(JsonNode node, String field) {
        if (node == null || node.isNull()) {
            return null;
        }
        return requiredNonNegativeInt(node, field);
    }

    private static int requiredNonNegativeInt(JsonNode node, String field) {
        int value = requiredInt(node, field);
        if (value < 0) {
            invalid(field + " must be non-negative");
        }
        return value;
    }

    private static int requiredInt(JsonNode node, String field) {
        if (node == null || !node.isInt() && !node.isLong() && !node.isBigInteger()) {
            invalid(field + " must be an integer");
        }
        if (!node.canConvertToInt()) {
            invalid(field + " is out of range");
        }
        return node.intValue();
    }

    private static String textRequired(JsonNode node, String field) {
        if (node == null || !node.isTextual()) {
            invalid(field + " must be text");
        }
        return node.textValue();
    }

    private static String nullableText(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        return node.isTextual() ? node.textValue() : "<invalid>";
    }

    private static String text(JsonNode node) {
        return node != null && node.isTextual() ? node.textValue() : "";
    }

    private static void requireExactFields(JsonNode node, Set<String> expected, String field) {
        if (!fieldNames(node).equals(expected)) {
            invalid(field + " are not on the allowlist");
        }
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new HashSet<>();
        Iterator<String> fields = node.fieldNames();
        fields.forEachRemaining(names::add);
        return names;
    }

    private static void invalid(String message) {
        throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, message);
    }

    private record NodeRecord(String idKey, JsonNode node, boolean leaf, int depth,
                              String parentLeft, String parentRight) {
    }

    private record Visit(String id, int depth) {
    }
}
