/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.canvas;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 算子输出列推导。
 *
 * <p>可信执行模式下平台读不到密文产物的表头，派生资产的登记表结构与节点配置态的可选列都取自
 * 这里。推导口径一旦与运行器 {@code modeling_ops} 不符，下游节点会选到不存在的列。
 */
class CanvasOperatorOutputColumnsTest {

    private static final List<String> INPUT = List.of("age", "income", "is_default");

    @Test
    void inPlaceOperatorsKeepColumns() {
        for (String code : List.of("preprocessing.fillna", "preprocessing.standardize",
                "preprocessing.outlier", "preprocessing.woe", "preprocessing.binning",
                "preprocessing.unique")) {
            assertEquals(INPUT, CanvasOperatorRegistry.outputColumns(code, Map.of(), INPUT), code);
        }
    }

    @Test
    void regressionTrainingAppendsPrediction() {
        assertEquals(List.of("age", "income", "is_default", "pred"),
                CanvasOperatorRegistry.outputColumns("ml.linear_regression",
                        Map.of("features", List.of("age", "income"), "label", "is_default"), INPUT));
    }

    @Test
    void classificationTrainingAppendsProbability() {
        assertEquals(List.of("age", "income", "is_default", "pred", "pred_prob"),
                CanvasOperatorRegistry.outputColumns("ml.xgboost",
                        Map.of("task", "classification"), INPUT));
    }

    @Test
    void treeModelFollowsTaskParameter() {
        assertEquals(List.of("age", "income", "is_default", "pred"),
                CanvasOperatorRegistry.outputColumns("ml.xgboost", Map.of("task", "regression"), INPUT));
    }

    @Test
    void clusteringAppendsClusterColumn() {
        assertEquals(List.of("age", "income", "is_default", "cluster"),
                CanvasOperatorRegistry.outputColumns("ml.kmeans", Map.of(), INPUT));
    }

    @Test
    void deriveAppendsNewColumn() {
        assertEquals(List.of("age", "income", "is_default", "high_income"),
                CanvasOperatorRegistry.outputColumns("preprocessing.derive",
                        Map.of("expression", "income > 20000", "new_column", "high_income"), INPUT));
    }

    @Test
    void deriveOverwritingExistingColumnDoesNotDuplicate() {
        assertEquals(INPUT, CanvasOperatorRegistry.outputColumns("preprocessing.derive",
                Map.of("expression", "income * 2", "new_column", "income"), INPUT));
    }

    @Test
    void reshapingOperatorsReturnFixedColumns() {
        assertEquals(List.of("column", "psi"),
                CanvasOperatorRegistry.outputColumns("preprocessing.psi", Map.of(), INPUT));
        assertEquals(List.of("column_a", "column_b", "value"),
                CanvasOperatorRegistry.outputColumns("stats.correlation", Map.of(), INPUT));
        assertEquals(List.of("column", "alignment", "dtype_input", "dtype_reference",
                        "rows_input", "rows_reference"),
                CanvasOperatorRegistry.outputColumns("preprocessing.feature_align", Map.of(), INPUT));
        assertEquals(List.of("metric", "value"),
                CanvasOperatorRegistry.outputColumns("ml.binary_classification", Map.of(), INPUT));
    }

    @Test
    void dataResourceNodePassesColumnsThrough() {
        assertEquals(INPUT, CanvasOperatorRegistry.outputColumns("data.table",
                Map.of("table", "asset_1"), INPUT));
    }

    @Test
    void unknownOperatorFallsBackToInput() {
        assertEquals(INPUT, CanvasOperatorRegistry.outputColumns("ml.unknown", Map.of(), INPUT));
    }
}
