/*
 * Copyright 2026 Ant Group Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 */
package org.secretflow.secretpad.web.service.sandbox;

import org.secretflow.secretpad.web.service.canvas.CanvasOperatorRegistry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 可授权的可信计算算子清单。
 *
 * <p>沙箱申请与挂载申请通过 {@code teeOperators} 承载授权算子，供数方投票批准的就是这份清单的子集；
 * 未被批准的算子在可信运行时一律拒绝。清单由数据开发的四类任务与画布内置算子合并而成，
 * 与实际下发到可信运行时的算子名保持一致。</p>
 */
public final class SandboxApprovalOperators {

    private static final String CATEGORY_DEV = "数据开发";

    private SandboxApprovalOperators() {
    }

    public static List<Map<String, Object>> list() {
        List<Map<String, Object>> rows = new ArrayList<>();
        rows.add(operator("sql.query", "SQL 查询", CATEGORY_DEV));
        rows.add(operator("python.execute", "Python 程序", CATEGORY_DEV));
        rows.add(operator("jar.execute", "JAR 程序", CATEGORY_DEV));
        rows.add(operator("function.execute", "自定义函数", CATEGORY_DEV));
        for (Map<String, Object> component : CanvasOperatorRegistry.builtInComponents()) {
            rows.add(operator(String.valueOf(component.get("code")),
                    String.valueOf(component.get("name")),
                    String.valueOf(component.get("category"))));
        }
        return rows;
    }

    private static Map<String, Object> operator(String code, String name, String category) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("code", code);
        row.put("name", name);
        row.put("category", category);
        return row;
    }
}
