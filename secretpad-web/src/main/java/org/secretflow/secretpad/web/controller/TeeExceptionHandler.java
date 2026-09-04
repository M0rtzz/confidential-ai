/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.UUID;

/**
 * 契约接口的拒绝响应。
 *
 * <p>沿用冻结的响应包装：业务拒绝为 HTTP 200 且 status.code 非零，其余按契约映射状态码。
 * 错误 data 固定四个字段，不含密钥、数据行或内部堆栈。
 */
@RestControllerAdvice(assignableTypes = TeeApi.class)
public class TeeExceptionHandler {

    @ExceptionHandler(TeeException.class)
    public ResponseEntity<Map<String, Object>> handle(TeeException failure) {
        return build(failure.error());
    }

    /** 请求体结构错误在进入服务前就会失败；一律归为契约格式错误，不回显原始输入。 */
    @ExceptionHandler({org.springframework.http.converter.HttpMessageNotReadableException.class,
            org.springframework.web.bind.MethodArgumentNotValidException.class,
            IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> handleMalformed(Exception ignored) {
        return build(TeeContract.Error.CONTRACT_INVALID);
    }

    private static ResponseEntity<Map<String, Object>> build(TeeContract.Error error) {
        Map<String, Object> body = Map.of(
                "status", Map.of("code", error.code(), "msg", error.name()),
                "data", Map.of("contractVersion", TeeContract.VERSION,
                        "errorCode", error.name(),
                        "requestId", UUID.randomUUID().toString(),
                        "retryable", error.retryable()));
        return ResponseEntity.status(error.httpStatus()).body(body);
    }
}
