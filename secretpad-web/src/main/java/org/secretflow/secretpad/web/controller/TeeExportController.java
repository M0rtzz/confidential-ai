/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

import lombok.RequiredArgsConstructor;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.tee.TeeExportGateway;
import org.secretflow.secretpad.web.service.tee.TeeExportService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;

/** P7 结果导出工单、机构投票和契约信封取回接口。 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1alpha1/tee")
public class TeeExportController implements TeeApi {

    private final TeeExportGateway gateway;

    @PostMapping("/exports")
    public SecretPadResponse<TeeExportService.RequestView> create(
            @RequestBody TeeExportService.CreateRequest request) {
        return SecretPadResponse.success(gateway.create(owner(), actor(), request));
    }

    @GetMapping("/exports/exportable")
    public SecretPadResponse<TeeExportService.ExportableResult> exportable() {
        return SecretPadResponse.success(gateway.exportable(owner()));
    }

    @GetMapping("/exports/mine")
    public SecretPadResponse<TeeExportService.ListResult> mine() {
        return SecretPadResponse.success(gateway.mine(owner()));
    }

    @GetMapping("/exports/pending")
    public SecretPadResponse<TeeExportService.ListResult> pending() {
        return SecretPadResponse.success(gateway.pending(owner()));
    }

    @GetMapping("/exports/{exportId}")
    public SecretPadResponse<TeeExportService.RequestView> detail(@PathVariable String exportId) {
        return SecretPadResponse.success(gateway.detail(owner(), exportId));
    }

    @PostMapping("/exports/{exportId}/action")
    public SecretPadResponse<TeeExportService.RequestView> action(@PathVariable String exportId,
            @RequestBody TeeExportService.ActionRequest request) {
        return SecretPadResponse.success(gateway.action(owner(), actor(), exportId, request));
    }

    @PostMapping("/exports/{exportId}/cancel")
    public SecretPadResponse<TeeExportService.RequestView> cancel(@PathVariable String exportId,
            @RequestBody TeeExportService.CancelRequest request) {
        return SecretPadResponse.success(gateway.cancel(owner(), actor(), exportId, request));
    }

    /** 取回并本地解封，直接回传结果明文；响应体不是契约包装，出错时仍由 TeeExceptionHandler 处理。 */
    @PostMapping("/exports/{exportId}/download")
    public ResponseEntity<byte[]> download(@PathVariable String exportId) {
        TeeExportGateway.Download result = gateway.download(owner(), actor(), exportId);
        String encoded = URLEncoder.encode(result.fileName(), StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + result.fileName() + "\"; filename*=UTF-8''" + encoded)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.parseMediaType(result.contentType()))
                .body(result.content());
    }

    @PostMapping("/results/{resultId}/export")
    public SecretPadResponse<TeeExportService.ExportResult> export(@PathVariable String resultId,
            @RequestBody TeeExportService.ExportRequest request) {
        return SecretPadResponse.success(gateway.export(owner(), actor(), resultId, request));
    }

    private static String owner() {
        return UserContext.getUser().getOwnerId();
    }

    private static String actor() {
        return UserContext.getUser().getName();
    }
}
