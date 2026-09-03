/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/** P7 客户端薄委派；客户端不保存或裁决导出工单。 */
@Service
public class TeeExportGateway {

    private final TeeExportService service;
    private final TeeCenterClient center;
    private final TeeInstitutionKey institutionKey;
    private final ObjectMapper mapper;

    public TeeExportGateway(TeeExportService service, TeeCenterClient center,
                            TeeInstitutionKey institutionKey, ObjectMapper mapper) {
        this.service = service;
        this.center = center;
        this.institutionKey = institutionKey;
        this.mapper = mapper;
    }

    public TeeExportService.RequestView create(String ownerId, String actor,
                                               TeeExportService.CreateRequest request) {
        TeeExportService.CreateRequest secured = new TeeExportService.CreateRequest(
                request.contractVersion(), request.requestId(), request.resultId(),
                center.configured() ? institutionKey.certificatePem() : request.recipientCertPem());
        return center.configured()
                ? center.post("/exports", secured, TeeExportService.RequestView.class)
                : service.create(ownerId, actor, secured);
    }

    public TeeExportService.ListResult mine(String ownerId) {
        return center.configured() ? list(center.get("/exports/mine", JsonNode.class)) : service.mine(ownerId);
    }

    public TeeExportService.ListResult pending(String ownerId) {
        return center.configured() ? list(center.get("/exports/pending", JsonNode.class)) : service.pending(ownerId);
    }

    public TeeExportService.RequestView detail(String ownerId, String exportId) {
        return center.configured()
                ? center.get("/exports/" + path(exportId), TeeExportService.RequestView.class)
                : service.detail(ownerId, exportId);
    }

    public TeeExportService.RequestView action(String ownerId, String actor, String exportId,
                                               TeeExportService.ActionRequest request) {
        return center.configured()
                ? center.post("/exports/" + path(exportId) + "/action", request,
                        TeeExportService.RequestView.class)
                : service.action(ownerId, actor, exportId, request);
    }

    public TeeExportService.RequestView cancel(String ownerId, String actor, String exportId,
                                               TeeExportService.CancelRequest request) {
        return center.configured()
                ? center.post("/exports/" + path(exportId) + "/cancel", request,
                        TeeExportService.RequestView.class)
                : service.cancel(ownerId, actor, exportId, request);
    }

    public TeeExportService.ExportResult export(String ownerId, String actor, String resultId,
                                                TeeExportService.ExportRequest request) {
        TeeExportService.ExportRequest secured = new TeeExportService.ExportRequest(
                request.contractVersion(), request.requestId(),
                center.configured() ? institutionKey.certificatePem() : request.recipientCertPem());
        return center.configured()
                ? center.post("/results/" + path(resultId) + "/export", secured,
                        TeeExportService.ExportResult.class)
                : service.export(ownerId, actor, resultId, secured);
    }

    private TeeExportService.ListResult list(JsonNode data) {
        List<TeeExportService.RequestView> items = new ArrayList<>();
        for (JsonNode item : data.path("items")) {
            try {
                items.add(mapper.treeToValue(item, TeeExportService.RequestView.class));
            } catch (Exception failure) {
                throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端导出工单结构不符");
            }
        }
        return new TeeExportService.ListResult(TeeContract.VERSION, items);
    }

    private static String path(String value) {
        String normalized = TeeGuard.requireText(value, "path");
        if (!normalized.matches("[A-Za-z0-9_-]{1,128}")) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "路径标识格式无效");
        }
        return normalized;
    }
}
