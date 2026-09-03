/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** P7 客户端薄委派；客户端不保存或裁决导出工单。 */
@Service
public class TeeExportGateway {

    /** 一次下载的产物；明文只在响应写出期间存在，不落盘也不进幂等记录。 */
    public record Download(String fileName, String contentType, byte[] content) {
    }

    private final TeeExportService service;
    private final TeeCenterClient center;
    private final TeeInstitutionKey institutionKey;
    private final DataSandboxMvpService mvp;
    private final ObjectMapper mapper;

    public TeeExportGateway(TeeExportService service, TeeCenterClient center,
                            TeeInstitutionKey institutionKey, DataSandboxMvpService mvp,
                            ObjectMapper mapper) {
        this.service = service;
        this.center = center;
        this.institutionKey = institutionKey;
        this.mvp = mvp;
        this.mapper = mapper;
    }

    public TeeExportService.ExportableResult exportable(String ownerId) {
        return center.configured()
                ? exportableList(center.get("/exports/exportable", JsonNode.class))
                : service.exportable(ownerId);
    }

    public TeeExportService.RequestView create(String ownerId, String actor,
                                               TeeExportService.CreateRequest request) {
        TeeExportService.CreateRequest secured = new TeeExportService.CreateRequest(
                request.contractVersion(), request.requestId(), request.resultId(),
                center.configured() ? institutionKey.certificatePem() : request.recipientCertPem());
        if (!center.configured()) {
            return service.create(ownerId, actor, secured);
        }
        TeeExportService.RequestView view = center.post("/exports", secured,
                TeeExportService.RequestView.class);
        delegated(actor, "TEE_EXPORT_SUBMIT", view, "resultId=" + view.resultId()
                + " kind=" + view.kind());
        return view;
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
        if (!center.configured()) {
            return service.action(ownerId, actor, exportId, request);
        }
        TeeExportService.RequestView view = center.post("/exports/" + path(exportId) + "/action",
                request, TeeExportService.RequestView.class);
        String normalized = request.action() == null ? "" : request.action().trim().toUpperCase();
        delegated(actor, "TEE_EXPORT_" + ("REJECT".equals(normalized) ? "REJECT" : "APPROVE"),
                view, "ownerId=" + ownerId + " status=" + view.status());
        return view;
    }

    public TeeExportService.RequestView cancel(String ownerId, String actor, String exportId,
                                               TeeExportService.CancelRequest request) {
        if (!center.configured()) {
            return service.cancel(ownerId, actor, exportId, request);
        }
        TeeExportService.RequestView view = center.post("/exports/" + path(exportId) + "/cancel",
                request, TeeExportService.RequestView.class);
        delegated(actor, "TEE_EXPORT_CANCEL", view, "resultId=" + view.resultId());
        return view;
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

    /**
     * 取回信封并在本机构本地解封，返回结果明文。
     *
     * <p>契约规定普通中心平台不解密导出结果，因此只有配置了中心端契约通道的数据方实例
     * 才允许本地解封；中心裁决实例一律拒绝。信封由官方客户端
     * {@link TeeInstitutionKey#decryptExport} 统一使用——到期与接收者绑定都在 RSA 运算之前判定，
     * 数据密钥仅存内存并在用完后清零，信封本身不返回给调用方，也不进入浏览器。
     */
    public Download download(String ownerId, String actor, String exportId) {
        if (!center.configured()) {
            throw TeeException.of(TeeContract.Error.END_ROLE_DENIED,
                    "中心裁决实例不解密导出结果");
        }
        TeeExportService.RequestView view = detail(ownerId, exportId);
        if (!ownerId.equals(view.requesterOwnerId())) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                    "只有发起机构可以取回该结果");
        }
        if (!"APPROVED".equals(view.status())) {
            throw TeeException.of(TeeContract.Error.EXPORT_NOT_APPROVED, "导出工单尚未全票通过");
        }
        TeeExportService.ExportResult exported = export(ownerId, actor, view.resultId(),
                new TeeExportService.ExportRequest(TeeContract.VERSION,
                        "egress-" + UUID.randomUUID().toString().replace("-", ""), null));
        TeeCrypto.EncryptedObject object = center.get(
                "/objects/" + path(exported.objectId()), TeeCrypto.EncryptedObject.class);
        byte[] plaintext = institutionKey.decryptExport(exported, object, mapper);
        mvp.auditAs("TEE", "INFO", actor, "TEE_RESULT_DOWNLOAD", "TEE_EXPORT",
                view.exportId(), "stage=EGRESS resultId=" + view.resultId()
                        + " kind=" + view.kind() + " bytes=" + plaintext.length, true);
        mvp.dispatchWebhooks("tee.export.download", Map.of("exportId", view.exportId(),
                "resultId", view.resultId(), "status", view.status(), "stage", "EGRESS"));
        return new Download(fileName(view), contentType(view.kind()), plaintext);
    }

    /**
     * 委派成功后在本机构补记一条审计。
     *
     * <p>权威台账在中心端，客户端只做薄委派。但本机构的统一日志必须能看到本方操作员
     * 做过什么，否则申请与投票在数据方一侧完全无迹可查。事件名与中心端一致，
     * detail 中标注 delegated 以区分裁决记录与本方操作记录。
     */
    private void delegated(String actor, String action, TeeExportService.RequestView view,
                           String detail) {
        mvp.auditAs("TEE", "INFO", actor, action, "TEE_EXPORT", view.exportId(),
                "stage=EGRESS delegated=true " + detail, true);
    }

    /** 密文对象没有格式列，文件名按结果类型推定：DATA 为 CSV，MODEL 为 JSON。 */
    private static String fileName(TeeExportService.RequestView view) {
        String suffix = "MODEL".equals(view.kind()) ? ".json"
                : "DATA".equals(view.kind()) ? ".csv" : ".bin";
        return path(view.resultId()) + suffix;
    }

    private static String contentType(String kind) {
        return "MODEL".equals(kind) ? "application/json" : "text/csv";
    }

    private TeeExportService.ExportableResult exportableList(JsonNode data) {
        List<TeeExportService.ExportableView> items = new ArrayList<>();
        for (JsonNode item : data.path("items")) {
            try {
                items.add(mapper.treeToValue(item, TeeExportService.ExportableView.class));
            } catch (Exception failure) {
                throw TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, "中心端可导出结果结构不符");
            }
        }
        return new TeeExportService.ExportableResult(TeeContract.VERSION, items);
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
