/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeAssetDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** 将已验签、已放行任务固化为最小权限的对象读取和结果写入授权。 */
@Service
public class TeeRuntimeGrantService {

    private static final long MAX_RUNTIME_SECONDS = 30 * 60;

    public record ResultBinding(String kind, String keyId, String keyVersion) {
    }

    private final TeeRuntimeTaskRepository tasks;
    private final TeeAssetRepository assets;
    private final ObjectMapper mapper;

    public TeeRuntimeGrantService(TeeRuntimeTaskRepository tasks, TeeAssetRepository assets,
                                  ObjectMapper mapper) {
        this.tasks = tasks;
        this.assets = assets;
        this.mapper = mapper;
    }

    @Transactional
    public List<String> accept(String callerId, TeeTaskSpec task, String taskJws,
                               String workloadCertSha256) {
        LinkedHashSet<String> objectIds = new LinkedHashSet<>();
        LinkedHashSet<String> contributors = new LinkedHashSet<>();
        for (TeeTaskSpec.Input input : task.inputs()) {
            TeeAssetDO asset = assets.findById(new TeeAssetDO.UPK(
                            input.assetId(), String.valueOf(input.assetVersion())))
                    .orElseThrow(() -> TeeException.of(TeeContract.Error.CONTRACT_INVALID,
                            "签名任务引用的资产不存在"));
            if (!asset.getObjectId().equals(input.objectId())) {
                throw TeeException.of(TeeContract.Error.DATA_INTEGRITY_FAILED,
                        "签名任务对象与资产登记不符");
            }
            objectIds.add(input.objectId());
            contributors.add(asset.getOwnerId());
        }
        TeeRuntimeTaskDO.UPK key = new TeeRuntimeTaskDO.UPK(task.taskId());
        TeeRuntimeTaskDO existing = tasks.findById(key).orElse(null);
        if (existing != null) {
            if (!existing.getRequestId().equals(task.requestId())
                    || !existing.getCallerId().equals(callerId)
                    || !existing.getWorkloadCertSha256().equals(workloadCertSha256)) {
                throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT,
                        "任务标识已绑定其他请求或运行时身份");
            }
            return readStrings(existing.getContributorsJson());
        }
        tasks.save(TeeRuntimeTaskDO.builder().upk(key).requestId(task.requestId())
                .callerId(callerId).workloadCertSha256(workloadCertSha256)
                .objectIdsJson(write(new ArrayList<>(objectIds)))
                .contributorsJson(write(new ArrayList<>(contributors)))
                .programObjectId(task.program().objectId()).resultBindingsJson("{}")
                // TaskSpec 的 expiresAt 约束“开始放行”的签名窗口；任务一旦被接受，
                // 结果写回与回执仍须覆盖契约规定的最长 30 分钟执行窗口。
                .taskJws(taskJws).expiresAt(Instant.parse(task.expiresAt())
                        .plusSeconds(MAX_RUNTIME_SECONDS).toString()).status("ACCEPTED")
                .receiptVerified(false).build());
        return new ArrayList<>(contributors);
    }

    public void requireObjectRead(String callerId, String taskId, String objectId) {
        TeeRuntimeTaskDO task = requireActive(callerId, taskId);
        if (!readStrings(task.getObjectIdsJson()).contains(objectId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                    "对象不在该运行时任务的签名输入范围内");
        }
    }

    public void requireProgramRead(String callerId, String taskId, String objectId) {
        TeeRuntimeTaskDO task = requireActive(callerId, taskId);
        if (task.getProgramObjectId() == null || !task.getProgramObjectId().equals(objectId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                    "程序不在该运行时任务的签名范围内");
        }
    }

    public List<String> contributors(String callerId, String taskId) {
        return readStrings(requireActive(callerId, taskId).getContributorsJson());
    }

    @Transactional
    public void bindResult(String callerId, String taskId, String resultId, String kind,
                           String keyId, String keyVersion) {
        TeeRuntimeTaskDO task = requireActive(callerId, taskId);
        Map<String, ResultBinding> bindings = readBindings(task.getResultBindingsJson());
        ResultBinding proposed = new ResultBinding(kind, keyId, keyVersion);
        ResultBinding existing = bindings.get(resultId);
        if (existing != null && !existing.equals(proposed)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                    "结果标识已绑定其他类型或密钥");
        }
        bindings.put(resultId, proposed);
        task.setResultBindingsJson(write(bindings));
        tasks.save(task);
    }

    public ResultBinding requireResult(String callerId, String taskId, String resultId,
                                       String kind, String keyId, String keyVersion) {
        ResultBinding binding = requireResult(callerId, taskId, resultId);
        ResultBinding expected = new ResultBinding(kind, keyId, keyVersion);
        if (!expected.equals(binding)) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                    "密文结果未由该任务申领并绑定");
        }
        return binding;
    }

    public ResultBinding requireResult(String callerId, String taskId, String resultId) {
        ResultBinding binding = readBindings(requireActive(callerId, taskId)
                .getResultBindingsJson()).get(resultId);
        if (binding == null) {
            throw TeeException.of(TeeContract.Error.POLICY_DENIED,
                    "结果标识尚未由该任务申领");
        }
        return binding;
    }

    public Map<String, ResultBinding> resultBindings(String callerId, String taskId) {
        return new LinkedHashMap<>(readBindings(requireTask(callerId, taskId)
                .getResultBindingsJson()));
    }

    public TeeRuntimeTaskDO requireTask(String callerId, String taskId) {
        TeeRuntimeTaskDO task = tasks.findById(new TeeRuntimeTaskDO.UPK(
                        TeeGuard.requireText(taskId, "taskId")))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                        "运行时任务不存在"));
        if (!task.getCallerId().equals(callerId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED,
                    "运行时任务不属于当前证书身份");
        }
        return task;
    }

    public TeeRuntimeTaskDO requireActiveTask(String callerId, String taskId) {
        return requireActive(callerId, taskId);
    }

    @Transactional
    public void saveReceipt(String callerId, String taskId, String receiptJws, String status) {
        TeeRuntimeTaskDO task = requireTask(callerId, taskId);
        if (Boolean.TRUE.equals(task.getReceiptVerified())) {
            if (!receiptJws.equals(task.getReceiptJws())) {
                throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT,
                        "任务已经绑定其他已核实回执");
            }
            return;
        }
        task.setReceiptJws(receiptJws);
        task.setReceiptVerified(true);
        task.setStatus(status);
        tasks.save(task);
    }

    private TeeRuntimeTaskDO requireActive(String callerId, String taskId) {
        TeeRuntimeTaskDO task = requireTask(callerId, taskId);
        if (Instant.now().isAfter(Instant.parse(task.getExpiresAt()).plusSeconds(
                TeeContract.CLOCK_SKEW_SECONDS))) {
            throw TeeException.of(TeeContract.Error.TASK_EXPIRED, "运行时任务授权已过期");
        }
        return task;
    }

    public TeeRuntimeTaskDO receipt(String callerId, String taskId) {
        TeeRuntimeTaskDO task = requireTask(callerId, taskId);
        if (!Boolean.TRUE.equals(task.getReceiptVerified()) || task.getReceiptJws() == null) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "任务尚无已核实回执");
        }
        return task;
    }

    private String write(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "运行时授权无法序列化");
        }
    }

    private List<String> readStrings(String json) {
        try {
            return mapper.readValue(json, new TypeReference<>() { });
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "运行时授权记录损坏");
        }
    }

    private Map<String, ResultBinding> readBindings(String json) {
        try {
            return mapper.readValue(json, new TypeReference<LinkedHashMap<String, ResultBinding>>() { });
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "结果绑定记录损坏");
        }
    }
}
