/* Copyright 2026 Ant Group Co., Ltd. Licensed under the Apache License, Version 2.0. */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.secretflow.secretpad.persistence.repository.TeeAssetRepository;
import org.secretflow.secretpad.web.service.AssetUsageDeadline;
import org.secretflow.secretpad.web.service.DataAssetService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;

/** 使用期限变更最终同步到挂载副本与自动计算策略；任务执行前另有即时复核。 */
@Slf4j
@Component
public class TeeDeadlineSynchronizer {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final DataAssetService dataAssets;
    private final TeeAssetRepository assets;
    private final TeePolicyService policies;

    public TeeDeadlineSynchronizer(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                                    DataAssetService dataAssets, TeeAssetRepository assets,
                                    TeePolicyService policies) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.dataAssets = dataAssets;
        this.assets = assets;
        this.policies = policies;
    }

    @Scheduled(fixedDelayString = "${secretpad.tee.deadline-sync.interval-ms:30000}", initialDelay = 30000)
    public void synchronize() {
        dataAssets.reconcileUsageSnapshots();
        for (Map<String, Object> mount : jdbc.queryForList(
                "select m.id,m.asset_id,m.expires_at,s.project_id from ds_sandbox_dataset_mount m "
                        + "join ds_sandbox s on s.id=m.sandbox_id and s.deleted=0 "
                        + "where m.deleted=0 and m.status='READY'")) {
            try {
                AssetUsageDeadline.Deadline deadline = AssetUsageDeadline.resolve(jdbc, mapper,
                        text(mount.get("project_id")), text(mount.get("asset_id")));
                if (deadline.found() && !deadline.value().equals(text(mount.get("expires_at")))) {
                    jdbc.update("update ds_sandbox_dataset_mount set expires_at=?,updated_at=? "
                                    + "where id=? and deleted=0 and status='READY' and coalesce(expires_at,'')=?",
                            deadline.value(), java.time.LocalDateTime.now().toString(), mount.get("id"),
                            text(mount.get("expires_at")));
                }
            } catch (RuntimeException invalid) {
                log.debug("挂载 {} 的期限等待有效快照: {}", mount.get("id"), invalid.getMessage());
            }
        }
        // 客户端没有权威 tee_asset 台账，因此只在实际持有台账的中心端更新策略。
        for (var asset : assets.findAll()) {
            try {
                var policy = policies.require(asset.getPolicyId(), asset.getPolicyVersion());
                if (TeePolicyService.followsDataDeadline(policy)) {
                    policies.refreshForAsset(asset, policy.getSandboxId());
                }
            } catch (RuntimeException unavailable) {
                // 解除挂载、停用或吊销时不恢复权限；执行入口会按当前状态拒绝。
                log.debug("资产 {} 的计算期限未更新: {}", asset.getUpk(), unavailable.getMessage());
            }
        }
    }

    private static String text(Object value) {
        return Objects.toString(value, "");
    }
}
