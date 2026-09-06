package org.secretflow.secretpad.web.service.canvas;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.web.service.dev.DataDevService;
import org.secretflow.secretpad.web.service.dev.DevJobExecutor;
import org.secretflow.secretpad.web.service.tee.TeeCrypto;
import org.secretflow.secretpad.web.service.tee.TeeModelReportAccess;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;

/** 报告独立异步生成；缓存每次读取仍复核来源和当前权限。 */
@Service
public class TeeTreeReportService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final TeeModelReportAccess access;
    private final DataDevService tasks;
    private final DevJobExecutor executor;
    private final ExecutorService workers = Executors.newFixedThreadPool(2);
    private final java.util.Set<String> active = ConcurrentHashMap.newKeySet();

    public TeeTreeReportService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
                               TeeModelReportAccess access, DataDevService tasks, DevJobExecutor executor) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.access = access;
        this.tasks = tasks;
        this.executor = executor;
    }

    @PreDestroy
    public void close() { workers.shutdownNow(); }

    public Map<String, Object> cached(String objectId, String sandboxId, List<String> features, int treeIndex) {
        try {
            var authorized = access.authorize(objectId, sandboxId, features);
            String id = identity(objectId, treeIndex, authorized.policyFingerprint());
            List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_model_tree_report where id=?", id);
            if (rows.isEmpty()) return state("NOT_COMPUTED", "树结构尚未生成");
            return render(rows.get(0));
        } catch (Exception error) {
            return state("BLOCKED", error.getMessage());
        }
    }

    /** 同一模型、树索引、策略版本只创建一个有效任务，重试使用新任务和 nonce。 */
    public synchronized Map<String, Object> request(String objectId, String sandboxId, String canvasId,
                                                   String nodeId, String modelKind, List<String> features,
                                                   int treeIndex, boolean retry) {
        if (treeIndex < 0 || treeIndex > 100000) throw new IllegalArgumentException("树索引必须是范围内非负整数");
        var authorized = access.authorize(objectId, sandboxId, features);
        String id = identity(objectId, treeIndex, authorized.policyFingerprint());
        List<Map<String, Object>> rows = jdbc.queryForList("select * from ds_model_tree_report where id=?", id);
        if (!rows.isEmpty()) {
            Map<String, Object> row = rows.get(0);
            if ("AVAILABLE".equals(row.get("status")) || "FAILED".equals(row.get("status")) && !retry) {
                return render(row);
            }
            if ("RUNNING".equals(row.get("status"))) {
                resume(id, row.get("task_id").toString(), objectId, sandboxId, features);
                return render(row);
            }
        }
        Integer pending = jdbc.queryForObject("select count(*) from ds_model_tree_report where status='RUNNING'", Integer.class);
        if (pending != null && pending >= 20) return state("FAILED", "报告生成任务较多，请稍后重试");
        String taskId = tasks.createCanvasTask(sandboxId, canvasId, nodeId,
                access.operator(authorized), "", Map.of("op", access.operator(authorized)),
                List.of(), "", "");
        tasks.claimCanvasTask(taskId);
        String now = Instant.now().toString();
        jdbc.update("insert into ds_model_tree_report(id,model_object_id,tree_index,policy_fingerprint,task_id,status,created_at,updated_at) "
                        + "values(?,?,?,?,?,'RUNNING',?,?) on conflict(id) do update set task_id=excluded.task_id,"
                        + "status='RUNNING',content_json=null,error_message=null,updated_at=excluded.updated_at",
                id, objectId, treeIndex, authorized.policyFingerprint(), taskId, now, now);
        try {
            executor.submitTeeModelReport(taskId, sandboxId, objectId, features, modelKind, treeIndex);
            resume(id, taskId, objectId, sandboxId, features);
        } catch (Exception error) {
            fail(id, taskId, error.getMessage());
        }
        return render(jdbc.queryForMap("select * from ds_model_tree_report where id=?", id));
    }

    private void resume(String id, String taskId, String objectId, String sandboxId, List<String> features) {
        if (!active.add(id)) return;
        UserContextDTO user = UserContext.getUserOrNotExist();
        workers.execute(() -> {
            try {
                UserContext.setBaseUser(user);
                Map<String, Object> result = executor.runAndAwait(taskId);
                if (!"SUCCEEDED".equals(result.get("status"))) {
                    throw new IllegalStateException(String.valueOf(result.getOrDefault("errorMessage", "可信树报告生成失败")));
                }
                var authorized = access.authorize(objectId, sandboxId, features);
                Object reports = result.get("reports");
                Map<String, Object> content = null;
                if (reports instanceof List<?> list) {
                    for (Object item : list) {
                        if (item instanceof Map<?, ?> report && access.reportKind(authorized).equals(report.get("reportKind"))) {
                            content = mapper.convertValue(report.get("content"), Map.class);
                        }
                    }
                }
                if (content == null) throw new IllegalStateException("可信回执没有树结构报告");
                content.put("computedAt", Instant.now().toString());
                content.put("modelObjectId", objectId);
                content.put("reportTaskId", taskId);
                String json = mapper.writeValueAsString(content);
                jdbc.update("update ds_model_tree_report set status='AVAILABLE',content_json=?,updated_at=? "
                                + "where id=? and task_id=? and status='RUNNING'", json, Instant.now().toString(), id, taskId);
            } catch (Exception error) {
                fail(id, taskId, error.getMessage());
            } finally {
                UserContext.remove();
                active.remove(id);
            }
        });
    }

    private void fail(String id, String taskId, String message) {
        String safe = message == null ? "可信树报告生成失败" : message.substring(0, Math.min(message.length(), 400));
        jdbc.update("update ds_model_tree_report set status='FAILED',error_message=?,updated_at=? where id=? and task_id=?",
                safe, Instant.now().toString(), id, taskId);
    }

    private Map<String, Object> render(Map<String, Object> row) {
        if ("AVAILABLE".equals(row.get("status"))) {
            try {
                Map<String, Object> content = mapper.readValue(row.get("content_json").toString(), Map.class);
                content.put("status", "AVAILABLE");
                content.put("supported", true);
                return content;
            } catch (Exception error) { return state("FAILED", "报告缓存无法解析，请重试"); }
        }
        Map<String, Object> response = state(row.get("status").toString(),
                "RUNNING".equals(row.get("status")) ? "正在可信执行侧生成树结构" : String.valueOf(row.get("error_message")));
        response.put("taskId", row.get("task_id"));
        return response;
    }

    private String identity(String objectId, int treeIndex, String fingerprint) {
        return TeeCrypto.sha256Hex((objectId + ":" + treeIndex + ":" + fingerprint + ":"
                + TeeModelReportAccess.PARSER_VERSION).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private Map<String, Object> state(String status, String message) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("status", status); value.put("supported", true);
        value.put("message", message == null ? "树结构报告暂不可用" : message);
        value.put("nodes", List.of());
        return value;
    }
}
