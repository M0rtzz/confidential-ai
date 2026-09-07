package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** 在业务事务结束后记录授权裁决，拒绝记录不会随业务回滚丢失。 */
@Aspect
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TeePolicyAudit {
    private static final Logger log = LoggerFactory.getLogger(TeePolicyAudit.class);
    private final DataSandboxMvpService mvp;
    private final ObjectMapper mapper;
    private final TransactionTemplate transaction;
    private final ExecutorService writer = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "tee-policy-audit-writer");
        thread.setDaemon(true);
        return thread;
    });

    public TeePolicyAudit(DataSandboxMvpService mvp, ObjectMapper mapper, PlatformTransactionManager manager) {
        this.mvp = mvp;
        this.mapper = mapper;
        transaction = new TransactionTemplate(manager);
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Around("execution(* org.secretflow.secretpad.web.service.tee.TeeRuntimeService.release(..)) || "
            + "execution(* org.secretflow.secretpad.web.service.tee.TeePolicyService.register(..))")
    public Object audit(ProceedingJoinPoint invocation) throws Throwable {
        Object result = null;
        Throwable failure = null;
        try {
            result = invocation.proceed();
            return result;
        } catch (Throwable error) {
            failure = error;
            throw error;
        } finally {
            try {
                record(invocation.getArgs(), result, failure);
            } catch (Exception error) {
                log.warn("授权审计记录写入失败: {}", error.getMessage());
            }
        }
    }

    private void record(Object[] args, Object result, Throwable failure) throws Exception {
        String actor = String.valueOf(args[0]);
        Map<String, Object> detail = new LinkedHashMap<>();
        boolean success = failure == null;
        detail.put("outcome", success ? "通过" : "拒绝或失败");
        if (failure instanceof TeeException denied) {
            detail.put("errorCode", denied.error().name());
            detail.put("reason", denied.getMessage());
        } else if (failure != null) {
            detail.put("reason", "处理失败：" + failure.getClass().getSimpleName());
        }
        String action;
        String resource;
        if (args[1] instanceof TeeRuntimeService.ReleaseRequest request) {
            action = "任务授权校验与密钥放行";
            resource = request.requestId();
            detail.put("requestId", resource);
            // 仅提取关联字段；拒绝时这些字段只是请求声明，不代表通过签名或授权验证。
            try {
                JsonNode task = mapper.readTree(Base64.getUrlDecoder().decode(request.taskJws().split("\\.")[1]));
                for (String field : new String[]{"taskId", "sandboxId", "operatorId", "columns", "inputs"}) {
                    detail.put(field, task.path(field));
                }
            } catch (Exception invalid) {
                detail.put("requestMetadata", "任务载荷无法解析");
            }
            if (result instanceof TeeRuntimeService.ReleaseResult released) resource = released.taskId();
        } else if (args[1] instanceof TeePolicyService.RegisterRequest request) {
            action = "授权规则登记";
            resource = request.requestId();
            detail.put("requestId", resource);
            if (request.policy() != null) detail.put("policy", request.policy());
            if (result instanceof TeePolicyService.RegisterResult registered) {
                resource = registered.policyId();
                detail.put("policyId", registered.policyId());
                detail.put("policyVersion", registered.policyVersion());
            }
        } else return;
        String resourceId = resource;
        String json = mapper.writeValueAsString(detail);
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCompletion(int status) {
                    boolean committed = status == STATUS_COMMITTED;
                    // 此时原事务连接尚未归还，交给独立线程写入，避免单连接池内等待自身释放。
                    writer.execute(() -> persist(actor, action, resourceId,
                            committed ? json : json + "；业务事务已回滚", success && committed));
                }
            });
        } else persist(actor, action, resourceId, json, success);
    }

    private void persist(String actor, String action, String resource, String detail, boolean success) {
        try {
            transaction.executeWithoutResult(status -> mvp.auditAs("TEE_POLICY", success ? "INFO" : "WARN",
                    actor, action, "TEE_POLICY", resource, detail, success));
        } catch (Exception error) {
            log.warn("授权审计记录写入失败: {}", error.getMessage());
        }
    }

    @PreDestroy
    void close() {
        writer.shutdown();
        try {
            writer.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
