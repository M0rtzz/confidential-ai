package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import java.util.Base64;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TeePolicyAuditTest {
    @Test
    void successfulReleaseRecordsTaskWithoutTokenOrCertificate() throws Throwable {
        DataSandboxMvpService logs = mock(DataSandboxMvpService.class);
        ProceedingJoinPoint call = mock(ProceedingJoinPoint.class);
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"taskId\":\"task-1\",\"operatorId\":\"ml.cnn\",\"inputs\":[]}".getBytes());
        String token = "header." + payload + ".sensitive-signature";
        when(call.getArgs()).thenReturn(new Object[]{"owner-1",
                new TeeRuntimeService.ReleaseRequest("1", "req-1", token, "evidence", "private-certificate")});
        when(call.proceed()).thenReturn(new TeeRuntimeService.ReleaseResult("1", "task-1", "SIMULATION", false, List.of(), List.of()));
        audit(logs).audit(call);
        verify(logs).auditAs(eq("TEE_POLICY"), eq("INFO"), eq("owner-1"), anyString(), eq("TEE_POLICY"), eq("task-1"),
                argThat(detail -> detail.contains("ml.cnn") && !detail.contains(token) && !detail.contains("private-certificate")), eq(true));
    }

    @Test
    void deniedReleaseIsRecordedAfterRollbackAndPreservesException() throws Throwable {
        DataSandboxMvpService logs = mock(DataSandboxMvpService.class);
        ProceedingJoinPoint call = mock(ProceedingJoinPoint.class);
        when(call.getArgs()).thenReturn(new Object[]{"owner-1", new TeeRuntimeService.ReleaseRequest("1", "req-2", "invalid", "", "")});
        TeeException denied = TeeException.of(TeeContract.Error.POLICY_DENIED, "算子未在授权范围内");
        when(call.proceed()).thenThrow(denied);
        TransactionSynchronizationManager.initSynchronization();
        try {
            assertSame(denied, assertThrows(TeeException.class, () -> audit(logs).audit(call)));
            verifyNoInteractions(logs);
            for (TransactionSynchronization sync : TransactionSynchronizationManager.getSynchronizations()) {
                sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK);
            }
            verify(logs).auditAs(eq("TEE_POLICY"), eq("WARN"), eq("owner-1"), anyString(), eq("TEE_POLICY"), eq("req-2"),
                    argThat(detail -> detail.contains("POLICY_DENIED") && detail.contains("算子未在授权范围内")), eq(false));
        } finally {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private TeePolicyAudit audit(DataSandboxMvpService logs) {
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        return new TeePolicyAudit(logs, new ObjectMapper(), manager);
    }
}
