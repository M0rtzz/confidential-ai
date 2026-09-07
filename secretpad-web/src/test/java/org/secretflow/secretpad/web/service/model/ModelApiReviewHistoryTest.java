/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.secretflow.secretpad.web.service.sandbox.SandboxApprovalGate;
import org.secretflow.secretpad.web.service.sandbox.SandboxApprovalService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 已审核记录可回查，且单条投票不会隐藏其他待审申请。 */
class ModelApiReviewHistoryTest {
    private SingleConnectionDataSource database;
    private JdbcTemplate jdbc;
    private ModelApiApprovalService service;

    @BeforeEach
    void setUp() {
        database = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        jdbc = new JdbcTemplate(database);
        jdbc.execute("create table ds_sandbox_approval(id text,approval_type text,status text,payload_json text,created_at text,deleted integer default 0)");
        jdbc.execute("create table ds_sandbox_approval_vote(approval_id text,voter_node_id text,status text,voted_at text)");
        SandboxApprovalGate gate = mock(SandboxApprovalGate.class);
        when(gate.effectiveOwner()).thenReturn("node-b");
        service = new ModelApiApprovalService(jdbc, new ObjectMapper(), null, gate,
                mock(SandboxApprovalService.class), null);
    }

    @AfterEach
    void tearDown() { database.destroy(); }

    @Test
    void reviewingOneKeepsOtherPendingAndRetainsHistory() {
        insert("first", "node-b", "PENDING", "DATA_PROVIDER_REVIEW");
        insert("second", "node-b", "PENDING", "DATA_PROVIDER_REVIEW");
        assertEquals(2, service.listPending("").size());
        jdbc.update("update ds_sandbox_approval_vote set status='APPROVED',voted_at='2026-09-08T01:32:00' where approval_id='first' and voter_node_id='node-b'");
        jdbc.update("update ds_sandbox_approval set status='APPROVED' where id='first'");
        assertEquals(List.of("second"), ids(service.listPending("")));
        assertEquals(List.of("first"), ids(service.listReviewed("")));
    }

    @Test
    void historyIncludesMyVoteWhileAnotherProviderIsPendingAndExcludesOtherNodes() {
        insert("mine", "node-b", "APPROVED", "DATA_PROVIDER_REVIEW");
        jdbc.update("insert into ds_sandbox_approval_vote values('mine','node-a','PENDING','')");
        insert("other", "node-a", "APPROVED", "APPROVED");
        insert("rejected", "node-b", "REJECTED", "REJECTED");
        assertEquals(2, service.listReviewed("").size());
        assertTrue(ids(service.listReviewed("")).containsAll(List.of("mine", "rejected")));
        assertTrue(service.listPending("").isEmpty());
    }

    @Test
    void historySupportsSearchAndDoesNotExposeApiSecret() {
        insert("reviewed", "node-b", "APPROVED", "APPROVED");
        List<Map<String, Object>> rows = service.listReviewed("DNN");
        assertEquals(1, rows.size());
        assertFalse(rows.get(0).containsKey("payload_json"));
        assertEquals("", ((Map<?, ?>) rows.get(0).get("payload")).get("secret"));
        assertTrue(service.listReviewed("unrelated").isEmpty());
    }

    private void insert(String id, String voter, String vote, String status) {
        jdbc.update("insert into ds_sandbox_approval values(?,'MODEL_API',?,?,?,0)", id, status,
                "{\"modelName\":\"DNN\",\"secret\":\"test-secret\"}", "2026-09-08T01:31:00");
        jdbc.update("insert into ds_sandbox_approval_vote values(?,?,?,?)", id, voter, vote, "2026-09-08T01:32:00");
    }

    private List<Object> ids(List<Map<String, Object>> rows) {
        return rows.stream().map(row -> row.get("id")).toList();
    }
}
