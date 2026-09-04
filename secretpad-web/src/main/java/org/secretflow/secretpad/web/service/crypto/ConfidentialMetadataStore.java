package org.secretflow.secretpad.web.service.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** JDBC metadata store. Every payload is ciphertext, a public key, a digest, or signed metadata. */
@Repository
public class ConfidentialMetadataStore {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public ConfidentialMetadataStore(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public void saveIdentity(String ownerId, String kid, String encryptionKey, String signingKey) {
        List<Map<String, Object>> existing = jdbc.queryForList(
                "select user_id,encryption_public_key,signing_public_key from ds_crypto_identity where kid=?", kid);
        if (!existing.isEmpty()) {
            Map<String, Object> row = existing.get(0);
            if (!ownerId.equals(row.get("user_id")) || !encryptionKey.equals(row.get("encryption_public_key"))
                    || !signingKey.equals(row.get("signing_public_key"))) {
                throw TeeException.of(TeeContract.Error.REQUEST_ID_CONFLICT, "kid 已绑定其他身份或公钥");
            }
            return;
        }
        jdbc.update("insert into ds_crypto_identity(kid,tenant_id,user_id,encryption_public_key,signing_public_key,algorithm,status,created_at) values(?,?,?,?,?,?,?,?)",
                kid, ownerId, ownerId, encryptionKey, signingKey, "X25519+Ed25519", "ACTIVE", Instant.now().toString());
    }

    public void requireSigningIdentity(String ownerId, String signingKey) {
        Integer count = jdbc.queryForObject(
                "select count(*) from ds_crypto_identity where user_id=? and signing_public_key=? and status='ACTIVE'",
                Integer.class, ownerId, signingKey);
        if (count == null || count != 1) {
            throw TeeException.of(TeeContract.Error.TASK_SIGNATURE_INVALID, "签名公钥未登记或已撤销");
        }
    }

    public void requireEncryptionIdentity(String ownerId, String kid) {
        Integer count = jdbc.queryForObject(
                "select count(*) from ds_crypto_identity where user_id=? and kid=? and status='ACTIVE'",
                Integer.class, ownerId, kid);
        if (count == null || count != 1) {
            throw TeeException.of(TeeContract.Error.KEY_REVOKED, "加密接收公钥未登记、已撤销或不属于当前用户");
        }
    }

    public void saveTask(String ownerId, String taskId, JsonNode spec, String digest,
                         String profile, String requirement, String expiresAt) {
        jdbc.update("insert into ds_crypto_task(task_id,owner_id,task_spec_json,task_spec_digest,security_profile,runtime_security_requirement,status,created_at,expires_at) values(?,?,?,?,?,?,?,?,?)",
                taskId, ownerId, json(spec), digest, profile, requirement, "CREATED", Instant.now().toString(), expiresAt);
    }

    public TaskRow task(String ownerId, String taskId) {
        List<TaskRow> rows = jdbc.query(
                "select task_spec_json,task_spec_digest,security_profile,runtime_security_requirement,expires_at from ds_crypto_task where task_id=? and owner_id=?",
                (result, index) -> new TaskRow(ConfidentialCanonical.parse(mapper, result.getString(1)),
                        result.getString(2), result.getString(3), result.getString(4), result.getString(5)),
                taskId, ownerId);
        if (rows.size() != 1) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务不存在或无权访问");
        }
        return rows.get(0);
    }

    public void saveSession(String taskId, JsonNode response, String clientNonce) {
        JsonNode evidence = response.path("evidence");
        jdbc.update("insert into ds_tee_attestation_session(session_id,task_id,task_spec_digest,client_nonce_hash,tee_pubkey_hash,evidence_hash,evidence_json,evidence_type,simulated,hardware_model,security_profile,verifier_id,policy_id,issued_at,expires_at,status) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                response.path("sessionId").asText(), taskId, evidence.path("taskSpecDigest").asText(),
                ConfidentialCanonical.sha256Bytes(clientNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                evidence.path("teeEphemeralPublicKeyHash").asText(), ConfidentialCanonical.sha256(evidence), json(evidence),
                response.path("evidenceType").asText(), 1, response.path("hardwareModel").asText(),
                response.path("securityProfile").asText(), "sim-attestation-verifier",
                ConfidentialContract.SIM_POLICY, evidence.path("issuedAt").asText(), response.path("expiresAt").asText(), "ISSUED");
    }

    public void saveGrant(String ownerId, String grantId, String taskId, String sessionId, String jti,
                          JsonNode claims, JsonNode payload, String profile, String expiresAt) {
        try {
            jdbc.update("insert into ds_crypto_grant(grant_id,task_id,session_id,jti,owner_id,claims_hash,payload_json,security_profile,expires_at,created_at) values(?,?,?,?,?,?,?,?,?,?)",
                    grantId, taskId, sessionId, jti, ownerId, ConfidentialCanonical.sha256(claims), json(payload),
                    profile, expiresAt, Instant.now().toString());
        } catch (org.springframework.dao.DataIntegrityViolationException duplicate) {
            throw TeeException.of(TeeContract.Error.TASK_REPLAYED, "grant id 或 jti 已使用");
        }
    }

    public GrantRow consumeGrant(String ownerId, String grantId) {
        List<GrantRow> rows = jdbc.query(
                "select task_id,session_id,payload_json,security_profile,expires_at,consumed_at from ds_crypto_grant where grant_id=? and owner_id=? and revoked_at is null",
                (result, index) -> new GrantRow(result.getString(1), result.getString(2),
                        ConfidentialCanonical.parse(mapper, result.getString(3)), result.getString(4),
                        result.getString(5), result.getString(6)), grantId, ownerId);
        if (rows.size() != 1 || rows.get(0).consumedAt() != null) {
            throw TeeException.of(TeeContract.Error.TASK_REPLAYED, "grant 不存在、已撤销或已消费");
        }
        int updated = jdbc.update("update ds_crypto_grant set consumed_at=? where grant_id=? and consumed_at is null",
                Instant.now().toString(), grantId);
        if (updated != 1) {
            throw TeeException.of(TeeContract.Error.TASK_REPLAYED, "grant 已被并发消费");
        }
        return rows.get(0);
    }

    public void saveExecution(String taskId, String grantId, String sessionId, JsonNode result) {
        JsonNode receipt = result.path("receipt");
        jdbc.update("insert into ds_confidential_execution(execution_id,task_id,grant_id,session_id,security_profile,image_digest,sbom_digest,status,receipt_json,output_manifest_hash,output_json,created_at,completed_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                result.path("executionId").asText(), taskId, grantId, sessionId,
                result.path("securityProfile").asText(ConfidentialContract.SIM_PROFILE),
                "sha256:builtin-digest-v1", "sha256:builtin-sbom-v1", result.path("status").asText(),
                json(receipt), result.path("encryptedOutput").path("ciphertextSha256").asText(), json(result),
                Instant.now().toString(), receipt.path("completedAt").asText(Instant.now().toString()));
        jdbc.update("update ds_crypto_task set status='SUCCEEDED' where task_id=?", taskId);
    }

    public JsonNode latestOutput(String ownerId, String taskId) {
        List<String> rows = jdbc.query(
                "select e.output_json from ds_confidential_execution e join ds_crypto_task t on e.task_id=t.task_id where e.task_id=? and t.owner_id=? order by e.created_at desc",
                (result, index) -> result.getString(1), taskId, ownerId);
        if (rows.isEmpty()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "任务尚无加密输出");
        }
        return ConfidentialCanonical.parse(mapper, rows.get(0));
    }

    public synchronized void audit(String ownerId, String type, String subjectId, JsonNode detail) {
        List<String> previousRows = jdbc.query("select event_hash from ds_crypto_audit_event order by created_at desc",
                (result, index) -> result.getString(1));
        String previous = previousRows.isEmpty() ? "0".repeat(64) : previousRows.get(0);
        String createdAt = Instant.now().toString();
        Map<String, Object> event = Map.of("eventType", type, "subjectId", subjectId,
                "securityProfile", ConfidentialContract.SIM_PROFILE, "simulated", true,
                "previousHash", previous, "createdAt", createdAt, "detail", detail);
        String hash = ConfidentialCanonical.sha256(event);
        jdbc.update("insert into ds_crypto_audit_event(event_id,tenant_id,user_id,event_type,subject_id,security_profile,simulated,event_json,previous_hash,event_hash,created_at) values(?,?,?,?,?,?,?,?,?,?,?)",
                "audit_" + UUID.randomUUID().toString().replace("-", ""), ownerId, ownerId, type, subjectId,
                ConfidentialContract.SIM_PROFILE, 1, json(event), previous, hash, createdAt);
    }

    public List<JsonNode> auditEvents(String ownerId) {
        return jdbc.query("select event_json from ds_crypto_audit_event where user_id=? order by created_at desc",
                (result, index) -> ConfidentialCanonical.parse(mapper, result.getString(1)), ownerId);
    }

    private String json(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "JSON 序列化失败");
        }
    }

    public record TaskRow(JsonNode spec, String digest, String securityProfile,
                          String runtimeSecurityRequirement, String expiresAt) {
    }

    public record GrantRow(String taskId, String sessionId, JsonNode payload,
                           String securityProfile, String expiresAt, String consumedAt) {
    }
}
