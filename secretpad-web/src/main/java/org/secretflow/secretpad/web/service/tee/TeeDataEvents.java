package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** 记录真实的加密、挂载及密文接收事件；日志仅包含标识和摘要。 */
@Service
public class TeeDataEvents {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public TeeDataEvents(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public String institution(String nodeOrOwner) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select distinct inst_id from node where (node_id=? or inst_id=?) and is_deleted=0", nodeOrOwner, nodeOrOwner);
        String owner = rows.size() == 1 ? Objects.toString(rows.get(0).get("inst_id"), "") : "";
        if (owner.isBlank()) throw new IllegalStateException("数据节点缺少唯一机构映射: " + nodeOrOwner);
        return owner;
    }

    public synchronized void record(String action, String owner, String projectId, String objectId,
                                    TeeCrypto.EncryptedObject object) {
        String resource = projectId + "/" + object.assetId();
        Long existing = jdbc.queryForObject("select count(*) from ds_unified_log where log_type='TEE_DATA' "
                + "and action=? and actor=? and resource_id=?", Long.class, action, owner, resource);
        if (existing != null && existing > 0) return;
        try {
            String detail = mapper.writeValueAsString(Map.of("projectId", projectId, "assetId", object.assetId(),
                    "assetVersion", object.assetVersion(), "objectId", objectId, "keyId", object.keyId(),
                    "keyVersion", object.keyVersion(), "ciphertextSha256", object.ciphertextSha256()));
            jdbc.update("insert into ds_unified_log(log_type,level,actor,action,resource_type,resource_id,detail,ip_address,trace_id,success,created_at) "
                            + "values('TEE_DATA','INFO',?,?,'PROJECT_ASSET',?,?,'','',1,?)",
                    owner, action, resource, detail, LocalDateTime.now().toString());
        } catch (Exception failure) {
            throw new IllegalStateException("数据加密链路记录失败", failure);
        }
    }
}
