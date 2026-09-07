package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.ProjectAssetDO;
import org.secretflow.secretpad.persistence.repository.ProjectAssetRepository;
import org.secretflow.secretpad.web.service.MinioAssetStorage;
import org.secretflow.secretpad.web.service.storage.NodeDatasetStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** 项目挂载统一使用密文；本节点已物化的数据仍供本机构本地操作。 */
@Service
public class TeeProjectEncryption {
    private static final Logger log = LoggerFactory.getLogger(TeeProjectEncryption.class);
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final MinioAssetStorage storage;
    private final NodeDatasetStore datasets;
    private final TeeAssetEncryptor encryptor;
    private final TeeAssetService assets;
    private final TeeDataEvents events;
    private final ProjectAssetRepository projects;
    @Value("${secretpad.node-id:kuscia-system}") private String nodeId;

    public TeeProjectEncryption(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
            MinioAssetStorage storage, NodeDatasetStore datasets, TeeAssetEncryptor encryptor,
            TeeAssetService assets, TeeDataEvents events, ProjectAssetRepository projects) {
        this.jdbc = jdbc; this.mapper = mapper; this.storage = storage; this.datasets = datasets;
        this.encryptor = encryptor; this.assets = assets; this.events = events; this.projects = projects;
    }

    public synchronized Map<String, Object> ensure(String projectId, Map<String, Object> asset) {
        String assetId = Objects.toString(asset.get("id"), "");
        List<Map<String, Object>> current = jdbc.queryForList("select * from ds_data_asset where id=? and deleted=0", assetId);
        if (!current.isEmpty()) asset = current.get(0);
        String owner = events.institution(Objects.toString(asset.get("provider_node_id"), ""));
        Path temp = null;
        try {
            Map<String, Object> metadata = mapper.readValue(Objects.toString(asset.get("metadata_json"), "{}"), Map.class);
            boolean encrypted = Boolean.TRUE.equals(metadata.get("encrypted"));
            TeeCrypto.EncryptedObject object;
            if (encrypted) {
                try (InputStream in = storage.open(Objects.toString(asset.get("storage_uri"), ""))) {
                    object = mapper.readValue(in, TeeCrypto.EncryptedObject.class);
                }
                if (!assetId.equals(object.assetId())) throw new IllegalStateException("密文绑定的资产标识不一致");
            } else {
                if (!encryptor.available()) throw new IllegalStateException("项目挂载需要可用的密钥服务与本机构加密身份");
                datasets.ensureMaterialized(assetId);
                byte[] plaintext;
                try (InputStream in = storage.open(Objects.toString(asset.get("storage_uri"), ""))) {
                    plaintext = in.readAllBytes();
                }
                String version = Objects.toString(asset.get("version"), "1");
                TeeAssetEncryptor.Sealed sealed = encryptor.seal(owner, assetId, version, plaintext);
                object = sealed.object();
                temp = Files.createTempFile("project-asset-", ".enc");
                Files.write(temp, sealed.payload());
                String checksum = TeeCrypto.sha256Hex(sealed.payload());
                String uri = storage.put("encrypted/" + assetId + "/" + version + ".enc", temp.toFile(), "application/json", checksum);
                metadata.put("originalContentType", metadata.getOrDefault("contentType", "application/octet-stream"));
                metadata.put("contentType", "application/json");
                metadata.put("encrypted", true);
                metadata.put("algorithm", TeeContract.KEY_ALGORITHM);
                metadata.put("assetVersion", version);
                metadata.put("keyId", sealed.keyId());
                metadata.put("keyVersion", sealed.keyVersion());
                metadata.put("ciphertextSha256", sealed.ciphertextSha256());
                metadata.put("plaintextSha256", TeeCrypto.sha256Hex(plaintext));
                metadata.put("plaintextBytes", plaintext.length);
                metadata.put("sha256", checksum);
                metadata.put("sizeBytes", sealed.payload().length);
                String json = mapper.writeValueAsString(metadata);
                jdbc.update("update ds_data_asset set storage_uri=?,metadata_json=?,updated_at=? where id=? and deleted=0",
                        uri, json, LocalDateTime.now().toString(), assetId);
                asset = new LinkedHashMap<>(asset);
                asset.put("storage_uri", uri);
                asset.put("metadata_json", json);
            }
            String objectId = assets.ingestSynced(owner, object);
            events.record(encrypted ? "MOUNT_CIPHERTEXT" : "MOUNT_ENCRYPT", owner, projectId, objectId, object);
            return asset;
        } catch (Exception failure) {
            throw new IllegalStateException("项目数据加密或登记失败: " + assetId + "，" + failure.getMessage(), failure);
        } finally {
            if (temp != null) try { Files.deleteIfExists(temp); } catch (Exception ignored) { }
        }
    }

    /** 补齐此前已挂载但未加密或未登记的本方资产，每批最多处理二十条。 */
    @Scheduled(initialDelay = 15000, fixedDelay = 60000)
    public void reconcileMounted() {
        String owner;
        try { owner = events.institution(nodeId); } catch (Exception unavailable) { return; }
        List<Map<String, Object>> rows = jdbc.queryForList(
                "select pa.project_id,a.* from ds_project_asset pa join ds_data_asset a on a.id=pa.asset_id "
                        + "where pa.deleted=0 and coalesce(pa.is_deleted,0)=0 and a.deleted=0 "
                        + "and a.provider_node_id in (?,?) and not exists(select 1 from ds_unified_log l "
                        + "where l.log_type='TEE_DATA' and l.action in ('MOUNT_ENCRYPT','MOUNT_CIPHERTEXT') "
                        + "and l.resource_id=pa.project_id||'/'||a.id) limit 20", nodeId, owner);
        for (Map<String, Object> row : rows) {
            String project = Objects.toString(row.remove("project_id"));
            String id = Objects.toString(row.get("id"));
            try {
                Map<String, Object> asset = ensure(project, row);
                projects.findById(new ProjectAssetDO.UPK(project, id)).ifPresent(attachment -> {
                    try {
                        Map<String, Object> snapshot = mapper.readValue(attachment.getAssetJson(), Map.class);
                        snapshot.putAll(asset);
                        attachment.setAssetJson(mapper.writeValueAsString(snapshot));
                        projects.saveAndFlush(attachment);
                    } catch (Exception failure) { throw new IllegalStateException(failure); }
                });
            } catch (Exception failure) {
                log.warn("已挂载数据加密补录未完成 project={} asset={}: {}", project, id, failure.getMessage());
            }
        }
    }
}
