package org.secretflow.secretpad.web.service.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.web.service.crypto.ConfidentialMetadataStore;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Institution-scoped, versioned AI configuration. API keys never leave this service in clear text. */
@Service
public class AiConfigService {
    public record SaveRequest(String baseUrl, String modelId, String apiKey,
            boolean clearApiKey, boolean enabled) {}
    public record ResolvedConfig(String configId, int version, String baseUrl,
            String modelId, String apiKey) {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ConfidentialMetadataStore audit;
    private final OpenAiCompatibleClient client;
    private final Path masterKeyFile;
    private final Set<String> allowedPrivateHosts;

    public AiConfigService(@Qualifier("jdbcTemplate") JdbcTemplate jdbc, ObjectMapper mapper,
            ConfidentialMetadataStore audit, OpenAiCompatibleClient client,
            @Value("${DATA_SANDBOX_AI_CONFIG_MASTER_KEY_FILE:/app/ai-config/master.key}") String masterKeyFile,
            @Value("${DATA_SANDBOX_AI_ALLOWED_HOSTS:host.docker.internal}") String allowedHosts) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.audit = audit;
        this.client = client;
        this.masterKeyFile = Path.of(masterKeyFile);
        this.allowedPrivateHosts = java.util.Arrays.stream(allowedHosts.split(","))
                .map(String::trim).filter(value -> !value.isEmpty())
                .map(String::toLowerCase).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public Map<String, Object> current(String ownerId) {
        List<Map<String, Object>> rows = activeRows(ownerId);
        if (rows.isEmpty()) return Map.of("configured", false, "enabled", false,
                "format", "OPENAI_COMPATIBLE");
        return view(rows.get(0));
    }

    public ResolvedConfig requireActive(String ownerId) {
        List<Map<String, Object>> rows = activeRows(ownerId);
        if (rows.isEmpty() || !"ACTIVE".equals(text(rows.get(0).get("status")))) {
            throw invalid("当前机构尚未配置并启用 AI 服务");
        }
        Map<String, Object> row = rows.get(0);
        return new ResolvedConfig(text(row.get("config_id")), number(row.get("config_version")),
                text(row.get("base_url")), text(row.get("model_id")), decryptKey(row));
    }

    @Transactional
    public Map<String, Object> save(String ownerId, String actor, SaveRequest request) {
        String baseUrl = OpenAiCompatibleClient.normalizeBaseUrl(request.baseUrl(), allowedPrivateHosts);
        String modelId = required(request.modelId(), "modelId");
        List<Map<String, Object>> previousRows = activeRows(ownerId);
        Map<String, Object> previous = previousRows.isEmpty() ? null : previousRows.get(0);
        String apiKey = request.apiKey() == null ? "" : request.apiKey().trim();
        if (apiKey.isBlank() && !request.clearApiKey() && previous != null) apiKey = decryptKey(previous);

        int version = jdbc.queryForObject(
                "select coalesce(max(config_version),0)+1 from ds_ai_config where owner_id=?",
                Integer.class, ownerId);
        String configId = "aicfg_" + UUID.randomUUID().toString().replace("-", "");
        String now = Instant.now().toString();
        EncryptedValue encrypted = apiKey.isBlank() ? null : encryptKey(apiKey);
        jdbc.update("update ds_ai_config set is_current=0 where owner_id=? and is_current=1", ownerId);
        jdbc.update("insert into ds_ai_config(config_id,owner_id,config_version,format,base_url,model_id,"
                        + "api_key_ciphertext,api_key_nonce,status,is_current,created_by,created_at,updated_at) "
                        + "values(?,?,?,'OPENAI_COMPATIBLE',?,?,?,?,?,1,?,?,?)",
                configId, ownerId, version, baseUrl, modelId,
                encrypted == null ? null : encrypted.ciphertext(),
                encrypted == null ? null : encrypted.nonce(),
                request.enabled() ? "ACTIVE" : "DISABLED", actor, now, now);
        audit.audit(ownerId, "AI_CONFIG_UPDATED", configId,
                mapper.valueToTree(Map.of("version", version, "enabled", request.enabled(),
                        "modelId", modelId, "apiKeyConfigured", encrypted != null)));
        return current(ownerId);
    }

    public Map<String, Object> test(String ownerId) {
        ResolvedConfig config = requireActive(ownerId);
        String reply = client.complete(new OpenAiCompatibleClient.Settings(config.baseUrl(), config.modelId(),
                config.apiKey(), config.version()), "You are a connectivity check.", "Reply with OK.");
        return Map.of("connected", true, "configVersion", config.version(),
                "modelId", config.modelId(), "responseReceived", !reply.isBlank());
    }

    private List<Map<String, Object>> activeRows(String ownerId) {
        return jdbc.queryForList("select * from ds_ai_config where owner_id=? and is_current=1 "
                + "order by config_version desc", ownerId);
    }

    private Map<String, Object> view(Map<String, Object> row) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("configured", true);
        value.put("configId", row.get("config_id"));
        value.put("version", number(row.get("config_version")));
        value.put("format", row.get("format"));
        value.put("baseUrl", row.get("base_url"));
        value.put("modelId", row.get("model_id"));
        value.put("enabled", "ACTIVE".equals(text(row.get("status"))));
        value.put("apiKeyConfigured", row.get("api_key_ciphertext") != null);
        value.put("apiKeyMasked", row.get("api_key_ciphertext") == null ? "未配置" : "••••••••");
        value.put("updatedAt", row.get("updated_at"));
        return value;
    }

    private EncryptedValue encryptKey(String apiKey) {
        try {
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, masterKey(), new GCMParameterSpec(128, nonce));
            byte[] encrypted = cipher.doFinal(apiKey.getBytes(StandardCharsets.UTF_8));
            return new EncryptedValue(Base64.getEncoder().encodeToString(encrypted),
                    Base64.getEncoder().encodeToString(nonce));
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw unavailable("AI 配置密钥加密失败");
        }
    }

    private String decryptKey(Map<String, Object> row) {
        if (row.get("api_key_ciphertext") == null) return "";
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, masterKey(), new GCMParameterSpec(128,
                    Base64.getDecoder().decode(text(row.get("api_key_nonce")))));
            return new String(cipher.doFinal(Base64.getDecoder().decode(
                    text(row.get("api_key_ciphertext")))), StandardCharsets.UTF_8);
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw unavailable("AI 配置密钥解密失败");
        }
    }

    private SecretKeySpec masterKey() {
        try {
            byte[] key = Base64.getDecoder().decode(Files.readString(masterKeyFile).trim());
            if (key.length != 32) throw unavailable("AI 配置主密钥必须是 32 字节 Base64 数据");
            return new SecretKeySpec(key, "AES");
        } catch (TeeException failure) {
            throw failure;
        } catch (Exception failure) {
            throw unavailable("AI 配置主密钥文件不可用");
        }
    }

    private static int number(Object value) {
        return value instanceof Number number ? number.intValue() : Integer.parseInt(text(value));
    }

    private static String text(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) throw invalid(field + " 不能为空");
        return value.trim();
    }

    private static TeeException invalid(String message) {
        return TeeException.of(TeeContract.Error.CONTRACT_INVALID, message);
    }

    private static TeeException unavailable(String message) {
        return TeeException.of(TeeContract.Error.KEY_SERVICE_UNAVAILABLE, message);
    }

    private record EncryptedValue(String ciphertext, String nonce) {}
}
