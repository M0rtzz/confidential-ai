package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** 密文模型报告的来源校验。模型仍是 MODEL 对象，不重登记为表格资产。 */
@Service
public class TeeModelReportAccess {
    public static final String VERSION = "tee-contract/2.0";
    public static final String OPERATOR = "report.tree_structure";
    public static final String EVALUATION_OPERATOR = "report.model_evaluation";
    public static final String EVALUATION_KIND = "EVALUATION_METRICS";
    public static final String REPORT_KIND = "TREE_STRUCTURE";
    public static final String PARSER_VERSION = "tree-report/1";

    public record Authorized(TeeObjectDO object, TeeTaskSpec source, List<String> contributors,
                             String policyFingerprint) { }

    private final TeeObjectRepository objects;
    private final TeeRuntimeTaskRepository tasks;
    private final TeePolicyService policies;
    private final TeeKeyService keys;
    private final ObjectMapper mapper;
    private final JdbcTemplate jdbc;

    public TeeModelReportAccess(TeeObjectRepository objects, TeeRuntimeTaskRepository tasks,
                               TeePolicyService policies, TeeKeyService keys, ObjectMapper mapper,
                               @Qualifier("jdbcTemplate") JdbcTemplate jdbc) {
        this.objects = objects;
        this.tasks = tasks;
        this.policies = policies;
        this.keys = keys;
        this.mapper = mapper;
        this.jdbc = jdbc;
    }

    public static boolean isModelReport(TeeTaskSpec task) {
        return VERSION.equals(task.contractVersion())
                && List.of(OPERATOR, EVALUATION_OPERATOR).contains(task.operatorId());
    }

    /** 仅信任已核实训练回执中登记的模型，历史模型无需先补 ds_model_tee_binding。 */
    public Authorized authorize(String objectId, String sandboxId, List<String> features) {
        TeeObjectDO object = objects.findById(new TeeObjectDO.UPK(objectId))
                .orElseThrow(() -> denied("历史模型密文对象不存在，请核对训练产物"));
        if (!List.of("MODEL", "DATA").contains(object.getKind()) || object.getTaskId() == null) {
            throw denied("报告输入必须是已登记的训练 MODEL 结果");
        }
        TeeRuntimeTaskDO training = tasks.findById(new TeeRuntimeTaskDO.UPK(object.getTaskId()))
                .orElseThrow(() -> denied("模型缺少原训练可信任务记录"));
        if (!Boolean.TRUE.equals(training.getReceiptVerified()) || !"SUCCEEDED".equals(training.getStatus())) {
            throw denied("模型原训练回执未核实或训练未成功");
        }
        TeeTaskSpec source = readTask(training.getTaskJws());
        if (!sandboxId.equals(source.sandboxId()) || source.inputs() == null || source.inputs().isEmpty()) {
            throw denied("模型来源未绑定当前沙箱");
        }
        boolean evaluation = "DATA".equals(object.getKind());
        if (evaluation && !List.of("ml.xgboost", "ml.lightgbm", "ml.decision_tree", "ml.logistic_regression",
                "ml.linear_regression", "ml.knn", "ml.dnn", "ml.cnn", "ml.rnn", "ml.lstm").contains(source.operatorId())) {
            throw denied("评估报告只接受已核实的模型训练预测结果");
        }
        boolean found = false;
        for (JsonNode output : payload(training.getReceiptJws()).path("outputs")) {
            if (objectId.equals(output.path("objectId").asText()) && object.getKind().equals(output.path("kind").asText())
                    && !"PREPROCESSOR".equals(output.path("artifactType").asText())
                    && object.getCiphertextSha256().equals(output.path("ciphertextSha256").asText())
                    && object.getKeyId().equals(output.path("keyId").asText())
                    && object.getKeyVersion().equals(output.path("keyVersion").asText())) {
                found = true;
            }
        }
        if (!found) throw denied("密文模型与已核实的训练回执不一致");
        TeeGuard.requireSubset(features, source.columns(), "模型特征");
        var modelKey = keys.require(object.getKeyId(), object.getKeyVersion());
        keys.requireActive(modelKey);
        if (!object.getResultId().equals(modelKey.getAssetId()) || !"1".equals(modelKey.getAssetVersion())) {
            throw denied("模型结果密钥绑定不一致");
        }
        LinkedHashSet<String> contributors = new LinkedHashSet<>();
        List<Object> fingerprint = new ArrayList<>();
        for (TeeTaskSpec.Input input : source.inputs()) {
            TeePolicyDO policy = policies.resultSourcePolicy(input.policyId(), String.valueOf(input.policyVersion()));
            if (!input.assetId().equals(policy.getAssetId())
                    || !String.valueOf(input.assetVersion()).equals(policy.getAssetVersion())
                    || !sandboxId.equals(policy.getSandboxId())) {
                throw denied("原训练输入策略绑定不一致");
            }
            // 原训练授权必须仍有效，新增报告授权不覆盖原策略撤销和源密钥吊销。
            policies.requireAllows(policy, source.columns(), source.operatorId());
            keys.requireActive(keys.require(input.keyId(), String.valueOf(input.keyVersion())));
            boolean direct = evaluation ? policies.reportKinds(policy).contains(EVALUATION_KIND)
                    : policies.reportKinds(policy).contains(REPORT_KIND)
                    && stringList(policy.getOperatorsJson()).contains(OPERATOR);
            // 标准报告规则只适用于启用后开始的新树模型训练，不追溯扩张历史授权。
            List<String> cutoffs = jdbc.query("select value from ds_model_report_setting where id='standard_reports_since'",
                    (rs, index) -> rs.getString(1));
            boolean standard = !cutoffs.isEmpty() && Instant.parse(source.issuedAt()).isAfter(Instant.parse(cutoffs.get(0)))
                    && List.of("ml.decision_tree", "ml.xgboost", "ml.lightgbm").contains(source.operatorId());
            direct = direct || (!evaluation && standard);
            if (evaluation && !direct) throw denied("原训练来源未授权评估报告");
            String grantId = "original-policy";
            if (!direct) {
                List<Map<String, Object>> grants = jdbc.queryForList(
                        "select id,expires_at from ds_model_report_grant where model_object_id=? "
                                + "and source_policy_id=? and source_policy_version=? and owner_id=? "
                                + "and status='ACTIVE' order by created_at desc",
                        objectId, input.policyId(), String.valueOf(input.policyVersion()), policy.getOwnerId());
                Map<String, Object> grant = grants.stream().filter(g -> Instant.parse(g.get("expires_at").toString())
                        .isAfter(Instant.now())).findFirst().orElseThrow(() -> denied(
                                "历史模型来源尚未授权树结构报告，请供数机构补充 TREE_STRUCTURE 授权"));
                grantId = grant.get("id").toString();
            }
            contributors.add(policy.getOwnerId());
            fingerprint.add(List.of(input, policy.getUpk(), policy.getExpiresAt(), policy.getState(),
                    policy.getOperatorsJson(), policy.getReportKindsJson(), grantId));
        }
        // 模型的贡献方集合必须与来源一致，不能只使用模型所属的中心机构。
        LinkedHashSet<String> recorded = new LinkedHashSet<>(stringList(object.getContributorsJson()));
        if (!recorded.equals(contributors)) {
            throw denied("模型贡献方与原训练输入不一致，需先补齐完整来源关系");
        }
        return new Authorized(object, source, List.copyOf(contributors), hash(fingerprint));
    }

    /** 通用任务与回执入口读取报告前复核来源，避免绕过模型报告接口。 */
    public void requireReportRead(String taskId) {
        tasks.findById(new TeeRuntimeTaskDO.UPK(taskId)).ifPresent(stored -> {
            TeeTaskSpec task = readTask(stored.getTaskJws());
            if (isModelReport(task)) validate(task);
        });
    }

    public List<String> features(String objectId, String label) {
        TeeObjectDO object = objects.findById(new TeeObjectDO.UPK(objectId))
                .orElseThrow(() -> denied("模型密文对象不存在"));
        TeeRuntimeTaskDO source = tasks.findById(new TeeRuntimeTaskDO.UPK(object.getTaskId()))
                .orElseThrow(() -> denied("模型原任务不存在"));
        return readTask(source.getTaskJws()).columns().stream().filter(name -> !name.equals(label)).toList();
    }

    public TeeTaskSpec.Input input(Authorized authorized) {
        TeeObjectDO object = authorized.object();
        TeeTaskSpec.Input source = authorized.source().inputs().get(0);
        return new TeeTaskSpec.Input(object.getResultId(), 1, object.getKeyId(),
                Long.parseLong(object.getKeyVersion()), source.policyId(), source.policyVersion(),
                object.getUpk().getObjectId(), object.getCiphertextSha256(), object.getSizeBytes());
    }

    /** v2 输入仍使用原结果密钥，policy 引用指向原训练首项，完整来源由已验签任务回溯。 */
    public Authorized validate(TeeTaskSpec task) {
        if (!isModelReport(task) || task.inputs() == null || task.inputs().size() != 1
                || task.program() == null || !"BUILTIN".equals(task.program().kind())
                || !List.of(EVALUATION_OPERATOR.equals(task.operatorId()) ? EVALUATION_KIND : REPORT_KIND)
                        .equals(task.outputPolicy().reportKinds())) {
            throw denied("MODEL 报告任务结构无效");
        }
        Map<String, Object> p = task.program().parameters();
        boolean evaluation = EVALUATION_OPERATOR.equals(task.operatorId());
        if (p == null || !List.of(evaluation ? "DATA" : "MODEL").equals(p.get("inputKinds"))
                || !task.operatorId().equals(p.get("op")) || !PARSER_VERSION.equals(p.get("parserVersion"))) {
            throw denied("MODEL 报告任务缺少固定解析器绑定");
        }
        TeeTaskSpec.Input input = task.inputs().get(0);
        Authorized authorized = authorize(input.objectId(), task.sandboxId(), task.columns());
        if (!operator(authorized).equals(task.operatorId())
                || (evaluation && (!java.util.Objects.equals(label(authorized), p.get("label"))
                    || !java.util.Objects.equals(taskType(authorized), p.get("taskType"))))
                || !input(authorized).equals(input)
                || !authorized.object().getTaskId().equals(p.get("sourceTaskId"))
                || !authorized.policyFingerprint().equals(p.get("policyFingerprint"))
                || !task.columns().equals(p.get("features"))) {
            throw denied("MODEL 报告输入、来源或授权版本不匹配");
        }
        Object tree = p.get("treeIndex");
        if (!(tree instanceof Number number) || number.doubleValue() != number.intValue()
                || number.intValue() < 0 || number.intValue() > 100000) {
            throw denied("树索引必须是范围内的非负整数");
        }
        return authorized;
    }

    public String operator(Authorized authorized) {
        return "DATA".equals(authorized.object().getKind()) ? EVALUATION_OPERATOR : OPERATOR;
    }

    public String reportKind(Authorized authorized) {
        return "DATA".equals(authorized.object().getKind()) ? EVALUATION_KIND : REPORT_KIND;
    }

    public String label(Authorized authorized) {
        return java.util.Objects.toString(authorized.source().program().parameters().get("label"), "");
    }

    public String taskType(Authorized authorized) {
        return java.util.Objects.toString(authorized.source().program().parameters().get("task"), "classification");
    }

    public TeeTaskSpec readTask(String compact) {
        try { return mapper.treeToValue(payload(compact), TeeTaskSpec.class); }
        catch (Exception error) { throw denied("历史可信任务无法解析"); }
    }

    private JsonNode payload(String compact) {
        try { return mapper.readTree(TeeCrypto.decodeUrl(compact.split("\\.")[1])); }
        catch (Exception error) { throw denied("历史可信回执无法解析"); }
    }

    private List<String> stringList(String json) {
        try { return mapper.readerForListOf(String.class).readValue(json); }
        catch (Exception error) { throw denied("历史授权集合无法解析"); }
    }

    private String hash(Object value) {
        try { return TeeCrypto.sha256Hex(mapper.writeValueAsBytes(value)); }
        catch (Exception error) { throw denied("模型来源摘要无法计算"); }
    }

    private static TeeException denied(String message) {
        return TeeException.of(TeeContract.Error.POLICY_DENIED, message);
    }
}
