/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.secretflow.secretpad.persistence.entity.InstDO;
import org.secretflow.secretpad.common.enums.PlatformTypeEnum;
import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.manager.integration.noderoute.AbstractNodeRouteManager;
import org.secretflow.secretpad.persistence.entity.NodeDO;
import org.secretflow.secretpad.persistence.entity.NodeRouteDO;
import org.secretflow.secretpad.persistence.entity.ProjectJobDO;
import org.secretflow.secretpad.persistence.entity.ProjectNodeDO;
import org.secretflow.secretpad.service.EnvService;
import org.secretflow.v1alpha1.kusciaapi.DomainRoute;
import org.secretflow.secretpad.persistence.entity.TeeExportRequestDO;
import org.secretflow.secretpad.persistence.entity.TeeKeyDO;
import org.secretflow.secretpad.persistence.entity.TeeObjectDO;
import org.secretflow.secretpad.persistence.entity.TeePolicyDO;
import org.secretflow.secretpad.persistence.entity.TeeRuntimeTaskDO;
import org.secretflow.secretpad.persistence.model.GraphJobStatus;
import org.secretflow.secretpad.persistence.repository.InstRepository;
import org.secretflow.secretpad.persistence.repository.NodeRepository;
import org.secretflow.secretpad.persistence.repository.NodeRouteRepository;
import org.secretflow.secretpad.persistence.repository.ProjectJobRepository;
import org.secretflow.secretpad.persistence.repository.ProjectNodeRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportRequestRepository;
import org.secretflow.secretpad.persistence.repository.TeeExportVoteRepository;
import org.secretflow.secretpad.persistence.repository.TeeKeyRepository;
import org.secretflow.secretpad.persistence.repository.TeeObjectRepository;
import org.secretflow.secretpad.persistence.repository.TeePolicyRepository;
import org.secretflow.secretpad.persistence.repository.TeeRuntimeTaskRepository;
import org.secretflow.secretpad.web.service.DataSandboxMvpService;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;

/**
 * P2 + P8 只读聚合接口：把中心端权威台账与客户端既有委派汇总成信任链视图。
 *
 * <p>本类不新增任何 {@code /api/v1alpha1/tee} 契约接口，也不改
 * {@link TeeCenterClient}：中心端（{@code center.configured()==false}）直接查本地仓库，
 * 是全系统的全量视角；客户端（{@code configured()==true}）只能看到自己机构的数据，
 * 凡是既有委派已覆盖的（密钥台账、可导出结果、我的导出工单）复用委派，
 * 中心端独占裁决且客户端不留存台账的段（规则校验、TEE 执行）在客户端实例上直接不返回。
 */
@Service
public class TrustChainService {

    private static final int MAX_TASK_LIMIT = 200;
    private static final int DEFAULT_TASK_LIMIT = 50;
    private static final int RECENT_LOG_LIMIT = 20;
    private static final int PREVIEW_BYTES = 256;

    public record InstanceView(String endRole, String instanceName, String contractVersion) {
    }

    public record Metric(String label, long value) {
    }

    public record Segment(String key, String label, String state, List<Metric> metrics) {
    }

    public record SummaryView(String endRole, String ownerId, String ownerName, String contractVersion,
                              TeeEnvironmentService.Environment environment, String runtimeImageId,
                              List<Segment> segments) {
    }

    public record KeysView(List<TeeKeyService.LedgerItem> items) {
    }

    public record PolicyItem(String policyId, String policyVersion, String assetId, String ownerId,
                             String sandboxId, List<String> columns, List<String> operators,
                             List<String> reportKinds, String expiresAt, String state, String approvalId) {
    }

    public record LogItem(String at, String actor, String action, boolean allowed,
                          String detail) {
    }

    public record PoliciesView(List<PolicyItem> items, List<LogItem> recent) {
    }

    public record ObjectItem(String objectId, String kind, String ownerId, String assetId, String taskId,
                             String resultId, String keyId, String keyVersion, String ciphertextSha256,
                             long sizeBytes, List<String> contributors, String exportState, String gmtCreate) {
    }

    public record ObjectsView(List<ObjectItem> items) {
    }

    public record PreviewView(String objectId, long sizeBytes, int previewBytes, String hex) {
    }

    public record TaskItem(String taskId, String requestId, String callerId, List<String> contributors,
                           String status, String operator, String expiresAt, boolean receiptVerified,
                           String gmtCreate, String gmtModified) {
    }

    public record TasksView(List<TaskItem> items) {
    }

    public record VoteItem(String ownerId, String decision, String at) {
    }

    public record ExportItem(String exportId, String resultId, String objectId, String kind, String taskId,
                             String requesterOwnerId, String status, String approvedAt, String gmtCreate,
                             List<VoteItem> votes) {
    }

    public record ExportsView(List<ExportItem> items) {
    }

    /** 本端登记的一条节点路由及其在 Kuscia 中的实际状态。 */
    public record RouteItem(String direction, String srcNodeId, String dstNodeId, String status) {
    }

    public record PeerItem(String ownerId, String ownerName, String nodeId, String address, String certSha256,
                           List<RouteItem> routes,
                           Boolean contractChannelReachable, String contractCheckedAt) {
    }

    public record PeerView(String endRole, boolean bound, List<PeerItem> peers) {
    }

    public record Blocker(String key, String label, long count, String hint) {
    }

    public record UnbindCheckView(boolean clean, List<Blocker> blockers) {
    }

    private final TeeCenterClient center;
    private final TeeEnvironmentService environmentService;
    private final TeeKeyRepository keyRepository;
    private final TeeKeyGateway keyGateway;
    private final TeePolicyRepository policyRepository;
    private final TeeObjectRepository objectRepository;
    private final TeeObjectStore objectStore;
    private final TeeExportRequestRepository exportRequestRepository;
    private final TeeExportVoteRepository exportVoteRepository;
    private final TeeExportGateway exportGateway;
    private final TeeRuntimeTaskRepository taskRepository;
    private final NodeRepository nodeRepository;
    private final NodeRouteRepository nodeRouteRepository;
    private final InstRepository instRepository;
    private final ProjectNodeRepository projectNodeRepository;
    private final ProjectJobRepository projectJobRepository;
    private final TeeIdentityRegistry identityRegistry;
    private final AbstractNodeRouteManager nodeRouteManager;
    private final EnvService envService;
    private final DataSandboxMvpService mvp;
    private final ObjectMapper mapper;

    @Value("${TEE_END_ROLES:CENTER,CLIENT}")
    private String allowedEndRoles;

    /** 部署时登记的运行镜像摘要；仅用于看板展示，不参与任何鉴权判断。 */
    @Value("${secretpad.data-sandbox.tee.runtime-image-digest:}")
    private String runtimeImageId;

    public TrustChainService(TeeCenterClient center, TeeEnvironmentService environmentService,
                             TeeKeyRepository keyRepository, TeeKeyGateway keyGateway,
                             TeePolicyRepository policyRepository, TeeObjectRepository objectRepository,
                             TeeObjectStore objectStore, TeeExportRequestRepository exportRequestRepository,
                             TeeExportVoteRepository exportVoteRepository, TeeExportGateway exportGateway,
                             TeeRuntimeTaskRepository taskRepository, NodeRepository nodeRepository,
                             NodeRouteRepository nodeRouteRepository, InstRepository instRepository,
                             ProjectNodeRepository projectNodeRepository, ProjectJobRepository projectJobRepository,
                             TeeIdentityRegistry identityRegistry, AbstractNodeRouteManager nodeRouteManager,
                             EnvService envService, DataSandboxMvpService mvp, ObjectMapper mapper) {
        this.center = center;
        this.environmentService = environmentService;
        this.keyRepository = keyRepository;
        this.keyGateway = keyGateway;
        this.policyRepository = policyRepository;
        this.objectRepository = objectRepository;
        this.objectStore = objectStore;
        this.exportRequestRepository = exportRequestRepository;
        this.exportVoteRepository = exportVoteRepository;
        this.exportGateway = exportGateway;
        this.taskRepository = taskRepository;
        this.nodeRepository = nodeRepository;
        this.nodeRouteRepository = nodeRouteRepository;
        this.instRepository = instRepository;
        this.projectNodeRepository = projectNodeRepository;
        this.projectJobRepository = projectJobRepository;
        this.identityRegistry = identityRegistry;
        this.nodeRouteManager = nodeRouteManager;
        this.envService = envService;
        this.mvp = mvp;
        this.mapper = mapper;
    }

    /** 本实例声明列表的首项即端身份；免登录的 /instance 接口与鉴权判断都以它为准。 */
    public String endRole() {
        String[] parts = allowedEndRoles.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                return trimmed;
            }
        }
        return "CENTER";
    }

    public boolean isCenterInstance() {
        return !center.configured();
    }

    public InstanceView instance() {
        String role = endRole();
        return new InstanceView(role, "CENTER".equals(role) ? "中心端" : "客户端", TeeContract.VERSION);
    }

    public SummaryView summary(String ownerId, String ownerName) {
        boolean isCenter = isCenterInstance();
        List<Segment> segments = new ArrayList<>();
        segments.add(keyIssueSegment(ownerId, isCenter));
        segments.add(dataEncryptSegment(ownerId, isCenter));
        if (isCenter) {
            segments.add(policyCheckSegment());
        }
        segments.add(attestationSegment());
        if (isCenter) {
            segments.add(teeExecSegment());
        }
        segments.add(egressSegment(ownerId, isCenter));
        return new SummaryView(endRole(), ownerId, ownerName, TeeContract.VERSION,
                environmentService.environment(), runtimeImageId, segments);
    }

    public KeysView keys(String ownerId) {
        return new KeysView(keyLedger(ownerId, isCenterInstance()));
    }

    public PoliciesView policies() {
        if (!isCenterInstance()) {
            return new PoliciesView(List.of(), List.of());
        }
        List<PolicyItem> items = policyRepository.findTop200ByOrderByGmtCreateDesc().stream()
                .map(this::toPolicyItem).toList();
        return new PoliciesView(items, recentTeeLogs());
    }

    public ObjectsView objects(String ownerId) {
        return new ObjectsView(objectItems(ownerId, isCenterInstance()));
    }

    /** 只返回密文前 256 字节的十六进制；调用方必须是贡献机构，或本端为中心端。 */
    public PreviewView preview(String ownerId, String objectId) {
        TeeObjectDO record = objectRepository.findById(new TeeObjectDO.UPK(objectId))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "对象不存在"));
        List<String> contributors = readStrings(record.getContributorsJson());
        if (!isCenterInstance() && !contributors.contains(ownerId)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "无权预览该密文对象");
        }
        byte[] ciphertext = TeeCrypto.decode(objectStore.read(objectId).ciphertextB64());
        int n = Math.min(PREVIEW_BYTES, ciphertext.length);
        String hex = java.util.HexFormat.of().formatHex(ciphertext, 0, n);
        long sizeBytes = record.getSizeBytes() == null ? 0 : record.getSizeBytes();
        return new PreviewView(objectId, sizeBytes, n, hex);
    }

    public TasksView tasks(Integer limit) {
        if (!isCenterInstance()) {
            return new TasksView(List.of());
        }
        int n = limit == null ? DEFAULT_TASK_LIMIT : Math.max(1, Math.min(limit, MAX_TASK_LIMIT));
        List<TaskItem> items = taskRepository.findTop200ByOrderByGmtCreateDesc().stream()
                .limit(n).map(this::toTaskItem).toList();
        return new TasksView(items);
    }

    public TeeRuntimeService.ReceiptResult receipt(String taskId) {
        TeeRuntimeTaskDO task = taskRepository.findById(new TeeRuntimeTaskDO.UPK(taskId))
                .orElseThrow(() -> TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "任务不存在"));
        if (!Boolean.TRUE.equals(task.getReceiptVerified()) || task.getReceiptJws() == null) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "任务尚无已核实回执");
        }
        return new TeeRuntimeService.ReceiptResult(TeeContract.VERSION, taskId, task.getReceiptJws(), true);
    }

    public ExportsView exports(String ownerId) {
        return new ExportsView(exportItems(ownerId, isCenterInstance()));
    }

    public PeerView peer(String ownerId) {
        boolean isCenter = isCenterInstance();
        String selfNodeId = selfNodeId(ownerId);
        Set<NodeRouteDO> routes = nodeRouteRepository.findBySrcNodeIdOrDstNodeId(selfNodeId);
        Set<String> peerNodeIds = new LinkedHashSet<>();
        for (NodeRouteDO route : routes) {
            peerNodeIds.add(selfNodeId.equals(route.getSrcNodeId())
                    ? route.getDstNodeId() : route.getSrcNodeId());
        }
        Map<String, List<RouteItem>> byPeer = new LinkedHashMap<>();
        for (String peerNodeId : peerNodeIds) {
            // 两个方向都向 Kuscia 查一次：本端只登记自己创建的那一条，另一条在对端库里。
            byPeer.put(peerNodeId, List.of(
                    new RouteItem("OUTBOUND", selfNodeId, peerNodeId,
                            routeStatus(selfNodeId, peerNodeId)),
                    new RouteItem("INBOUND", peerNodeId, selfNodeId,
                            routeStatus(peerNodeId, selfNodeId))));
        }
        List<PeerItem> peers = new ArrayList<>();
        for (Map.Entry<String, List<RouteItem>> entry : byPeer.entrySet()) {
            NodeDO peerNode = nodeRepository.findByNodeId(entry.getKey());
            if (peerNode == null) {
                continue;
            }
            String peerOwnerId = notBlank(peerNode.getInstId()) ? peerNode.getInstId() : peerNode.getNodeId();
            InstDO inst = instRepository.findByInstId(peerOwnerId);
            String peerOwnerName = inst != null ? inst.getName() : peerNode.getName();
            Boolean reachable = isCenter ? null : center.reachable();
            String checkedAt = isCenter ? null : Instant.now().toString();
            peers.add(new PeerItem(peerOwnerId, peerOwnerName, peerNode.getNodeId(),
                    emptyIfNull(peerNode.getNetAddress()), safeFingerprint(peerOwnerId),
                    List.copyOf(entry.getValue()), reachable, checkedAt));
        }
        if (!isCenter && peers.size() > 1) {
            // 客户端至多一条：中心端。
            peers = peers.subList(0, 1);
        }
        boolean bound = isCenter ? !peers.isEmpty() : center.configured();
        return new PeerView(endRole(), bound, peers);
    }

    /**
     * 查询「from → to」这条路由在 Kuscia 中的实际状态。
     *
     * <p>不能用"本端 node_route 有没有这条记录"代替：每个平台只登记自己创建的那一条，
     * 两端各存一半，用记录是否存在推断会把对端创建的那一半误报为未就绪。
     * AUTONOMY 下按对端视角登记路由，查询时把 channel 固定为发起方，与
     * {@code NodeRouterServiceImpl.queryPage} 的换算保持一致。
     */
    private String routeStatus(String fromNodeId, String toNodeId) {
        try {
            boolean autonomy = PlatformTypeEnum.AUTONOMY.equals(envService.getPlatformType());
            DomainRoute.RouteStatus status = nodeRouteManager.getRouteStatus(
                    fromNodeId, toNodeId, autonomy ? fromNodeId : null);
            return status == null || status.getStatus() == null ? "Unknown" : status.getStatus();
        } catch (RuntimeException ignored) {
            return "Unknown";
        }
    }

    /**
     * 机构标识不等于节点标识：P2P 部署下会话的 ownerId 是机构 ID，路由表用的是节点 ID。
     * 优先取会话里的 platformNodeId，其次按机构反查节点，都取不到时才退回原值。
     */
    private String selfNodeId(String ownerId) {
        UserContextDTO user = UserContext.getUserOrNotExist();
        if (user != null && notBlank(user.getPlatformNodeId())) {
            return user.getPlatformNodeId();
        }
        List<NodeDO> owned = nodeRepository.findByInstId(ownerId);
        if (!owned.isEmpty()) {
            return owned.get(0).getNodeId();
        }
        NodeDO self = nodeRepository.findByNodeId(ownerId);
        return self != null ? self.getNodeId() : ownerId;
    }

    public UnbindCheckView unbindCheck(String ownerId) {
        boolean isCenter = isCenterInstance();
        long activeKeys;
        long openExports;
        long liveObjects;
        if (isCenter) {
            activeKeys = keyRepository.findByOwnerId(ownerId).stream()
                    .filter(k -> TeeContract.STATE_ACTIVE.equals(k.getState())).count();
            openExports = exportRequestRepository.findByRequesterOwnerIdOrderByGmtCreateDesc(ownerId).stream()
                    .filter(r -> "PENDING_APPROVAL".equals(r.getStatus())).count();
            liveObjects = objectRepository.findTop200ByOrderByGmtCreateDesc().stream()
                    .filter(o -> Set.of("DATA", "MODEL").contains(o.getKind()))
                    .filter(o -> readStrings(o.getContributorsJson()).contains(ownerId))
                    .count();
        } else {
            activeKeys = keyGateway.ledger(ownerId).stream()
                    .filter(item -> TeeContract.STATE_ACTIVE.equals(item.state())).count();
            openExports = exportGateway.mine(ownerId).items().stream()
                    .filter(view -> "PENDING_APPROVAL".equals(view.status())).count();
            liveObjects = exportGateway.exportable(ownerId).items().size();
        }
        long runningJobs = runningJobCount(ownerId);
        List<Blocker> blockers = List.of(
                new Blocker("ACTIVE_KEY", "生效的数据密钥", activeKeys, "在密钥台账逐把吊销"),
                new Blocker("OPEN_EXPORT", "未完结的导出工单", openExports, "投票结清或撤销工单"),
                new Blocker("LIVE_OBJECT", "仍在中心端的密文结果", liveObjects, "清理结果对象"),
                new Blocker("RUNNING_JOB", "运行中的作业", runningJobs, "等待作业结束"));
        boolean clean = blockers.stream().allMatch(b -> b.count() == 0);
        return new UnbindCheckView(clean, blockers);
    }

    /* ------------------------------- Segments ------------------------------- */

    private Segment keyIssueSegment(String ownerId, boolean isCenter) {
        List<TeeKeyService.LedgerItem> items = keyLedger(ownerId, isCenter);
        long active = items.stream().filter(item -> TeeContract.STATE_ACTIVE.equals(item.state())).count();
        long revoked = items.stream().filter(item -> TeeContract.STATE_REVOKED.equals(item.state())).count();
        return new Segment("KEY_ISSUE", "密钥签发", items.isEmpty() ? "EMPTY" : "OK",
                List.of(new Metric("生效", active), new Metric("已吊销", revoked)));
    }

    private Segment dataEncryptSegment(String ownerId, boolean isCenter) {
        List<ObjectItem> items = objectItems(ownerId, isCenter);
        long pending = items.stream().filter(item -> TeeContract.EXPORT_PENDING.equals(item.exportState())).count();
        return new Segment("DATA_ENCRYPT", "数据加密", items.isEmpty() ? "EMPTY" : "OK",
                List.of(new Metric("密文对象", items.size()), new Metric("待导出", pending)));
    }

    private Segment policyCheckSegment() {
        List<TeePolicyDO> items = policyRepository.findTop200ByOrderByGmtCreateDesc();
        long active = items.stream().filter(p -> TeeContract.STATE_ACTIVE.equals(p.getState())).count();
        return new Segment("POLICY_CHECK", "规则校验", items.isEmpty() ? "EMPTY" : "OK",
                List.of(new Metric("生效", active), new Metric("总数", items.size())));
    }

    /** 仿真模式下环境认证恒为 WARN，不因阻塞项数量升降级为 OK 或 EMPTY。 */
    private Segment attestationSegment() {
        TeeEnvironmentService.Environment environment = environmentService.environment();
        return new Segment("ATTESTATION", "环境认证", "WARN",
                List.of(new Metric("阻塞项", environment.blockers().size())));
    }

    private Segment teeExecSegment() {
        List<TeeRuntimeTaskDO> items = taskRepository.findTop200ByOrderByGmtCreateDesc();
        long verified = items.stream().filter(t -> Boolean.TRUE.equals(t.getReceiptVerified())).count();
        return new Segment("TEE_EXEC", "TEE 执行", items.isEmpty() ? "EMPTY" : "OK",
                List.of(new Metric("已核实回执", verified), new Metric("总任务", items.size())));
    }

    private Segment egressSegment(String ownerId, boolean isCenter) {
        List<ExportItem> items = exportItems(ownerId, isCenter);
        long approved = items.stream().filter(item -> TeeContract.EXPORT_APPROVED.equals(item.status())).count();
        return new Segment("EGRESS", "出域管控", items.isEmpty() ? "EMPTY" : "OK",
                List.of(new Metric("已批准", approved), new Metric("总数", items.size())));
    }

    /* ------------------------------- Mapping helpers ------------------------------- */

    private List<TeeKeyService.LedgerItem> keyLedger(String ownerId, boolean isCenter) {
        if (!isCenter) {
            return keyGateway.ledger(ownerId);
        }
        return keyRepository.findTop200ByOrderByGmtCreateDesc().stream()
                .map(key -> new TeeKeyService.LedgerItem(key.getUpk().getKeyId(), key.getUpk().getKeyVersion(),
                        key.getAssetId(), key.getOwnerId(), key.getState(), key.getIssuedAt(),
                        key.getClaimCount(), key.getReleaseCount()))
                .toList();
    }

    /**
     * 中心端返回全量密文对象；客户端由本地登记的资产对象（kind=ASSET，本端直接落盘）
     * 与既有 {@code /exports/exportable} 委派（结果对象）拼合而成——结果对象只在中心端
     * 执行任务时写入，客户端本地不会有这类记录。
     */
    private List<ObjectItem> objectItems(String ownerId, boolean isCenter) {
        if (isCenter) {
            return objectRepository.findTop200ByOrderByGmtCreateDesc().stream()
                    .map(this::toObjectItem).toList();
        }
        List<ObjectItem> items = new ArrayList<>();
        objectRepository.findTop200ByOwnerIdOrderByGmtCreateDesc(ownerId).forEach(
                object -> items.add(toObjectItem(object)));
        for (TeeExportService.ExportableView view : exportGateway.exportable(ownerId).items()) {
            items.add(new ObjectItem(view.objectId(), view.kind(), ownerId, "", emptyIfNull(view.taskId()),
                    view.resultId(), view.keyId(), view.keyVersion(), view.ciphertextSha256(),
                    view.sizeBytes() == null ? 0 : view.sizeBytes(), view.contributors(), view.exportState(), ""));
        }
        return items.size() > 200 ? items.subList(0, 200) : items;
    }

    private ObjectItem toObjectItem(TeeObjectDO object) {
        return new ObjectItem(object.getUpk().getObjectId(), object.getKind(), object.getOwnerId(),
                emptyIfNull(object.getAssetId()), emptyIfNull(object.getTaskId()),
                emptyIfNull(object.getResultId()), object.getKeyId(), object.getKeyVersion(),
                object.getCiphertextSha256(), object.getSizeBytes() == null ? 0 : object.getSizeBytes(),
                readStrings(object.getContributorsJson()), object.getExportState(),
                object.getGmtCreate() == null ? "" : object.getGmtCreate().toString());
    }

    private PolicyItem toPolicyItem(TeePolicyDO policy) {
        return new PolicyItem(policy.getUpk().getPolicyId(), policy.getUpk().getPolicyVersion(),
                policy.getAssetId(), policy.getOwnerId(), policy.getSandboxId(),
                readStrings(policy.getColumnsJson()), readStrings(policy.getOperatorsJson()),
                readStrings(policy.getReportKindsJson()), policy.getExpiresAt(), policy.getState(),
                policy.getApprovalId());
    }

    private TaskItem toTaskItem(TeeRuntimeTaskDO task) {
        return new TaskItem(task.getUpk().getTaskId(), task.getRequestId(), task.getCallerId(),
                readStrings(task.getContributorsJson()), task.getStatus(), operatorOf(task.getTaskJws()),
                task.getExpiresAt(), Boolean.TRUE.equals(task.getReceiptVerified()),
                task.getGmtCreate() == null ? "" : task.getGmtCreate().toString(),
                task.getGmtModified() == null ? "" : task.getGmtModified().toString());
    }

    /** 签名任务的 operatorId 只用于展示，解析失败不影响列表其余字段。 */
    private String operatorOf(String taskJws) {
        try {
            String[] parts = taskJws.split("\\.");
            JsonNode payload = mapper.readTree(TeeCrypto.decodeUrl(parts[1]));
            return payload.path("operatorId").asText("");
        } catch (Exception ignored) {
            return "";
        }
    }

    private List<ExportItem> exportItems(String ownerId, boolean isCenter) {
        if (isCenter) {
            return exportRequestRepository.findTop200ByOrderByGmtCreateDesc().stream()
                    .map(this::toExportItem).toList();
        }
        return exportGateway.mine(ownerId).items().stream().map(this::toExportItem).toList();
    }

    private ExportItem toExportItem(TeeExportRequestDO request) {
        List<VoteItem> votes = exportVoteRepository
                .findByUpkExportIdOrderByUpkVoterOwnerId(request.getUpk().getExportId()).stream()
                .map(vote -> new VoteItem(vote.getUpk().getVoterOwnerId(), vote.getStatus(), vote.getVotedAt()))
                .toList();
        return new ExportItem(request.getUpk().getExportId(), request.getResultId(), request.getObjectId(),
                request.getKind(), request.getTaskId(), request.getRequesterOwnerId(), request.getStatus(),
                request.getApprovedAt(),
                request.getGmtCreate() == null ? "" : request.getGmtCreate().toString(), votes);
    }

    private ExportItem toExportItem(TeeExportService.RequestView view) {
        List<VoteItem> votes = view.votes().stream()
                .map(vote -> new VoteItem(vote.ownerId(), vote.status(), vote.votedAt())).toList();
        return new ExportItem(view.exportId(), view.resultId(), view.objectId(), view.kind(), view.taskId(),
                view.requesterOwnerId(), view.status(), view.approvedAt(), "", votes);
    }

    /** 统一日志中 TEE 相关动作最近 20 条，成功与拒绝都保留。 */
    private List<LogItem> recentTeeLogs() {
        return mvp.listLogs("TEE", null, null, null, null, null, RECENT_LOG_LIMIT).stream()
                .map(row -> new LogItem(String.valueOf(row.get("created_at")), String.valueOf(row.get("actor")),
                        String.valueOf(row.get("action")), truthy(row.get("success")),
                        String.valueOf(row.get("detail"))))
                .toList();
    }

    /**
     * 与 {@code NodeRouterServiceImpl.validateNoRunningJobs} 同一套项目与作业查询，按机构而非单条路由统计。
     * 项目成员关系记的是节点标识，机构标识要先展开成它名下的全部节点。
     */
    private long runningJobCount(String ownerId) {
        List<String> nodeIds = new ArrayList<>(
                nodeRepository.findByInstId(ownerId).stream().map(NodeDO::getNodeId).toList());
        if (nodeIds.isEmpty()) {
            nodeIds.add(ownerId);
        }
        List<ProjectNodeDO> nodes = projectNodeRepository.findByNodeIds(nodeIds);
        Set<String> projectIds = new LinkedHashSet<>();
        for (ProjectNodeDO node : nodes) {
            projectIds.add(node.getUpk().getProjectId());
        }
        if (projectIds.isEmpty()) {
            return 0;
        }
        List<ProjectJobDO> jobs = projectJobRepository.findByProjectIds(List.copyOf(projectIds));
        if (jobs.isEmpty()) {
            return 0;
        }
        List<String> jobIds = jobs.stream().map(job -> job.getUpk().getJobId()).toList();
        List<GraphJobStatus> statuses = projectJobRepository.findStatusByJobIds(jobIds);
        return statuses.stream().filter(status -> status == GraphJobStatus.RUNNING).count();
    }

    private String safeFingerprint(String ownerId) {
        try {
            return identityRegistry.institutionFingerprint(ownerId);
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    private List<String> readStrings(String json) {
        try {
            return mapper.readerForListOf(String.class).readValue(json);
        } catch (Exception failure) {
            return List.of();
        }
    }

    private static boolean truthy(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        return "1".equals(String.valueOf(value)) || "true".equalsIgnoreCase(String.valueOf(value));
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private static String emptyIfNull(String value) {
        return value == null ? "" : value;
    }
}
