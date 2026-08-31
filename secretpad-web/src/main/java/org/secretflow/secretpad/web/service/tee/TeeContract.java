/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import java.util.List;
import java.util.Set;

/** 冻结契约 tee-contract/1.0 的常量、限额与错误码；实现不得静默偏离本文件。 */
public final class TeeContract {

    public static final String VERSION = "tee-contract/1.0";
    public static final String PREFIX = "/api/v1alpha1/tee";

    /** 单个对象明文上限 64 MiB，单任务全部输入明文上限 256 MiB。 */
    public static final long MAX_OBJECT_PLAINTEXT_BYTES = 64L * 1024 * 1024;
    public static final long MAX_TASK_PLAINTEXT_BYTES = 256L * 1024 * 1024;
    public static final int MAX_TASK_JSON_BYTES = 1024 * 1024;
    public static final int MAX_REPORT_BYTES = 1024 * 1024;

    /** 任务有效期最长 5 分钟，时钟容差 30 秒。 */
    public static final long MAX_TASK_LIFETIME_SECONDS = 300;
    public static final long CLOCK_SKEW_SECONDS = 30;
    /** 幂等记录与 nonce 记录的最短保留时间。 */
    public static final long RETENTION_SECONDS = 24 * 3600;
    /** 导出密钥信封有效期。 */
    public static final long EXPORT_TTL_SECONDS = 300;

    public static final String KEY_ALGORITHM = "AES-256-GCM";
    public static final String ENVELOPE_ALGORITHM = "RSA-OAEP-256";
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;
    public static final int DATA_KEY_BYTES = 32;

    /** CM 把 '*' 当作放开全部列或算子；契约不支持通配符，登记与放行都要拒绝。 */
    public static final String WILDCARD = "*";

    public static final Set<String> REPORT_KINDS =
            Set.of("EVALUATION_METRICS", "FEATURE_IMPORTANCE", "TREE_STRUCTURE");
    public static final Set<String> RESULT_KINDS = Set.of("REPORT", "DATA", "MODEL");
    public static final Set<String> PROGRAM_KINDS = Set.of("BUILTIN", "SQL", "PYTHON", "JAR");
    public static final List<String> CHAIN_STAGES =
            List.of("KEY_ISSUE", "ENCRYPT", "POLICY", "ATTESTATION", "EXECUTION", "EGRESS");

    public static final String STATE_ACTIVE = "ACTIVE";
    public static final String STATE_REVOKED = "REVOKED";
    public static final String EXPORT_PENDING = "PENDING_APPROVAL";
    public static final String EXPORT_APPROVED = "APPROVED";

    /** 契约第八节的错误码表；不新增条目，破坏性变更须发布新的契约主版本。 */
    public enum Error {
        END_ROLE_DENIED(49001, 403, false),
        END_ROLE_REQUIRED(49002, 200, false),
        RELOGIN_REQUIRED(49003, 401, false),
        ASSET_OWNER_MISMATCH(49004, 200, false),
        KEY_REVOKED(49005, 200, false),
        POLICY_DENIED(49006, 200, false),
        REQUEST_ID_CONFLICT(49007, 200, false),
        TASK_SIGNATURE_INVALID(49008, 200, false),
        TASK_REPLAYED(49009, 200, false),
        EXPORT_NOT_APPROVED(49010, 200, false),
        REAL_MODE_UNAVAILABLE(49011, 200, false),
        AUDIT_ACCESS_DENIED(49012, 403, false),
        CONTRACT_INVALID(49013, 400, false),
        PAYLOAD_TOO_LARGE(49014, 413, false),
        KEY_SERVICE_UNAVAILABLE(49015, 503, true),
        TASK_EXPIRED(49016, 200, false),
        DATA_INTEGRITY_FAILED(49017, 200, false);

        private final int code;
        private final int httpStatus;
        private final boolean retryable;

        Error(int code, int httpStatus, boolean retryable) {
            this.code = code;
            this.httpStatus = httpStatus;
            this.retryable = retryable;
        }

        public int code() {
            return code;
        }

        public int httpStatus() {
            return httpStatus;
        }

        public boolean retryable() {
            return retryable;
        }
    }

    private TeeContract() {
    }
}
