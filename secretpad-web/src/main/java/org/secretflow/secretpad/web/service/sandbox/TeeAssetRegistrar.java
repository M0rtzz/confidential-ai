/*
 * Copyright 2026 Ant Group Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 */
package org.secretflow.secretpad.web.service.sandbox;

import java.util.Map;

/**
 * 供数方投出同意票时，把本方数据按批准的列与算子登记进密文资产台账。
 *
 * <p>抽样脱敏产出只是加密落盘，尚未成为契约意义上的密文资产；可信运行时按台账里的
 * 资产与授权策略放行，缺这一步则任何计算都会以「挂载版本未登记为密文资产」被拒。</p>
 */
public interface TeeAssetRegistrar {

    /**
     * 登记该审批单里属于本方的密文数据。
     *
     * @param approval 申请单行，需含 {@code payload_json}、{@code sandbox_id} 与 {@code approval_type}
     */
    void registerApproved(Map<String, Object> approval);
}
