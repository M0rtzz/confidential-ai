/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.controller;

/**
 * 契约接口的标记。
 *
 * <p>登录拦截器按处理器类型识别这些接口并强制校验用户会话，
 * 因此新增契约接口必须实现本接口，否则会落到普通路径上，可能被鉴权开关或内部端口绕过。
 */
public interface TeeApi {
}
