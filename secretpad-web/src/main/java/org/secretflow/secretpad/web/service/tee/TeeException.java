/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

/** 契约层拒绝；只携带错误码与可公开的简短说明，不暴露密钥、数据行或内部堆栈。 */
public class TeeException extends RuntimeException {

    private final TeeContract.Error error;

    public TeeException(TeeContract.Error error, String message) {
        super(message, null, false, false);
        this.error = error;
    }

    public static TeeException of(TeeContract.Error error, String message) {
        return new TeeException(error, message);
    }

    public TeeContract.Error error() {
        return error;
    }
}
