/*
 * Copyright 2026 Ant Group Co., Ltd.
 * Licensed under the Apache License, Version 2.0.
 */
package org.secretflow.secretpad.web.service.tee;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.regex.Pattern;

/**
 * 密文对象的落盘存储。
 *
 * <p>只存放密文封装，明文不落盘；对象标识固定为十六进制，避免路径穿越。
 * 元数据留在数据库，本类只负责字节。
 */
@Component
public class TeeObjectStore {

    private static final Pattern OBJECT_ID = Pattern.compile("^[0-9a-f]{32}$");

    private final Path root;
    private final ObjectMapper mapper;

    public TeeObjectStore(ObjectMapper mapper,
            @Value("${secretpad.data.dir-path:/app/data/}") String dataDir) {
        this.mapper = mapper;
        this.root = Path.of(dataDir).resolve("tee-objects");
    }

    public void write(String objectId, TeeCrypto.EncryptedObject object) {
        Path target = resolve(objectId);
        try {
            Files.createDirectories(root);
            Path temp = Files.createTempFile(root, "obj", ".tmp");
            Files.writeString(temp, mapper.writeValueAsString(object));
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密文对象写入失败");
        }
    }

    public TeeCrypto.EncryptedObject read(String objectId) {
        try {
            return mapper.readValue(Files.readString(resolve(objectId)), TeeCrypto.EncryptedObject.class);
        } catch (IOException failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "密文对象不存在或不可读");
        }
    }

    public void writeProgram(String objectId, byte[] content) {
        try {
            Files.createDirectories(root);
            Path temp = Files.createTempFile(root, "prg", ".tmp");
            Files.write(temp, content);
            Files.move(temp, resolve(objectId), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "程序对象写入失败");
        }
    }

    public byte[] readProgram(String objectId) {
        try {
            return Files.readAllBytes(resolve(objectId));
        } catch (IOException failure) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "程序对象不存在或不可读");
        }
    }

    private Path resolve(String objectId) {
        if (objectId == null || !OBJECT_ID.matcher(objectId).matches()) {
            throw TeeException.of(TeeContract.Error.CONTRACT_INVALID, "对象标识格式无效");
        }
        return root.resolve(objectId + ".json");
    }
}
