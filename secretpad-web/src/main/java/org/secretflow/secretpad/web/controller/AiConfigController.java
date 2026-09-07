package org.secretflow.secretpad.web.controller;

import org.secretflow.secretpad.common.constant.resource.ApiResourceCodeConstants;
import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.service.model.common.SecretPadResponse;
import org.secretflow.secretpad.web.service.ai.AiConfigService;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.LinkedHashMap;

/** Institution-wide AI configuration shown from the user menu. */
@RestController
@RequestMapping("/api/v1alpha1/data-sandbox/ai-config")
public class AiConfigController implements CryptoApi {
    private final AiConfigService service;
    private final String adminName;

    public AiConfigController(AiConfigService service,
            @Value("${secretpad.auth.pad_name:admin}") String adminName) {
        this.service = service;
        this.adminName = adminName;
    }

    @GetMapping
    public SecretPadResponse<Map<String, Object>> current() {
        UserContextDTO user = user();
        Map<String, Object> value = new LinkedHashMap<>(service.current(user.getOwnerId()));
        value.put("editable", isAdmin(user));
        return SecretPadResponse.success(value);
    }

    @PutMapping
    public SecretPadResponse<Map<String, Object>> save(@RequestBody AiConfigService.SaveRequest request) {
        requireAdmin();
        UserContextDTO user = user();
        return SecretPadResponse.success(service.save(user.getOwnerId(), user.getName(), request));
    }

    @PostMapping("/test")
    public SecretPadResponse<Map<String, Object>> test() {
        requireAdmin();
        return SecretPadResponse.success(service.test(user().getOwnerId()));
    }

    private void requireAdmin() {
        UserContextDTO user = user();
        if (!isAdmin(user)) {
            throw TeeException.of(TeeContract.Error.AUDIT_ACCESS_DENIED, "仅机构管理员可以修改 AI 配置");
        }
    }

    private boolean isAdmin(UserContextDTO user) {
        return adminName.equalsIgnoreCase(user.getName())
                || user.containInterfaceResource(ApiResourceCodeConstants.ALL_INTERFACE_RESOURCE);
    }

    private static UserContextDTO user() {
        return UserContext.getUser();
    }
}
