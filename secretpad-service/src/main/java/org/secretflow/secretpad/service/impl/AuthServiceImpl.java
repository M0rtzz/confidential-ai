/*
 * Copyright 2023 Ant Group Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.secretflow.secretpad.service.impl;

import org.secretflow.secretpad.common.constant.CacheConstants;
import org.secretflow.secretpad.common.dto.UserContextDTO;
import org.secretflow.secretpad.common.enums.ResourceTypeEnum;
import org.secretflow.secretpad.common.enums.UserOwnerTypeEnum;
import org.secretflow.secretpad.common.errorcode.AuthErrorCode;
import org.secretflow.secretpad.common.exception.SecretpadException;
import org.secretflow.secretpad.common.util.UUIDUtils;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.persistence.entity.*;
import org.secretflow.secretpad.persistence.repository.*;
import org.secretflow.secretpad.service.AuthService;
import org.secretflow.secretpad.service.EnvService;
import org.secretflow.secretpad.service.SysResourcesBizService;
import org.secretflow.secretpad.service.UserService;

import jakarta.annotation.Resource;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * User auth service implementation class
 *
 * @author : xiaonan.fhn
 * @date 2023/5/25
 */
@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserService userService;

    @Autowired
    private UserAccountsRepository userAccountsRepository;

    @Autowired
    private UserTokensRepository userTokensRepository;

    @Autowired
    private ProjectNodeRepository projectNodeRepository;

    @Autowired
    private EnvService envService;

    @Autowired
    private SysResourcesBizService resourcesBizService;

    @Value("${secretpad.deploy-mode}")
    private String deployMode;


    @Value("${secretpad.account-error-max-attempts:5}")
    private Integer maxAttempts;

    @Value("${secretpad.account-error-lock-time-minutes:30}")
    private Integer lockTimeMinutes;

    @Value("${secretpad.auth.pad_name:admin}")
    private String adminName;

    /** 实例支持的端；生产按端部署，开发机可两端都开。 */
    @org.springframework.beans.factory.annotation.Value("${TEE_END_ROLES:CLIENT,CENTER}")
    private String allowedEndRoles;

    @Resource
    private CacheManager cacheManager;
    @Resource
    private InstRepository instRepository;
    @Resource
    private NodeRepository nodeRepository;

    /**
     * 解析本次会话的端角色。
     *
     * <p>实例通过 {@code secretpad.tee-end-roles} 声明自己支持哪些端：
     * 生产按端部署为单端，开发机允许两端都开。单端实例可省略选择，双端实例必须显式选择。
     * 端角色由服务端决定，不接受请求头自报，也不因端角色额外授予机构或项目权限。
     */
    private String resolveEndRole(String requested) {
        java.util.List<String> allowed = java.util.Arrays.stream(allowedEndRoles.split(","))
                .map(String::trim).filter(value -> !value.isEmpty()).distinct().toList();
        if (allowed.isEmpty()) {
            throw SecretpadException.of(AuthErrorCode.AUTH_FAILED, "instance declares no end role");
        }
        if (requested == null || requested.isBlank()) {
            if (allowed.size() == 1) {
                return allowed.get(0);
            }
            throw SecretpadException.of(AuthErrorCode.AUTH_FAILED, "END_ROLE_REQUIRED");
        }
        String value = requested.trim();
        if (!allowed.contains(value)) {
            throw SecretpadException.of(AuthErrorCode.AUTH_FAILED, "END_ROLE_DENIED");
        }
        return value;
    }

    @Override
    @Transactional(rollbackFor = Exception.class, noRollbackFor = SecretpadException.class)
    public UserContextDTO login(String name, String passwordHash, String endRole) {
        //check password and lock
        AccountsDO user = accountLockedCheck(name, passwordHash);
        String token = UUIDUtils.newUUID();
        user.setLastLoginAt(LocalDateTime.now());
        userAccountsRepository.save(user);

        UserContextDTO userContextDTO = new UserContextDTO();
        userContextDTO.setName(user.getName());
        userContextDTO.setOwnerId(user.getOwnerId());
        userContextDTO.setOwnerType(user.getOwnerType());
        userContextDTO.setToken(token);
        userContextDTO.setPlatformType(envService.getPlatformType());
        userContextDTO.setPlatformNodeId(envService.getPlatformNodeId());

        // fill project id and resource codes
        if (UserOwnerTypeEnum.EDGE.equals(user.getOwnerType())) {
            List<ProjectNodeDO> byNodeId = projectNodeRepository.findByNodeId(user.getOwnerId());
            Set<String> projectIds = byNodeId.stream().map(t -> t.getUpk().getProjectId()).collect(Collectors.toSet());
            userContextDTO.setProjectIds(projectIds);

            Set<String> resourceCodeSet = resourcesBizService.queryResourceCodeByUsername(user.getOwnerType().toPermissionUserType(), ResourceTypeEnum.API, user.getName());
            userContextDTO.setApiResources(resourceCodeSet);
        }

        userContextDTO.setDeployMode(deployMode);
        userContextDTO.setEndRole(resolveEndRole(endRole));
        InstDO instDO = instRepository.findByInstId(user.getOwnerId());
        if (Objects.nonNull(instDO)) {
            userContextDTO.setOwnerName(instDO.getName());
        } else {
            NodeDO nodeDO = nodeRepository.findByNodeId(user.getOwnerId());
            if (Objects.nonNull(nodeDO)) {
                userContextDTO.setOwnerName(nodeDO.getName());
            }
        }
        TokensDO tokensDO = TokensDO.builder().name(user.getName()).token(token).gmtToken(LocalDateTime.now()).sessionData(userContextDTO.toJsonStr()).build();
        userTokensRepository.saveAndFlush(tokensDO);
        UserContext.setBaseUser(userContextDTO);
        return userContextDTO;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void logout(String name, String token) {
        userTokensRepository.deleteByNameAndToken(name, token);
    }


    /**
     * account lock check
     *
     * @param userName
     */

    private AccountsDO accountLockedCheck(String userName, String passwordHash) {

        LocalDateTime currentTime = LocalDateTime.now();
        //current user is need lock
        AccountsDO user = userService.queryUserByName(userName);
        if (ObjectUtils.isEmpty(user)) {
            Cache cache = cacheManager.getCache(CacheConstants.USER_LOCK_CACHE);
            HashMap<String, Integer> lockInfo = cache.get(userName, HashMap.class);
            int failedAttempts = 0;
            if (lockInfo != null) {
                failedAttempts = lockInfo.get("failedAttempts");
                if (failedAttempts >= maxAttempts) {
                    throw SecretpadException.of(AuthErrorCode.USER_IS_LOCKED, String.valueOf(lockTimeMinutes));
                }
            } else {
                lockInfo = new HashMap<>();
            }
            lockInfo.put("failedAttempts", ++failedAttempts);
            cache.put(userName, lockInfo);
            throw SecretpadException.of(AuthErrorCode.USER_PASSWORD_ERROR, String.valueOf(maxAttempts - --failedAttempts));
        }
        if (!adminName.equalsIgnoreCase(user.getName())
                && !"ENABLED".equalsIgnoreCase(user.getAccountStatus())) {
            throw SecretpadException.of(AuthErrorCode.AUTH_FAILED, "account is disabled");
        }

        //checkPassword success
        if (user.getPasswordHash().equals(passwordHash)) {
            //lock invalid
            user.setLockedInvalidTime(null);
            user.setFailedAttempts(null);
            userAccountsRepository.save(user);
            return user;
        }

        user.setFailedAttempts(Objects.isNull(user.getFailedAttempts()) ? 1 : user.getFailedAttempts() + 1);
        if (user.getFailedAttempts() >= maxAttempts) {
            user.setLockedInvalidTime(currentTime.plusMinutes(lockTimeMinutes));
            userService.userLock(user);
            throw SecretpadException.of(AuthErrorCode.USER_IS_LOCKED, String.valueOf(lockTimeMinutes));
        }
        userService.userLock(user);
        throw SecretpadException.of(AuthErrorCode.USER_PASSWORD_ERROR, String.valueOf(maxAttempts - user.getFailedAttempts()));
    }
}
