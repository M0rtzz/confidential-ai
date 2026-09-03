/*
 * Copyright 2026 Ant Group Co., Ltd.
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

package org.secretflow.secretpad.service.test;

import org.secretflow.secretpad.service.impl.AuthServiceImpl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 端身份解析改为「声明列表首项」后的单测。
 *
 * @author claude
 * @date 2026/9/3
 */
@ExtendWith(MockitoExtension.class)
public class AuthServiceImplResolveEndRoleTest {

    @InjectMocks
    private AuthServiceImpl authService;

    @Test
    public void testResolveEndRole_singleEndInstance_withoutParam_resolvesToItself() {
        ReflectionTestUtils.setField(authService, "allowedEndRoles", "CLIENT");
        String resolved = ReflectionTestUtils.invokeMethod(authService, "resolveEndRole", (Object) null);
        Assertions.assertEquals("CLIENT", resolved);
    }

    @Test
    public void testResolveEndRole_multiEndInstance_withoutParam_resolvesToFirstDeclared() {
        ReflectionTestUtils.setField(authService, "allowedEndRoles", "CENTER,CLIENT");
        String resolved = ReflectionTestUtils.invokeMethod(authService, "resolveEndRole", (Object) null);
        Assertions.assertEquals("CENTER", resolved);
    }
}
