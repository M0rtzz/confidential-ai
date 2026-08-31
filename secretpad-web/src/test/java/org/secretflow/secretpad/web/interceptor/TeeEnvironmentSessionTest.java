package org.secretflow.secretpad.web.interceptor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.common.util.UserContext;
import org.secretflow.secretpad.persistence.entity.TokensDO;
import org.secretflow.secretpad.persistence.repository.ProjectNodeRepository;
import org.secretflow.secretpad.persistence.repository.UserTokensRepository;
import org.secretflow.secretpad.service.EnvService;
import org.secretflow.secretpad.service.SysResourcesBizService;
import org.secretflow.secretpad.web.controller.TeeEnvironmentController;
import org.secretflow.secretpad.web.service.tee.TeeEnvironmentService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.method.HandlerMethod;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** 验证新接口不接受关闭鉴权、内部节点头或过期会话。 */
class TeeEnvironmentSessionTest {
    @AfterEach void clearContext() { UserContext.remove(); }

    private LoginInterceptor interceptor(UserTokensRepository tokens) {
        var interceptor = new LoginInterceptor(tokens, mock(EnvService.class),
                mock(SysResourcesBizService.class), mock(ProjectNodeRepository.class));
        ReflectionTestUtils.setField(interceptor, "enable", false);
        ReflectionTestUtils.setField(interceptor, "innerHttpPort", 9001);
        var paths = new InnerPortPathConfig();
        ReflectionTestUtils.setField(paths, "path", java.util.List.of());
        ReflectionTestUtils.setField(interceptor, "innerPortPathConfig", paths);
        return interceptor;
    }

    private HandlerMethod handler() throws Exception {
        return new HandlerMethod(new TeeEnvironmentController(mock(TeeEnvironmentService.class)), "environment");
    }

    @Test void disabledAuthenticationCannotBypassSession() throws Exception {
        var tokens = mock(UserTokensRepository.class);
        when(tokens.findByToken(anyString())).thenReturn(Optional.empty());
        var request = new MockHttpServletRequest("GET", "/api/v1alpha1/tee/environment");
        request.setLocalPort(8080);
        var response = new MockHttpServletResponse();
        assertFalse(interceptor(tokens).preHandle(request, response, handler()));
        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains("tee-contract/1.0"));
        assertNull(UserContext.getUserOrNotExist());
    }

    @Test void internalNodeHeaderIsNotAUserSession() throws Exception {
        var request = new MockHttpServletRequest("GET", "/api/v1alpha1/tee/environment");
        request.setLocalPort(9001);
        request.addHeader("kuscia-origin-source", "dev-tee-a-client-1");
        var response = new MockHttpServletResponse();
        assertFalse(interceptor(mock(UserTokensRepository.class)).preHandle(request, response, handler()));
        assertEquals(403, response.getStatus());
    }

    @Test void validSessionAcceptedAndExpiredSessionRejected() throws Exception {
        for (boolean expired : new boolean[]{false, true}) {
            var tokens = mock(UserTokensRepository.class);
            var session = TokensDO.builder().name("devadmin").token("synthetic-session")
                    .gmtToken(LocalDateTime.now().minusDays(expired ? 2 : 0))
                    .sessionData("{\"name\":\"devadmin\",\"ownerId\":\"dev-tee-a-center\"}").build();
            when(tokens.findByToken("synthetic-session")).thenReturn(Optional.of(session));
            var request = new MockHttpServletRequest("GET", "/api/v1alpha1/tee/environment");
            request.setLocalPort(8080);
            request.addHeader("User-Token", "synthetic-session");
            var response = new MockHttpServletResponse();
            assertEquals(!expired, interceptor(tokens).preHandle(request, response, handler()));
            if (expired) assertEquals(401, response.getStatus());
            UserContext.remove();
        }
    }
}
