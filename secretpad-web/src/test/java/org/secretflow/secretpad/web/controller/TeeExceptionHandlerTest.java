package org.secretflow.secretpad.web.controller;

import org.junit.jupiter.api.Test;
import org.secretflow.secretpad.web.service.tee.TeeContract;
import org.secretflow.secretpad.web.service.tee.TeeException;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TeeExceptionHandlerTest {

    @Test
    void adviceCoversEveryTeeApiController() {
        RestControllerAdvice advice = TeeExceptionHandler.class.getAnnotation(RestControllerAdvice.class);
        assertArrayEquals(new Class<?>[]{TeeApi.class}, advice.assignableTypes());
    }

    @Test
    void policyFailureUsesFrozenContractResponse() {
        var response = new TeeExceptionHandler().handle(
                TeeException.of(TeeContract.Error.REAL_MODE_UNAVAILABLE, "not exposed"));

        assertEquals(200, response.getStatusCode().value());
        Map<?, ?> body = response.getBody();
        Map<?, ?> status = (Map<?, ?>) body.get("status");
        Map<?, ?> data = (Map<?, ?>) body.get("data");
        assertEquals(49011, status.get("code"));
        assertEquals("REAL_MODE_UNAVAILABLE", data.get("errorCode"));
    }
}
