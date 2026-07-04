package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.result.Result;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;

@Component
public class ExceptionAuthenticationHandler extends BaseAuthenticationHandler
        implements AccessDeniedHandler {

    public ExceptionAuthenticationHandler(JsonMapper jsonMapper) {
        super(jsonMapper);
    }

    @Override
    public void handle(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AccessDeniedException accessDeniedException
    ) throws IOException {
        write(response, Result.forbidden(accessDeniedException.getMessage()));
    }
}
