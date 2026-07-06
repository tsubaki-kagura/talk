package org.kagura.security.handler.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.result.Result;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;

/**
 * 异常认证处理器
 */
@Component
public class ExceptionAuthenticationHandler extends BaseAuthenticationHandler
        implements AuthenticationEntryPoint, AccessDeniedHandler {

    public ExceptionAuthenticationHandler(JsonMapper jsonMapper) {
        super(jsonMapper);
    }

    /**
     * 未经认证/认证失败处理逻辑
     * @param request 请求
     * @param response 响应
     * @param authException 异常1
     * @throws IOException 异常2
     */
    @Override
    public void commence(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AuthenticationException authException
    ) throws IOException {
        onAuthenticationFailure(request, response, authException);
    }

    /**
     * 权限不足处理逻辑
     * @param request 请求
     * @param response 响应
     * @param accessDeniedException 异常1
     * @throws IOException 异常2
     */
    @Override
    public void handle(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AccessDeniedException accessDeniedException
    ) throws IOException {
        write(response, Result.forbidden(accessDeniedException.getMessage()));
    }
}
