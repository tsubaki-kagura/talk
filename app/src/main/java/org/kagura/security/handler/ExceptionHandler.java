package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.result.Result;
import org.kagura.service.JwtService;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * 认证/授权异常处理器，处理未认证请求与权限不足请求
 */
@Component
public class ExceptionHandler extends BaseHandler
        implements AuthenticationEntryPoint, AccessDeniedHandler {
    public ExceptionHandler(JsonMapper jsonMapper, JwtService jwtService) {
        super(jsonMapper, jwtService);
    }

    /**
     * 未认证请求处理逻辑，委托给 {@link #onAuthenticationFailure}
     *
     * @param request 请求
     * @param response 响应
     * @param authException 认证异常
     */
    @Override
    public void commence(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AuthenticationException authException
    ) {
        onAuthenticationFailure(request, response, authException);
    }

    /**
     * 权限不足处理逻辑
     *
     * @param request 请求
     * @param response 响应
     * @param accessDeniedException 权限不足异常
     */
    @Override
    public void handle(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AccessDeniedException accessDeniedException
    ) {
        write(response, Result.forbidden(accessDeniedException.getMessage()));
    }
}
