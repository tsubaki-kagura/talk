package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.result.Result;
import org.kagura.security.BaseWriter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

/**
 * 基础认证处理器
 */
public class BaseAuthenticationHandler extends BaseWriter
        implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    protected BaseAuthenticationHandler(JsonMapper jsonMapper) {
        super(jsonMapper);
    }

    /**
     * 认证成功处理逻辑
     *
     * @param request 请求
     * @param response 响应
     * @param authentication 认证信息
     */
    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) {
        write(response, Result.ok(authentication.getPrincipal()));
    }

    /**
     * 认证失败处理逻辑
     *
     * @param request 请求
     * @param response 响应
     * @param exception 认证失败异常
     */
    @Override
    public void onAuthenticationFailure(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AuthenticationException exception
    ) {
        write(response, Result.unauthorized(exception.getMessage()));
    }
}
