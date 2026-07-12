package org.kagura.security.auth.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.model.UserModel;
import org.kagura.result.Result;
import org.kagura.security.BaseWriter;
import org.kagura.service.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

/**
 * 基础认证处理器
 */
public abstract class BaseHandler extends BaseWriter
        implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    protected final JwtService jwtService;

    protected BaseHandler(JsonMapper jsonMapper, JwtService jwtService) {
        super(jsonMapper);
        this.jwtService = jwtService;
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
        // 构建创建 jwt 所需要的负载
        UserModel userModel = extractUserModel(authentication);
        Map<String, Object> payload = userModel.createJwtPayload();

        // 在该负载的基础上添加 jwt 字段，再一并发送给客户端，可有效减少重复构建
        payload.put("jwt", jwtService.createJwt(payload));
        write(response, Result.ok(payload));
    }

    /**
     * 从认证信息中提取出用户信息
     *
     * @param authentication 认证信息
     * @return 用户信息
     */
    protected UserModel extractUserModel(Authentication authentication) {
        return (UserModel) authentication.getPrincipal();
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
