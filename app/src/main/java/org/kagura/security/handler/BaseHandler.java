package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.kagura.model.UserModel;
import org.kagura.result.Result;
import org.kagura.service.JwtService;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 认证处理器基类，提供认证成功/失败的默认处理逻辑，认证成功后生成 JWT 并将 {@link Result} 以 JSON 格式写入响应
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class BaseHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    protected final JsonMapper jsonMapper;
    protected final JwtService jwtService;

    /**
     * 认证成功处理，生成 JWT 并写入响应
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
     * 认证失败处理，返回未授权响应
     *
     * @param request 请求
     * @param response 响应
     * @param exception 认证异常
     */
    @Override
    public void onAuthenticationFailure(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AuthenticationException exception
    ) {
        write(response, Result.unauthorized(exception.getMessage()));
    }

    /**
     * 从认证信息中提取用户信息
     *
     * @param authentication 认证信息
     * @return 用户信息
     */
    protected UserModel extractUserModel(Authentication authentication) {
        return (UserModel) authentication.getPrincipal();
    }

    /**
     * 将响应结果以 JSON 格式写入响应
     *
     * @param response 响应
     * @param result 响应结果
     * @param <T> 响应数据类型
     */
    protected <T> void write(HttpServletResponse response, Result<T> result) {
        response.setCharacterEncoding(StandardCharsets.UTF_8);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try (PrintWriter writer = response.getWriter()) {
            writer.write(jsonMapper.writeValueAsString(result));
        } catch (IOException exception) {
            throw new RuntimeException("响应数据写入失败...", exception);
        }
    }
}
