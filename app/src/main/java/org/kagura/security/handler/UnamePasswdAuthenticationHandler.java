package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.model.UserModel;
import org.kagura.result.Result;
import org.kagura.service.JwtService;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 用户名密码认证处理器
 */
@Component
public class UnamePasswdAuthenticationHandler extends BaseAuthenticationHandler {
    private final JwtService jwtService;

    public UnamePasswdAuthenticationHandler(JsonMapper jsonMapper, JwtService jwtService) {
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
        UserModel userModel = (UserModel) authentication.getPrincipal();
        if (Objects.isNull(userModel)) {
            onAuthenticationFailure(
                    request, response,
                    new AuthenticationServiceException("用户名或密码有误")
            );
            return;
        }

        // 构建创建 jwt 所需要的负载
        Map<String, Object> payload = Map.of(
                "uid", userModel.getUid(),
                "uname", userModel.getUsername()
        );

        // 在该负载的基础上添加 jwt 字段，再一并发送给客户端，可有效减少重复构建
        HashMap<String, Object> data = new HashMap<>(payload);
        data.put("jwt", jwtService.createJwt(payload));
        write(response, Result.ok(data));
    }
}
