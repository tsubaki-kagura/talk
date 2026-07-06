package org.kagura.security.handler.auth;

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

import java.io.IOException;
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
     * 用户名密码认证成功处理逻辑
     * @param request 请求
     * @param response 响应
     * @param authentication 异常1
     * @throws IOException 异常2
     */
    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) throws IOException {
        UserModel userModel = (UserModel) authentication.getPrincipal();
        if (Objects.nonNull(userModel)) {
            write(response, Result.ok(
                    Map.of(
                            "uid", userModel.getUid(),
                            "uname", userModel.getUsername(),
                            "jwt", jwtService.createJwt(userModel)
                    )
            ));
        } else {
            onAuthenticationFailure(
                    request, response,
                    new AuthenticationServiceException("用户名或密码有误")
            );
        }
    }
}
