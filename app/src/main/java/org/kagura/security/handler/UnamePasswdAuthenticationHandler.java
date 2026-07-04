package org.kagura.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.model.UserModel;
import org.kagura.result.Result;
import org.kagura.service.JwtService;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@Component
public class UnamePasswdAuthenticationHandler extends BaseAuthenticationHandler
        implements AuthenticationSuccessHandler {
    private final JwtService jwtService;

    public UnamePasswdAuthenticationHandler(JsonMapper jsonMapper, JwtService jwtService) {
        super(jsonMapper);
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) throws IOException {
        UserModel userModel = (UserModel) authentication.getPrincipal();
        if (Objects.isNull(userModel)) {
            onAuthenticationFailure(
                    request, response,
                    new AuthenticationServiceException("用户名或密码有误")
            );
            return;
        }
        write(response, Result.ok(
                Map.of(
                        "uid", userModel.getUid(),
                        "uname", userModel.getUsername(),
                        "jwt", jwtService.createJwt(userModel)
                )
        ));
    }
}
