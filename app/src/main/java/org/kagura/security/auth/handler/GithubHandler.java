package org.kagura.security.auth.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.kagura.result.Result;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
@Component
public class GithubHandler extends BaseHandler {

    public GithubHandler(JsonMapper jsonMapper) {
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
        write(response, Result.ok((OAuth2AuthenticationToken) authentication));
    }
}
