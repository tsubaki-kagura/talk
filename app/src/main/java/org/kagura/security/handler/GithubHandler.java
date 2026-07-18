package org.kagura.security.handler;

import org.kagura.model.UserModel;
import org.kagura.service.JwtService;
import org.kagura.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * GitHub OAuth2 认证成功/失败处理器，认证成功时通过 {@link UserService#loadUserByProvider} 加载或创建用户并生成 JWT
 */
@Component
public class GithubHandler extends BaseHandler {
    private final UserService userService;

    public GithubHandler(JsonMapper jsonMapper, JwtService jwtService, UserService userService) {
        super(jsonMapper, jwtService);
        this.userService = userService;
    }

    /**
     * 从 OAuth2 认证信息中提取用户，用户不存在时自动创建
     *
     * @param authentication OAuth2 认证信息
     * @return 用户模型
     */
    @Override
    protected UserModel extractUserModel(Authentication authentication) {
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) authentication;
        return userService.loadUserByProvider(
                authenticationToken.getAuthorizedClientRegistrationId(),
                authenticationToken.getName()
        );
    }
}
