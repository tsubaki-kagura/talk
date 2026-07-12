package org.kagura.security.auth.handler;

import org.kagura.model.UserModel;
import org.kagura.service.JwtService;
import org.kagura.service.OAuth2UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * Github 授权认证处理器
 */
@Component
public class GithubHandler extends BaseHandler {
    private final OAuth2UserService oAuth2UserService;

    public GithubHandler(JsonMapper jsonMapper, JwtService jwtService, OAuth2UserService oAuth2UserService) {
        super(jsonMapper, jwtService);
        this.oAuth2UserService = oAuth2UserService;
    }

    @Override
    protected UserModel extractUserModel(Authentication authentication) {
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) authentication;
        return oAuth2UserService.searchUser(
                authenticationToken.getAuthorizedClientRegistrationId(),
                authenticationToken.getName()
        );
    }
}
