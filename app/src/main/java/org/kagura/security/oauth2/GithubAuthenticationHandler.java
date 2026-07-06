package org.kagura.security.oauth2;

import org.kagura.security.handler.auth.BaseAuthenticationHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

@Component
public class GithubAuthenticationHandler extends BaseAuthenticationHandler {
    public GithubAuthenticationHandler(JsonMapper jsonMapper) {
        super(jsonMapper);
    }
}
