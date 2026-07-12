package org.kagura.security.auth.handler;

import org.kagura.service.JwtService;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * 用户名密码认证处理器
 */
@Component
public class UnamePasswdHandler extends BaseHandler {
    public UnamePasswdHandler(JsonMapper jsonMapper, JwtService jwtService) {
        super(jsonMapper, jwtService);
    }
}
