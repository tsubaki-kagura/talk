package org.kagura.security.handler;

import org.kagura.service.JwtService;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * 用户名密码认证成功/失败处理器，认证成功时生成 JWT 并写入响应
 */
@Component
public class UnamePasswdHandler extends BaseHandler {
    public UnamePasswdHandler(JsonMapper jsonMapper, JwtService jwtService) {
        super(jsonMapper, jwtService);
    }
}
