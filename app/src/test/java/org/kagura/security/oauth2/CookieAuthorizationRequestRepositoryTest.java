package org.kagura.security.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

@Slf4j
@JsonTest
class CookieAuthorizationRequestRepositoryTest {

    @Autowired
    JsonMapper jsonMapper;

    @Test
    void loadAuthorizationRequestTest() throws IOException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("oauth2/github.json")) {

            // 将 json 字符串反序列化为一个 Map 集合
            Map<String, Object> map = jsonMapper.readValue(inputStream, new TypeReference<>() {
            });

            // 由于 OAuth2AuthorizationRequest 无法直接被反序列化
            // 所以只能从 Map 集合中提取出相关信息，然后手动构建 OAuth2AuthorizationRequest 实例
            OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(map.get("authorizationUri").toString())
                    .clientId(map.get("clientId").toString())
                    .redirectUri(map.get("redirectUri").toString())
                    .scopes(
                            jsonMapper.convertValue(map.get("scopes"), new TypeReference<>() {
                            })
                    )
                    .state(map.get("state").toString())
                    .additionalParameters(
                            jsonMapper.convertValue(map.get("additionalParameters"), new TypeReference<Map<String, Object>>() {
                            })
                    )
                    .authorizationRequestUri(map.get("authorizationRequestUri").toString())
                    .attributes(
                            jsonMapper.convertValue(map.get("attributes"), new TypeReference<Map<String, Object>>() {
                            })
                    )
                    .build();
            // 由于 OAuth2AuthorizationRequest 实例的 toString 方法没有被重写，无法查看其内部的详细信息
            // 所以这里通过 json 序列化，查看 OAuth2AuthorizationRequest 实例内部的详细信息
            log.debug("OAuth2 Authorization: {}", jsonMapper.writeValueAsString(authorizationRequest));
        }
    }
}
