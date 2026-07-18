package org.kagura.security.repository;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * 基于 Cookie 的 OAuth2 授权请求存储，将序列化后的授权请求 Base64 编码存入 Cookie，替代默认的 Session 存储
 */
@Component
@RequiredArgsConstructor
public class CookieRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private final JsonMapper jsonMapper;
    private final CookieProperties cookieProperties;

    /**
     * 提取配置文件中的 cookie 配置
     *
     * @param name cookie 名称
     * @param age cookie 有效时长
     */
    @ConfigurationProperties("spring.security.oauth2.cookie")
    public record CookieProperties(String name, Integer age) {
    }

    /**
     * 从 Cookie 中加载已保存的授权请求，Base64 解码后反序列化为 {@link OAuth2AuthorizationRequest}
     *
     * @param request 请求
     * @return 授权请求，未找到时返回 {@code null}
     */
    @Override
    public @Nullable OAuth2AuthorizationRequest loadAuthorizationRequest(@NonNull HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, cookieProperties.name);
        if (Objects.isNull(cookie) || !StringUtils.hasText(cookie.getValue())) {

            // 由于 HttpSessionOAuth2AuthorizationRequestRepository 中是直接返回的 null，所以这里也返回 null
            return null;
        }

        // 将该 base64 字符串解码为普通字符串
        byte[] bytes = cookie.getValue().getBytes(StandardCharsets.UTF_8);
        byte[] decodedBytes = Base64.getDecoder().decode(bytes);

        // 然后 json 反序列化为 OAuth2AuthorizationRequest 实例
        return exchangeAuthorizationRequest(decodedBytes);
    }

    /**
     * 将字节流反序列化为 OAuth2AuthorizationRequest 实例
     *
     * @param bytes 字节流
     * @return OAuth2AuthorizationRequest 实例
     */
    private OAuth2AuthorizationRequest exchangeAuthorizationRequest(byte[] bytes) {
        try {
            Map<String, Object> map = jsonMapper.readValue(bytes, new TypeReference<>() {
            });

            // 由于 OAuth2AuthorizationRequest 实例未提供无参构造，无法直接反序列化，所以只能一点一点的把数据塞进去
            return OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(map.get("authorizationUri").toString())
                    .clientId(map.get("clientId").toString())
                    .redirectUri(map.get("redirectUri").toString())
                    .scopes(
                            jsonMapper.convertValue(map.get("scopes"), new TypeReference<>() {
                            })
                    )
                    .state(map.get("state").toString())
                    .additionalParameters(
                            jsonMapper.convertValue(
                                    map.get("additionalParameters"),
                                    new TypeReference<Map<String, Object>>() {
                                    }
                            )
                    )
                    .authorizationRequestUri(map.get("authorizationRequestUri").toString())
                    .attributes(
                            jsonMapper.convertValue(map.get("attributes"), new TypeReference<Map<String, Object>>() {
                            })
                    )
                    .build();
        } catch (JwtException exception) {
            return null;
        }
    }

    /**
     * 保存授权请求，序列化为 JSON 后 Base64 编码存入 Cookie
     *
     * @param authorizationRequest 授权请求，为 {@code null} 时移除 Cookie
     * @param request 请求
     * @param response 响应
     */
    @Override
    public void saveAuthorizationRequest(
            @Nullable OAuth2AuthorizationRequest authorizationRequest,
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response
    ) {
        if (Objects.isNull(authorizationRequest)) {
            removeAuthorizationRequest(request, response);
            return;
        }

        // json 序列化认证信息，并将其编码为 base64 字符串
        byte[] bytes = jsonMapper.writeValueAsBytes(authorizationRequest);
        byte[] encodedBytes = Base64.getEncoder().encode(bytes);
        String state = new String(encodedBytes, StandardCharsets.UTF_8);

        // 将该 base64 字符串作为 cookie 发送给客户端保存
        String cookie = buildStateCookie(request, state, cookieProperties.age);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie);
    }

    /**
     * 构建存放 state 参数的 cookie
     *
     * @param request 请求，用于提取基路径和是否为安全请求
     * @param state state 参数的值
     * @param age cookie 的存活时间
     * @return cookie 的值
     */
    private String buildStateCookie(HttpServletRequest request, String state, Integer age) {
        return ResponseCookie.from(cookieProperties.name)
                .value(state)
                .path(request.getContextPath())
                .httpOnly(true)
                .secure(request.isSecure())
                .maxAge(age)
                .build()
                .toString();
    }

    /**
     * 移除授权请求，加载后通过设置同名过期 Cookie 清除
     *
     * @param request 请求
     * @param response 响应
     * @return 已移除的授权请求
     */
    @Override
    public @Nullable OAuth2AuthorizationRequest removeAuthorizationRequest(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response
    ) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = loadAuthorizationRequest(request);
        String cookie = buildStateCookie(request, "", 0);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie);
        return oAuth2AuthorizationRequest;
    }
}
