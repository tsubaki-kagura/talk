package org.kagura.security.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class CookieAuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private final JsonMapper jsonMapper;

    @Override
    public @Nullable OAuth2AuthorizationRequest loadAuthorizationRequest(@NonNull HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "state");
        if (Objects.isNull(cookie)) {
            return null;
        }
        byte[] bytes = cookie.getValue().getBytes(StandardCharsets.UTF_8);
        byte[] decodedBase64 = Base64.getDecoder().decode(bytes);
        return exchangeAuthorizationRequest(decodedBase64);
    }

    private OAuth2AuthorizationRequest exchangeAuthorizationRequest(byte[] bytes) {
        Map<String, Object> map = jsonMapper.readValue(bytes, new TypeReference<>() {
        });
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
                        jsonMapper.convertValue(map.get("additionalParameters"), new TypeReference<Map<String, Object>>() {
                        })
                )
                .authorizationRequestUri(map.get("authorizationRequestUri").toString())
                .attributes(
                        jsonMapper.convertValue(map.get("attributes"), new TypeReference<Map<String, Object>>() {
                        })
                )
                .build();
    }

    private Cookie buildStateCookie(HttpServletRequest request, String state) {
        Cookie cookie = new Cookie("state", state);
        cookie.setPath(request.getContextPath());
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setMaxAge(300);
        return cookie;
    }

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
        byte[] bytes = jsonMapper.writeValueAsString(authorizationRequest).getBytes(StandardCharsets.UTF_8);
        byte[] encodedBase64 = Base64.getEncoder().encode(bytes);
        Cookie cookie = buildStateCookie(request, new String(encodedBase64, StandardCharsets.UTF_8));
        response.addCookie(cookie);
    }

    @Override
    public @Nullable OAuth2AuthorizationRequest removeAuthorizationRequest(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response
    ) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = loadAuthorizationRequest(request);
        response.addCookie(buildStateCookie(request, null));
        return oAuth2AuthorizationRequest;
    }
}
