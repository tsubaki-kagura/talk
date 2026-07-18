package org.kagura.security.filter;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.kagura.model.UserModel;
import org.kagura.service.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * JWT 认证过滤器，从请求头 {@code Authorization: Bearer <token>} 中解析 JWT 并写入安全上下文。
 * 未携带 Authorization 头的请求直接放行，不进行认证。
 */
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final WebAuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private static final String AUTH_TYPE = "Bearer ";

    private final JwtService jwtService;

    /**
     * 解析请求头中的 JWT，校验通过后将认证信息写入 {@link SecurityContextHolder}
     *
     * @param request 请求
     * @param response 响应
     * @param filterChain 过滤器链
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authorizationHeader)) {
            if (!authorizationHeader.startsWith(AUTH_TYPE)) {
                throw new BadCredentialsException("认证方式有误，请使用 " + AUTH_TYPE + "认证");
            }
            String jwt = authorizationHeader.substring(AUTH_TYPE.length());
            try {
                Map<String, Object> payload = jwtService.parseJwt(jwt);
                setSecurityContext(payload.get("uname").toString(), request);
            } catch (JwtException exception) {
                throw new BadCredentialsException("无效的 jwt，请检查或重新登录以获取新的 jwt");
            }
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 基于用户名构造认证信息并写入安全上下文
     *
     * @param uname 用户名
     * @param request 请求，用于构建认证详情
     */
    private void setSecurityContext(String uname, HttpServletRequest request) {
        UserModel userModel = new UserModel(uname, "******");
        UsernamePasswordAuthenticationToken authenticatedToken =
                UsernamePasswordAuthenticationToken.authenticated(
                        userModel, userModel.getPassword(), userModel.getAuthorities()
                );

        // 标记认证信息，借鉴于 UsernamePasswordAuthenticationFilter
        authenticatedToken.setDetails(authenticationDetailsSource.buildDetails(request));

        // 将用户信息写入安全上下文
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authenticatedToken);
        SecurityContextHolder.setContext(securityContext);
    }
}
