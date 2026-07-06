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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * jwt 认证过滤器
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final WebAuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private static final String AUTH_TYPE = "Bearer ";

    private final JwtService jwtService;

    /**
     * jwt 认证逻辑，当且仅当携带请求头 Authorization 时，才会进行 jwt 认证，否则则直接放行，不进行 jwt 认证
     * @param request 请求
     * @param response 响应
     * @param filterChain 过滤器链
     * @throws ServletException 异常1
     * @throws IOException 异常2
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authorizationHeader)) {
            if (!authorizationHeader.startsWith(AUTH_TYPE)) {
                throw new BadCredentialsException("认证方式有误，请使用 " + AUTH_TYPE + "认证");
            }
            String jwt = authorizationHeader.substring(AUTH_TYPE.length());
            try {
                String uname = jwtService.parseJwt(jwt).get("uname").toString();
                Authentication authentication = exchangeAuthentication(uname, request);
                fillSecurityContext(authentication);
            } catch (JwtException exception) {
                throw new BadCredentialsException("无效的 jwt，请检查或重新登录以获取新的 jwt");
            }
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 将提供的认证信息写入安全上下文
     * @param authentication 认证信息
     */
    private void fillSecurityContext(Authentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    /**
     * 使用用户名交换认证信息
     * @param uname 用户名
     * @param request 请求对象，以标记认证信息
     * @return 认证信息
     */
    private Authentication exchangeAuthentication(String uname, HttpServletRequest request) {
        UserModel userModel = new UserModel();
        userModel.setUsername(uname);
        UsernamePasswordAuthenticationToken authenticatedToken =
                UsernamePasswordAuthenticationToken.authenticated(
                        userModel, userModel.getPassword(), userModel.getAuthorities()
                );

        // 标记认证信息，借鉴于 UsernamePasswordAuthenticationFilter
        authenticatedToken.setDetails(authenticationDetailsSource.buildDetails(request));
        return authenticatedToken;
    }
}
