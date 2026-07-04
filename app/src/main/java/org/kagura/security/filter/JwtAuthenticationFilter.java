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
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    private static final String AUTH_TYPE = "Bearer ";

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
                Map<String, Object> payload = jwtService.parseJwt(jwt);
                fillSecurityContext(payload.get("uname").toString());
            } catch (JwtException exception) {
                throw new BadCredentialsException("无效的 jwt，请检查或重新登录以获取新的 jwt");
            }
        }
        filterChain.doFilter(request, response);
    }

    private void fillSecurityContext(String uname) {
        Authentication authentication = exchangeAuthentication(uname);
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private Authentication exchangeAuthentication(String uname) {
        UserModel userModel = new UserModel();
        userModel.setUsername(uname);
        UsernamePasswordAuthenticationToken authenticatedToken =
                UsernamePasswordAuthenticationToken.authenticated(
                        userModel, userModel.getPassword(), userModel.getAuthorities()
                );
        authenticatedToken.setDetails(null);
        return authenticatedToken;
    }
}
