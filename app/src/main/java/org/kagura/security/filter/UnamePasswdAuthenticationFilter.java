package org.kagura.security.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.security.handler.UnamePasswdAuthenticationHandler;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UnamePasswdAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final JsonMapper jsonMapper;

    public UnamePasswdAuthenticationFilter(
            String processesUrl,
            AuthenticationManager authenticationManager,
            JsonMapper jsonMapper,
            UnamePasswdAuthenticationHandler authenticationHandler) {
        super(processesUrl, authenticationManager);
        this.jsonMapper = jsonMapper;
        this.setAuthenticationFailureHandler(authenticationHandler);
        this.setAuthenticationSuccessHandler(authenticationHandler);
    }

    @Override // 这一块可以借鉴 UsernamePasswordAuthenticationFilter 的实现
    public @NonNull Authentication attemptAuthentication(
            HttpServletRequest request,
            @NonNull HttpServletResponse response
    ) throws AuthenticationException {
        String requestMethod = request.getMethod();
        if (!HttpMethod.POST.matches(requestMethod)) {
            throw new AuthenticationServiceException("暂不支持该种认证方式：" + requestMethod);
        }
        String contentType = request.getContentType();
        if (!MediaType.APPLICATION_JSON_VALUE.equals(contentType)) {
            throw new AuthenticationServiceException("暂不支持该种内容类型：" + contentType);
        }
        Authentication authentication = extractAuthentication(request);
        return getAuthenticationManager().authenticate(authentication);
    }

    // 简单约束一下请求体的字段
    private record UnamePasswdModel(String uname, String passwd) {
    }

    private Authentication extractAuthentication(HttpServletRequest request) {
        try (Stream<String> stream = request.getReader().lines()) {
            String requestBodyString = stream.collect(Collectors.joining());
            UnamePasswdModel unamePasswdModel = jsonMapper.readValue(requestBodyString, UnamePasswdModel.class);
            if (!StringUtils.hasText(unamePasswdModel.uname) || !StringUtils.hasText(unamePasswdModel.passwd)) {
                throw new AuthenticationServiceException("请确保用户名和密码均已填写");
            }
            UsernamePasswordAuthenticationToken unauthenticatedToken =
                    UsernamePasswordAuthenticationToken.unauthenticated(unamePasswdModel.uname, unamePasswdModel.passwd);
            unauthenticatedToken.setDetails(authenticationDetailsSource.buildDetails(request));
            return unauthenticatedToken;
        } catch (IOException exception) {
            throw new AuthenticationServiceException("认证信息异常，请检查认证信息是否有误");
        }
    }
}
