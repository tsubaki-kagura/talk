package org.kagura.security.auth.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.domain.request.UnamePasswdLoginRequest;
import org.kagura.security.auth.handler.UnamePasswdHandler;
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

/**
 * 用户名密码认证过滤器
 */
public class UnamePasswdFilter extends AbstractAuthenticationProcessingFilter {
    public UnamePasswdFilter(
            String processesUrl, AuthenticationManager authenticationManager,
            UnamePasswdHandler unamePasswdHandler
    ) {
        super(processesUrl, authenticationManager);
        this.setAuthenticationFailureHandler(unamePasswdHandler);
        this.setAuthenticationSuccessHandler(unamePasswdHandler);
    }

    /**
     * 用户名密码认证逻辑
     *
     * @param request 请求
     * @param response 响应
     * @return 认证成功且待写入安全上下文的认证信息
     * @throws AuthenticationException 认证异常
     */
    @Override // 这一块可以借鉴原生 UsernamePasswordAuthenticationFilter 的实现
    public @NonNull Authentication attemptAuthentication(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response
    ) throws AuthenticationException {
        preAuthenticate(request); // 认证预处理
        Authentication authentication = extractAuthentication(request);
        return getAuthenticationManager().authenticate(authentication);
    }

    /**
     * 认证预处理，判断请求方法和内容类型是否正确
     *
     * @param request 请求
     */
    private void preAuthenticate(HttpServletRequest request) {
        String requestMethod = request.getMethod();
        if (!HttpMethod.POST.matches(requestMethod)) {
            throw new AuthenticationServiceException("暂不支持该种认证方式：" + requestMethod);
        }
        String contentType = request.getContentType();
        if (!MediaType.APPLICATION_JSON_VALUE.equals(contentType)) {
            throw new AuthenticationServiceException("暂不支持该种内容类型：" + contentType);
        }
    }

    /**
     * 从请求中提取出认证信息
     *
     * @param request 请求
     * @return 认证信息
     */
    private Authentication extractAuthentication(HttpServletRequest request) {
        JsonMapper jsonMapper = ((UnamePasswdHandler) getSuccessHandler()).getJsonMapper();
        try (Stream<String> stream = request.getReader().lines()) {
            String requestBodyString = stream.collect(Collectors.joining());
            UnamePasswdLoginRequest loginDTO = jsonMapper.readValue(requestBodyString, UnamePasswdLoginRequest.class);
            if (!StringUtils.hasText(loginDTO.uname()) || !StringUtils.hasText(loginDTO.passwd())) {
                throw new AuthenticationServiceException("请确保用户名和密码均已填写");
            }
            UsernamePasswordAuthenticationToken unauthenticatedToken =
                    UsernamePasswordAuthenticationToken.unauthenticated(loginDTO.uname(), loginDTO.passwd());
            unauthenticatedToken.setDetails(authenticationDetailsSource.buildDetails(request));
            return unauthenticatedToken;
        } catch (IOException exception) {
            throw new AuthenticationServiceException("认证信息异常，请检查认证信息是否有误");
        }
    }
}
