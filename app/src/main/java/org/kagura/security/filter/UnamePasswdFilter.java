package org.kagura.security.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.kagura.security.handler.UnamePasswdHandler;
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
 * 用户名密码认证过滤器，拦截指定登录路径的 POST 请求，从 JSON 请求体中提取用户名密码进行认证
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
     * 校验请求方法与 Content-Type，从请求体中提取认证信息后交由 {@link AuthenticationManager} 认证
     *
     * @param request 请求
     * @param response 响应
     * @return 认证成功后的认证信息
     * @throws AuthenticationException 认证异常
     */
    @Override
    public @NonNull Authentication attemptAuthentication(
            @NonNull HttpServletRequest request, @NonNull HttpServletResponse response
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

    /**
     * 用户名密码认证请求体模型
     *
     * @param uname 用户名
     * @param passwd 密码
     */
    private record UnamePasswdModel(String uname, String passwd) {
    }

    /**
     * 从 JSON 请求体中解析用户名密码，构建未认证的 {@link UsernamePasswordAuthenticationToken}
     *
     * @param request 请求
     * @return 未认证的认证信息
     */
    private Authentication extractAuthentication(HttpServletRequest request) {
        JsonMapper jsonMapper = ((UnamePasswdHandler) getSuccessHandler()).getJsonMapper();
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
