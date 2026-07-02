package org.kagura.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.kagura.result.Result;
import org.kagura.security.filter.UnamePasswdAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final JsonMapper jsonMapper;

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                new DaoAuthenticationProvider(
                        new InMemoryUserDetailsManager(
                                User.builder()
                                        .username("tsubaki")
                                        .password("{noop}041018")
                                        .build()
                        )
                )
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   AuthenticationManager authenticationManager,
                                                   @Value("${spring.web.error.path:/error}") String error,
                                                   @Value("${spring.security.login}") String login
    ) {
        return httpSecurity

                // 添加自定义用户名密码认证
                .addFilterAfter(
                        new UnamePasswdAuthenticationFilter(
                                login,
                                authenticationManager,
                                jsonMapper,
                                this::authenticationHandler,
                                this::authenticationHandler
                        ),
                        ExceptionTranslationFilter.class
                )

                // 拦截配置
                .authorizeHttpRequests(registry -> registry

                        // 放行默认错误处理端点
                        .requestMatchers(error).permitAll()

                        // 放行 OPTIONS 预检请求
                        .requestMatchers(HttpMethod.OPTIONS).permitAll()

                        // 拦截其它资源请求
                        .anyRequest().authenticated()
                )

                // 接口异常访问应对
                .exceptionHandling(security -> security
                        .authenticationEntryPoint(this::authenticationHandler) // 请求未经认证
                        .accessDeniedHandler(this::authenticationHandler)) // 请求权限不足

                // 不创建 Session
                .sessionManagement(security -> security
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // REST API 不需要 CSRF 防护和“记住我”
                .csrf(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)

                // 禁用请求重定向
                .requestCache(AbstractHttpConfigurer::disable)

                // 禁用默认认证
                .httpBasic(AbstractHttpConfigurer::disable)

                // 禁用默认登录/登出
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                // 构建过滤器链
                .build();
    }

    private <T> void authenticationHandler(
            HttpServletRequest request,
            HttpServletResponse response,
            T authenticationOrException
    ) throws IOException {
        response.setCharacterEncoding(StandardCharsets.UTF_8);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Result<?> result = switch (authenticationOrException) {
            case AuthenticationException exception -> Result.unauthorized(exception.getMessage());
            case AccessDeniedException exception -> Result.forbidden(exception.getMessage());
            case Authentication authentication -> Result.ok(authentication.getPrincipal());
            default -> Result.ok("理论上说，这个分支应该永远不会被触发，你怎么触发的？");
        };
        response.getWriter().write(jsonMapper.writeValueAsString(result));
    }
}
