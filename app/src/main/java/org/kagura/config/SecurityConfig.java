package org.kagura.config;

import org.kagura.security.AuthenticationHandler;
import org.kagura.security.filter.JwtAuthenticationFilter;
import org.kagura.security.filter.UnamePasswdAuthenticationFilter;
import org.kagura.service.JwtService;
import org.kagura.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserService userService, PasswordEncoder passwordEncoder
    ) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(daoAuthenticationProvider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            AuthenticationManager authenticationManager,
            @Value("${spring.security.login}") String login,
            JsonMapper jsonMapper,
            AuthenticationHandler authenticationHandler,
            JwtService jwtService
    ) {
        return httpSecurity

                // 添加 jwt 认证
                .addFilterAfter(
                        new JwtAuthenticationFilter(jwtService),
                        ExceptionTranslationFilter.class
                )

                // 添加自定义用户名密码认证
                .addFilterAfter(
                        new UnamePasswdAuthenticationFilter(
                                login,
                                authenticationManager,
                                jsonMapper,
                                authenticationHandler
                        ),
                        ExceptionTranslationFilter.class
                )

                // 拦截配置
                .authorizeHttpRequests(registry -> registry

                        // 放行默认错误处理端点
                        .requestMatchers("/error").permitAll()

                        // 放行 OPTIONS 预检请求
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 拦截其它资源请求
                        .anyRequest().authenticated()
                )

                // 接口异常访问应对
                .exceptionHandling(security -> security
                        .authenticationEntryPoint(authenticationHandler) // 请求未经认证
                        .accessDeniedHandler(authenticationHandler)) // 请求权限不足

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
}
