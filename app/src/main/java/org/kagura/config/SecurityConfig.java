package org.kagura.config;

import org.kagura.security.auth.filter.JwtFilter;
import org.kagura.security.auth.filter.UnamePasswdFilter;
import org.kagura.security.auth.handler.ExceptionHandler;
import org.kagura.security.auth.handler.GithubHandler;
import org.kagura.security.auth.handler.UnamePasswdHandler;
import org.kagura.security.auth.repository.CookieRequestRepository;
import org.kagura.service.JwtService;
import org.kagura.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 构建密码编码器
     *
     * @return 使用 BCrypt 加密算法的密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
    }

    /**
     * 构建全局认证管理器
     *
     * @param userService 用户服务
     * @param passwordEncoder 密码编码器
     */
    @Bean
    public AuthenticationManager authenticationManager(UserService userService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(List.of(daoAuthenticationProvider));
    }

    /**
     * 构建 SpringSecurity 过滤器链
     *
     * @param httpSecurity 过滤器链生成器
     * @param exceptionHandler 认证失败/异常处理器
     * @param login 登录 url，用于组装 UnamePasswdAuthenticationFilter
     * @param authenticationManager 全局认证管理器
     * @param unamePasswdHandler 用户名密码认证处理器，用于组装 UnamePasswdAuthenticationFilter
     * @param jwtService jwt 服务，用于组装 JwtAuthenticationFilter
     * @param corsConfigurationSource cors 配置源，用于构建 CorsFilter
     * @param cookieRequestRepository cookie 认证存储，用于替换默认的 session 认证存储
     * @param oauth2Redirect oauth2 重定向 url
     * @param githubAuthenticationHandler github 认证处理器
     * @return SpringSecurity 过滤器链
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            ExceptionHandler exceptionHandler,
            @Value("${spring.security.login}") String login,
            AuthenticationManager authenticationManager,
            UnamePasswdHandler unamePasswdHandler,
            JwtService jwtService,
            CorsConfigurationSource corsConfigurationSource,
            CookieRequestRepository cookieRequestRepository,
            @Value("${spring.security.oauth2.redirect}") String oauth2Redirect,
            GithubHandler githubAuthenticationHandler
    ) {
        return httpSecurity

                // 添加自定义用户名密码认证
                .addFilterAt(
                        new UnamePasswdFilter(login, authenticationManager, unamePasswdHandler),
                        UsernamePasswordAuthenticationFilter.class
                )

                // 添加 jwt 认证
                .addFilterBefore(new JwtFilter(jwtService), AuthorizationFilter.class)

                // 请求认证配置
                .authorizeHttpRequests(auth -> auth

                        // 放行默认错误处理端点
                        .requestMatchers("/error").permitAll()

                        // 放行 OPTIONS 预检请求
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 拦截除此以外的所有请求
                        .anyRequest().authenticated()
                )

                // oauth2 登录配置
                .oauth2Login(oauth2 -> oauth2

                        // 授权端点配置
                        .authorizationEndpoint(auth -> auth
                                .baseUri(login) // 由于会自动为 url 附加 /{registrationId}，所以可以直接复用普通登录的 url
                                .authorizationRequestRepository(cookieRequestRepository)
                        )

                        // 回调端点配置
                        .redirectionEndpoint(redirect -> redirect
                                .baseUri(oauth2Redirect + "/*")
                        )

                        // 授权成功/失败处理器
                        .successHandler(githubAuthenticationHandler)
                        .failureHandler(githubAuthenticationHandler)
                )

                // 接口异常访问处理
                .exceptionHandling(security -> security
                        .authenticationEntryPoint(exceptionHandler) // 请求未经认证
                        .accessDeniedHandler(exceptionHandler) // 请求权限不足
                )

                // 关闭 session
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 关闭 csrf 防护和“记住我”
                .csrf(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)

                // 关闭匿名访问
                .anonymous(AbstractHttpConfigurer::disable)

                // 关闭请求重定向和 servlet 增强
                .requestCache(AbstractHttpConfigurer::disable)
                .servletApi(AbstractHttpConfigurer::disable)

                // 关闭默认认证
                .httpBasic(AbstractHttpConfigurer::disable)

                // 关闭默认登录/登出
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                // cors 配置
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // 构建过滤器链
                .build();
    }

    /**
     * 提取配置文件中的 cors 配置
     *
     * @param origins 允许的主机
     * @param methods 允许的请求方法
     */
    @ConfigurationProperties("spring.security.cors")
    public record CorsProperties(String origins, String methods) {
        public List<String> split(String string) {
            return Arrays.asList(string.split(","));
        }
    }

    /**
     * 构建 cors 配置源
     *
     * @param corsProperties cors 配置
     * @return cors 配置源
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(CorsProperties corsProperties) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        // cors 具体配置
        corsConfiguration.setAllowedOrigins(corsProperties.split(corsProperties.origins));
        corsConfiguration.setAllowedMethods(corsProperties.split(corsProperties.methods));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}
