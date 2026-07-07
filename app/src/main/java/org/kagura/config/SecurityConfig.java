package org.kagura.config;

import org.kagura.security.filter.JwtAuthenticationFilter;
import org.kagura.security.filter.UnamePasswdAuthenticationFilter;
import org.kagura.security.handler.ExceptionAuthenticationHandler;
import org.kagura.security.oauth2.GithubAuthenticationHandler;
import org.kagura.security.handler.UnamePasswdAuthenticationHandler;
import org.kagura.security.oauth2.CookieAuthorizationRequestRepository;
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
     * 配置密码编码器
     *
     * @return 使用 BCrypt 加密算法的密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
        return new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
    }

    /**
     * 配置认证管理器，用于注册多个认证提供者
     *
     * @param userService 用户服务，用于组装 DaoAuthenticationProvider
     * @param passwordEncoder 密码编码器，用于组装 DaoAuthenticationProvider
     * @return 认证管理器
     */
    @Bean
    public AuthenticationManager authenticationManager(UserService userService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(daoAuthenticationProvider);
    }

    /**
     * 提取配置文件中的 cors 配置
     *
     * @param origins 允许的主机
     * @param methods 允许的请求方法
     */
    @ConfigurationProperties("spring.security.cors")
    public record CorsProperties(String origins, String methods) {
        public List<String> asOrigins() {
            return Arrays.asList(origins.split(","));
        }

        public List<String> asMethods() {
            return Arrays.asList(methods.split(","));
        }
    }

    /**
     * 配置 cors 配置源
     *
     * @param corsProperties cors 配置
     * @return cors 配置源
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(CorsProperties corsProperties) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(corsProperties.asOrigins());
        corsConfiguration.setAllowedMethods(corsProperties.asMethods());
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    /**
     * 配置 SpringSecurity 过滤器链
     *
     * @param httpSecurity 过滤器链生成器
     * @param exceptionAuthenticationHandler 认证失败/异常处理器
     * @param login 登录 url，用于组装 UnamePasswdAuthenticationFilter
     * @param authenticationManager 认证管理器，用于组装 UnamePasswdAuthenticationFilter
     * @param unamePasswdAuthenticationHandler 用户名密码认证处理器，用于组装 UnamePasswdAuthenticationFilter
     * @param jwtService jwt 服务，用于组装 JwtAuthenticationFilter
     * @param corsConfigurationSource cors 配置源，用于构建 CorsFilter
     * @param cookieAuthorizationRequestRepository cookie 认证存储，用于替换默认的 session 认证存储
     * @param oauth2Redirect oauth2 重定向 url
     * @param githubAuthenticationHandler github 认证处理器
     * @return SpringSecurity 过滤器链
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            ExceptionAuthenticationHandler exceptionAuthenticationHandler,
            @Value("${spring.security.login}") String login,
            AuthenticationManager authenticationManager,
            UnamePasswdAuthenticationHandler unamePasswdAuthenticationHandler,
            JwtService jwtService,
            CorsConfigurationSource corsConfigurationSource,
            CookieAuthorizationRequestRepository cookieAuthorizationRequestRepository,
            @Value("${spring.security.oauth2.redirect}") String oauth2Redirect,
            GithubAuthenticationHandler githubAuthenticationHandler
    ) {
        return httpSecurity

                // 添加自定义用户名密码认证
                .addFilterAt(
                        new UnamePasswdAuthenticationFilter(
                                login,
                                authenticationManager,
                                unamePasswdAuthenticationHandler
                        ),
                        UsernamePasswordAuthenticationFilter.class
                )

                // 添加 jwt 认证
                .addFilterBefore(new JwtAuthenticationFilter(jwtService), AuthorizationFilter.class)

                // 请求拦截配置
                .authorizeHttpRequests(auth -> auth

                        // 放行默认错误处理端点
                        .requestMatchers("/error").permitAll()

                        // 放行 OPTIONS 预检请求
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 拦截其它资源请求
                        .anyRequest().authenticated()
                )

                // oauth2 登录配置
                .oauth2Login(oauth2 -> oauth2

                        // 授权端点配置
                        .authorizationEndpoint(auth -> auth
                                .baseUri(login) // 由于 url 末尾会自动附加 /{registrationId}，所以可以直接复用普通登录的 url
                                .authorizationRequestRepository(cookieAuthorizationRequestRepository)
                        )

                        // 回调端点配置
                        .redirectionEndpoint(redirect -> redirect
                                .baseUri(oauth2Redirect + "/*")
                        )

                        // 授权成功/失败处理器
                        .successHandler(githubAuthenticationHandler)
                        .failureHandler(githubAuthenticationHandler)
                )

                // cors 配置
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // 接口异常访问处理
                .exceptionHandling(security -> security
                        .authenticationEntryPoint(exceptionAuthenticationHandler) // 请求未经认证
                        .accessDeniedHandler(exceptionAuthenticationHandler) // 请求权限不足
                )

                // 不创建 Session
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 关闭 CSRF 防护和“记住我”
                .csrf(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)

                // 关闭请求重定向和 servlet 增强
                .requestCache(AbstractHttpConfigurer::disable)
                .servletApi(AbstractHttpConfigurer::disable)

                // 关闭默认认证
                .httpBasic(AbstractHttpConfigurer::disable)

                // 关闭默认登录/登出
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                // 构建过滤器链
                .build();
    }
}
