package org.kagura.config;

import org.kagura.security.oauth2.repository.CookieOAuth2AuthorizationRequestRepository;
import org.kagura.service.JwtService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({
        JwtService.JwtProperties.class,
        SecurityConfig.CorsProperties.class,
        CookieOAuth2AuthorizationRequestRepository.CookieProperties.class
})
public class PropertyBindingConfig {
}
