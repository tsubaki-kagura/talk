package org.kagura.config;

import org.kagura.security.auth.repository.CookieRequestRepository;
import org.kagura.service.JwtService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({
        JwtService.JwtProperties.class,
        SecurityConfig.CorsProperties.class,
        CookieRequestRepository.CookieProperties.class
})
public class PropertyBindingConfig {
}
