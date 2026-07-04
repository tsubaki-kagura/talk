package org.kagura.config;

import org.kagura.service.JwtService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JwtService.JwtProperties.class)
public class PropertyBindingConfig {
}
