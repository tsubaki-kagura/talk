package org.kagura.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Slf4j
@ExtendWith(SpringExtension.class)
@TestPropertySource("classpath:application.yaml")
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
class JwtServiceTest {

    @Value("${spring.security.jwt.issuer}")
    String issuer;

    @Value("${spring.security.jwt.secret}")
    String secret;

    @Test
    void createJwtTest() {
        log.info("jwt: {}", Jwts.builder()
                .header()
                .add(
                        Map.of("typ", "JWT")
                )
                .and()
                .claims(
                        Map.of(
                                "uid", 199535917,
                                "uname", "tsubaki"
                        )
                )
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3_600_000))
                .signWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(secret)
                        )
                )
                .compact());
    }
}
