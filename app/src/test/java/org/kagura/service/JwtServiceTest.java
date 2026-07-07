package org.kagura.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
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

    // 由于配置文件中已经去除了 spring.security.jwt.secret 属性
    // 所以此处随便生成了一个测试密钥，生成命令为：openssl rand -base64 32
    @Value("${spring.security.jwt.secret:C8+RBKd+WmjcI3Nwm3lVKv7oSNfM7darPumHZtcrX7w=}")
    String secret;

    @Test
    void createJwtTest() {
        log.info(
                "jwt: {}",
                Jwts.builder()
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
                        .compact()
        );
    }

    @Test
    void ed25519KeyPairGenerateTest() throws IOException {
        KeyPair keyPair = Jwks.CRV.Ed25519.keyPair().build();
        Files.write(Paths.get("keys/jwt_ed25519.pem"), keyPair.getPrivate().getEncoded());
        Files.write(Paths.get("keys/jwt_ed25519_pub.pem"), keyPair.getPublic().getEncoded());
    }
}
