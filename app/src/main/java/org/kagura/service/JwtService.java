package org.kagura.service;

import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.kagura.util.KeyPairUtil;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * jwt 服务，用于生成/解析 jwt
 */
@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProperties jwtProperties;
    private KeyPair keyPair;

    @PostConstruct
    public void initKeyPair() {
        keyPair = KeyPairUtil.loadEd25519KeyPair(jwtProperties.keypair);
    }

    /**
     * 提取配置文件中的 jwt 配置
     *
     * @param issuer 签发者
     * @param keypair 签发密钥对
     * @param expiration 有效时长
     */
    @ConfigurationProperties("spring.security.jwt")
    public record JwtProperties(String issuer, String keypair, Integer expiration) {
    }

    /**
     * 根据负载创建 jwt
     *
     * @param payload 负载
     * @return jwt
     */
    public String createJwt(Map<String, Object> payload) {
        long currentTimeMillis = System.currentTimeMillis();
        return Jwts.builder()
                .header()
                .add("typ", "JWT") // 添加默认头部
                .and()
                .claims(payload)
                .id(UUID.randomUUID().toString())
                .issuer(jwtProperties.issuer)
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(currentTimeMillis + jwtProperties.expiration * 1000L))
                .signWith(keyPair.getPrivate(), Jwts.SIG.EdDSA)
                .compact();
    }

    /**
     * 解析 jwt
     *
     * @param jwt jwt
     * @return jwt 负载
     */
    public Map<String, Object> parseJwt(String jwt) {
        return Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}
