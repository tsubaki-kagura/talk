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
 * JWT 服务，使用 EdDSA 算法对 JWT 进行签名和验证
 */
@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProperties jwtProperties;
    private KeyPair keyPair;

    /**
     * 初始化 Ed25519 密钥对
     */
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
     * 使用 EdDSA 私钥签名生成 JWT
     *
     * @param payload 负载
     * @return JWT 字符串
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
     * 使用 EdDSA 公钥验证并解析 JWT
     *
     * @param jwt JWT 字符串
     * @return JWT 负载
     */
    public Map<String, Object> parseJwt(String jwt) {
        return Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}
