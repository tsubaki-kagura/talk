package org.kagura.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.kagura.model.UserModel;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

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

    /**
     * 提取配置文件中的 jwt 配置
     * @param issuer 签发者
     * @param secret 密钥
     * @param expiration 有效时长
     */
    @ConfigurationProperties("spring.security.jwt")
    public record JwtProperties(String issuer, String secret, Integer expiration) {
    }

    /**
     * 根据用户信息创建 jwt
     * @param userModel 用户信息
     * @return jwt
     */
    public String createJwt(UserModel userModel) {
        long currentTimeMillis = System.currentTimeMillis();
        return Jwts.builder()
                .header()
                .add("typ", "JWT") // 添加默认头部
                .and()
                .claims(
                        Map.of(
                                "uid", userModel.getUid(),
                                "uname", userModel.getUsername()
                        )
                )
                .id(UUID.randomUUID().toString())
                .issuer(jwtProperties.issuer)
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(currentTimeMillis + jwtProperties.expiration * 1000L))
                .signWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(jwtProperties.secret)
                        )
                )
                .compact();
    }

    /**
     * 解析 jwt
     * @param jwt jwt
     * @return jwt 负载
     */
    public Map<String, Object> parseJwt(String jwt) {
        return Jwts.parser()
                .verifyWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(jwtProperties.secret)
                        )
                )
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}
