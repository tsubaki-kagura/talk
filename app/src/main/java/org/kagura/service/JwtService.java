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

@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProperties jwtProperties;

    @ConfigurationProperties("spring.security.jwt")
    public record JwtProperties(String issuer, String secret, Integer expiration) {
    }

    public String createJwt(UserModel userModel) {
        long currentTimeMillis = System.currentTimeMillis();
        return Jwts.builder()
                .header()
                .add("typ", "JWT")
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
