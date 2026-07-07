package org.kagura.service;

import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * jwt 服务，用于生成/解析 jwt
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private final JwtProperties jwtProperties;
    private KeyPair keyPair;

    @PostConstruct
    public void init() {
        keyPair = loadKeyPair(jwtProperties.keypath);
    }

    /**
     * 加载密钥对
     *
     * @param keypath 签发密钥对路径
     * @return 密钥对
     */
    private KeyPair loadKeyPair(String keypath) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get(keypath + ".pem"));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(keypath + "_pub.pem"));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException exception) {
            log.error("未知算法，请检查设置是否有误", exception);
        } catch (IOException exception) {
            log.error("无法读取密钥对...", exception);
        } catch (InvalidKeySpecException exception) {
            log.error("无法加载密钥对...", exception);
        }
        return null;
    }

    /**
     * 提取配置文件中的 jwt 配置
     *
     * @param issuer 签发者
     * @param keypath 签发密钥对路径
     * @param expiration 有效时长
     */
    @ConfigurationProperties("spring.security.jwt")
    public record JwtProperties(String issuer, String keypath, Integer expiration) {
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
                .signWith(keyPair.getPrivate())
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
