package org.kagura.util;

import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class KeyPairUtil {
    private static final String KEYPAIR_STORE_PATH = "keys";
    private static final String PRIVATE_KEY_POSTFIX = ".private.jwk";
    private static final String PUBLIC_KEY_POSTFIX = ".public.jwk";
    private static final String ED2519 = "_ed25519";

    /**
     * 生成 Ed25519 密钥对
     *
     * @param keypair 密钥对名称
     */
    public static void generateEd25519KeyPair(String keypair) {

        // 生成 ed25519 密钥对，并分别将私钥和公钥转换为 Jwk 对象
        KeyPair keyPair = Jwks.CRV.Ed25519.keyPair().build();
        PrivateJwk<PrivateKey, PublicKey, ?> privateJwk = Jwks.builder().key(keyPair.getPrivate()).build();
        PublicJwk<PublicKey> publicJwk = Jwks.builder().key(keyPair.getPublic()).build();

        try {
            String keypairPath = String.join("/", KEYPAIR_STORE_PATH, keypair);

            // 将私钥保存至指定路径
            String privateKeyPath = keypairPath + ED2519 + PRIVATE_KEY_POSTFIX;
            Files.writeString(Paths.get(privateKeyPath), Jwks.UNSAFE_JSON(privateJwk));

            // 将公钥保存至指定路径
            String publicKeyPath = keypairPath + ED2519 + PUBLIC_KEY_POSTFIX;
            Files.writeString(Paths.get(publicKeyPath), Jwks.json(publicJwk));
        } catch (IOException exception) {
            throw new RuntimeException("ed25519 密钥对 " + keypair + " 保存失败...", exception);
        }
    }

    /**
     * 加载 Ed25519 密钥对
     *
     * @param keypair 密钥对名称
     * @return Ed25519 密钥对
     */
    public static KeyPair loadEd25519KeyPair(String keypair) {
        try {
            String keypairPath = String.join("/", KEYPAIR_STORE_PATH, keypair);
            String privateKeyPath = keypairPath + ED2519 + PRIVATE_KEY_POSTFIX;
            String publicKeyPath = keypairPath + ED2519 + PUBLIC_KEY_POSTFIX;

            // 加载私钥
            BufferedReader privateKeyReader = Files.newBufferedReader(Paths.get(privateKeyPath));
            PrivateKey privateKey = (PrivateKey) Jwks.parser().build().parse(privateKeyReader).toKey();

            // 加载公钥
            BufferedReader publicKeyReader = Files.newBufferedReader(Paths.get(publicKeyPath));
            PublicKey publicKey = (PublicKey) Jwks.parser().build().parse(publicKeyReader).toKey();

            return new KeyPair(publicKey, privateKey);
        } catch (IOException exception) {
            throw new RuntimeException("ed25519 密钥对" + keypair + "加载失败...", exception);
        }
    }
}
