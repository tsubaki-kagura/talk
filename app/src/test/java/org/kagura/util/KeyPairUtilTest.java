package org.kagura.util;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

@Slf4j
class KeyPairUtilTest {

    @Test
    void generateEd25519KeyPairTest() {
        KeyPairUtil.generateEd25519KeyPair("jwt");
        log.info("Ed25519 密钥对生成成功");
    }

    @Test
    void loadEd25519KeyPairTest() {
        KeyPair keyPair = KeyPairUtil.loadEd25519KeyPair("jwt");
        log.info("Ed25519 密钥对加载成功: {}", keyPair);
    }
}
