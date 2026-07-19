package org.kagura.service;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Collectors;

@Slf4j
class UserServiceTest {

    SecureRandom random;

    @BeforeEach
    void initSecureRandom() throws NoSuchAlgorithmException {
        random = SecureRandom.getInstanceStrong();
    }

    @Test
    void secureRandomPasswdGenerateTest() {
        String passwd = random.ints(33, 127)
                .limit(32)
                .mapToObj(Character::toString)
                .collect(Collectors.joining());
        log.info("secure random passwd: {}", passwd);
    }
}
