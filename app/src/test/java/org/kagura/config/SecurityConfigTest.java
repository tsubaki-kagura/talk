package org.kagura.config;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
class SecurityConfigTest {

    @Test
    void passwordEncoderTest() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B);
        log.info("passwd: {}", passwordEncoder.encode("041018"));
    }
}
