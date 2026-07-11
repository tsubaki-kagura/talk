package org.kagura.config;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.kagura.model.UserModel;
import org.kagura.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@SpringBootTest(properties = "spring.jpa.hibernate.ddl-auto=create")
class SecurityConfigTest {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    /**
     * 插入一条测试用户记录
     */
    @Test
    void saveTestUserTest() {
        UserModel userModel = new UserModel("tsubaki", "041018");
        userModel.setPassword(passwordEncoder.encode(userModel.getPassword()));
        userModel = userRepository.save(userModel);
        log.debug("测试用户插入成功：userModel={}", userModel);
    }
}
