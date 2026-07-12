package org.kagura.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.kagura.model.OAuth2UserModel;
import org.kagura.model.UserModel;
import org.kagura.repository.OAuth2UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2UserService {
    private final OAuth2UserRepository oAuth2UserRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserModel searchUser(String provider, String providerUserId) {
        OAuth2UserModel oAuth2UserModel = oAuth2UserRepository.findByProviderAndProviderUserId(provider, providerUserId)
                .orElseGet(() -> {
                    String uname = String.join("@", provider, providerUserId);
                    String passwd = passwordEncoder.encode("123456");
                    return oAuth2UserRepository.save(
                            new OAuth2UserModel(
                                    provider, providerUserId, new UserModel(uname, passwd)
                            )
                    );
                });

        // 获取关联的用户信息
        UserModel userModel = oAuth2UserModel.getUser();
        log.debug("用户 {} 登录成功", userModel.getUsername()); // 手动触发一下懒加载查询，否则会抛出懒加载异常
        return userModel;
    }
}
