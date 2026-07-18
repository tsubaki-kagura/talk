package org.kagura.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.kagura.model.OAuth2UserModel;
import org.kagura.model.UserModel;
import org.kagura.repository.OAuth2UserRepository;
import org.kagura.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 用户服务
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository repository;
    private final OAuth2UserRepository oAuth2UserRepository;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * 根据用户名加载用户信息
     *
     * @param username 用户名
     * @return 用户信息
     * @throws UsernameNotFoundException 用户名不存在时抛出
     */
    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        return repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户名或密码有误"));
    }

    /**
     * 根据 OAuth2 提供商及提供商用户 ID 加载用户信息，用户不存在则自动创建
     *
     * @param provider 提供商名称
     * @param providerUserId 提供商用户ID
     * @return 用户信息
     */
    @Transactional
    public UserModel loadUserByProvider(String provider, String providerUserId) {
        UserModel userModel = oAuth2UserRepository.findByProvider(provider, providerUserId)
                .orElseGet(() -> oAuth2UserRepository.save(
                        new OAuth2UserModel(
                                provider, providerUserId,
                                new UserModel(
                                        String.join("@", provider, providerUserId),
                                        passwordEncoder.encode("12345678")
                                )
                        )
                ))
                .getUser();

        // 返回之前需要手动触发一下查询，否则会抛出懒加载查询异常
        log.debug("用户 {} 登录成功", userModel.getUsername());
        return userModel;
    }
}
