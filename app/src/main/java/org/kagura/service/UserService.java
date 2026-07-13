package org.kagura.service;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.kagura.exception.BaseException;
import org.kagura.model.UserModel;
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
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    /**
     * 根据用户名加载用户信息
     *
     * @param username 用户名
     * @return 用户信息
     * @throws UsernameNotFoundException 异常
     */
    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        return repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户名或密码有误"));
    }

    /**
     * 用户注册相关逻辑
     * 若用户名重复，则抛出异常 BaseException("用户名 " + uname + " 已被占用")
     * 若成功注册，则返回注册成功后的用户名
     *
     * @param uname 用户名
     * @param passwd 密码
     * @return 注册成功后的用户名
     */
    @Transactional
    public String register(String uname, String passwd) {
        repository.findByUsername(uname)
                .ifPresent(_ -> {
                    throw new BaseException("用户名 " + uname + " 已被占用");
                });
        UserModel userModel = new UserModel(uname, passwordEncoder.encode(passwd));
        return repository.save(userModel).getUsername();
    }
}
