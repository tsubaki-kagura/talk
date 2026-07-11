package org.kagura.service;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.kagura.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 用户服务
 */
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository repository;

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
}
