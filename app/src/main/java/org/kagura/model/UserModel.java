package org.kagura.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * 最简用户实体，仅保留 uid、uname 和 passwd 字段，权限暂时固定为 USER
 */
@Getter
@Setter
@ToString
@Entity
@Table(name = "users")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserModel implements UserDetails {

    public UserModel(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq")
    @SequenceGenerator(name = "user_seq", sequenceName = "user_uid_seq")
    @EqualsAndHashCode.Include
    private Long uid;

    @Column(name = "uname", unique = true, nullable = false, length = 32)
    private String username;

    @JsonIgnore
    @Column(name = "passwd", nullable = false, length = 64)
    private String password;

    @Override
    public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "ROLE_USER");
    }
}
